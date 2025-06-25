package ifaces

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/sirupsen/logrus"
)

var rlog = logrus.WithField("component", "ifaces.Registerer")

// Registerer is an informer that wraps another informer implementation, and keeps track of
// the currently existing interfaces in the system, accessible through the IfaceNameForIndex method.
type Registerer struct {
	m                   sync.RWMutex
	inner               Informer
	ifaces              map[int]map[[6]uint8]string
	mapSize             int
	bufLen              int
	preferredInterfaces []preferredInterface
	metrics             *metrics.Metrics
}

func NewRegisterer(inner Informer, cfg *config.Agent, m *metrics.Metrics) (*Registerer, error) {
	pref, err := newPreferredInterfaces(cfg.PreferredInterfaceForMACPrefix)
	if err != nil {
		return nil, err
	}
	r := &Registerer{
		inner:               inner,
		bufLen:              cfg.BuffersLength,
		ifaces:              map[int]map[[6]uint8]string{},
		preferredInterfaces: pref,
		metrics:             m,
	}
	m.CreateInterfaceBufferGauge("registerer", func() float64 { return float64(r.mapSize) })
	return r, nil
}

func (r *Registerer) Subscribe(ctx context.Context) (<-chan Event, error) {
	innerCh, err := r.inner.Subscribe(ctx)
	if err != nil {
		return nil, err
	}
	out := make(chan Event, r.bufLen)
	go func() {
		for ev := range innerCh {
			switch ev.Type {
			case EventAdded:
				rlog.Debugf("Registerer:Subscribe %d=%s", ev.Interface.Index, ev.Interface.Name)
				r.metrics.InterfaceEventsCounter.Increase("reg_subscribed", ev.Interface.Name, ev.Interface.Index, ev.Interface.NSName, ev.Interface.MAC, 1)
				r.m.Lock()
				if _, ok := r.ifaces[ev.Interface.Index]; ok {
					r.ifaces[ev.Interface.Index][ev.Interface.MAC] = ev.Interface.Name
				} else {
					r.ifaces[ev.Interface.Index] = map[[6]uint8]string{ev.Interface.MAC: ev.Interface.Name}
				}
				r.mapSize = len(r.ifaces)
				r.m.Unlock()
			case EventDeleted:
				r.metrics.InterfaceEventsCounter.Increase("reg_unsubscribed", ev.Interface.Name, ev.Interface.Index, ev.Interface.NSName, ev.Interface.MAC, 1)
				r.m.Lock()
				if macs, ok := r.ifaces[ev.Interface.Index]; ok {
					name, ok := macs[ev.Interface.MAC]
					// prevent removing an interface with the same index but different name
					// e.g. due to an out-of-order add/delete signaling
					if ok && name == ev.Interface.Name {
						delete(macs, ev.Interface.MAC)
					}
					if len(macs) == 0 {
						delete(r.ifaces, ev.Interface.Index)
					}
				}
				r.mapSize = len(r.ifaces)
				r.m.Unlock()
			}
			out <- ev
		}
	}()
	return out, nil
}

// IfaceNameForIndexAndMAC returns the interface name for a given
// interface index and MAC address, using the cached data from prior
// events observed by the underlying interfaces informer. It returns
// the interface name and true if a match is found, or an empty string
// and false if not.
//
// If multiple MACs are associated with the same index, this function
// attempts to disambiguate using the provided MAC. If no exact match
// is found, it applies heuristics (e.g., preferred MAC prefix rules)
// to choose a preferred interface name. As a last resort, if no MAC
// match is possible, it returns the first name associated with the
// index to avoid falling back to a syscall.
//
// A fallback to net.InterfaceByIndex is performed only if the index
// is not present in the cache, or the MAC does not match any known
// entry and no heuristic rule applies.
//
// Concurrency note:
//
// Without double-checked locking, the following sequence may occur:
//
//  1. Goroutine A acquires RLock, sees r.ifaces[idx][mac] is missing
//  2. Goroutine B does the same (also sees entry missing)
//  3. Both release RLock and call net.InterfaceByIndex(idx)
//  4. Both prepare to insert iface.Name into r.ifaces[idx][mac]
//  5. Goroutine A acquires Lock and writes to the map
//  6. Goroutine B acquires Lock and overwrites A's result
//
// This results in a lost update. To prevent this, the function uses
// double-checked locking: it re-checks under Lock before inserting,
// ensuring that only one goroutine updates the cache.
func (r *Registerer) IfaceNameForIndexAndMAC(idx int, mac [6]uint8) (string, bool) {
	if name, found := r.ifaceCacheLookup(idx, mac); found {
		return name, found
	}
	// Fallback if not found, interfaces lookup
	iface, err := net.InterfaceByIndex(idx)
	if err != nil {
		return "", false
	}
	foundMAC, err := macToFixed6(iface.HardwareAddr)
	if err != nil {
		return "", false
	}

	r.m.Lock()
	defer r.m.Unlock()

	if current, ok := r.ifaces[idx]; ok {
		if existing, exists := current[foundMAC]; exists {
			// The entry was populated concurrently during
			// our fallback path. Respect the existing
			// value to avoid a lost update.
			return existing, true
		}
		current[foundMAC] = iface.Name
	} else {
		r.ifaces[idx] = map[[6]uint8]string{foundMAC: iface.Name}
		r.mapSize = len(r.ifaces)
	}
	return iface.Name, true
}

func (r *Registerer) ifaceCacheLookup(idx int, mac [6]uint8) (string, bool) {
	r.m.RLock()
	defer r.m.RUnlock()

	macsMap, ok := r.ifaces[idx]
	if ok {
		if len(macsMap) == 1 {
			// No risk of collision, just return entry without checking for MAC
			for _, name := range macsMap {
				return name, true
			}
		} else if len(macsMap) > 1 {
			// Several entries, need to disambiguate by MAC
			name, ok := macsMap[mac]
			if ok {
				return name, true
			}
			// Not found => before falling back to syscall lookup that is CPU intensive, run this quick ovn optimization:
			// eth0 & ens5 often collide; MAC starting with 0A:58 should be eth0 and not ens5, but since the MAC captured in flow
			// doesn't match the actual interface MAC, we'll hardcode that.
			for i := range r.preferredInterfaces {
				if name, ok = r.preferredInterfaces[i].matches(mac, macsMap); ok {
					return name, true
				}
			}
			// ifindex was found but MAC not found. Use the ifindex anyway regardless of MAC, to avoid CPU penalty from syscall.
			if rlog.Logger.IsLevelEnabled(logrus.DebugLevel) {
				sMac := model.MacAddr(mac)
				rlog.Debugf("interface lookup found ifindex (%d) with MAC unmatched (%s)", idx, sMac.String())
				candidates := []string{}
				for m, name := range macsMap {
					sMac = model.MacAddr(m)
					candidates = append(candidates, fmt.Sprintf("%s (%s)", name, sMac.String()))
				}
				rlog.Debugf("picking first among candidates: %s", strings.Join(candidates, ", "))
			}
			for _, name := range macsMap {
				return name, true
			}
		}
	}
	return "", false
}

type preferredInterface struct {
	macPrefix []uint8
	intf      string
}

func newPreferredInterfaces(s string) ([]preferredInterface, error) {
	var ret []preferredInterface
	if len(s) == 0 {
		return nil, nil
	}
	all := strings.Split(s, ",")
	for _, kv := range all {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("PreferredInterfaceForMACPrefix, bad format '%s'; expected 'mac_prefix=name'", kv)
		}
		macChars := strings.ReplaceAll(parts[0], ":", "")
		data, err := hex.DecodeString(macChars)
		if err != nil {
			return nil, fmt.Errorf("PreferredInterfaceForMACPrefix, bad MAC prefix '%s'; %w", parts[0], err)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("PreferredInterfaceForMACPrefix, empty MAC prefix in '%s'", kv)
		}
		if len(data) > 6 {
			return nil, fmt.Errorf("PreferredInterfaceForMACPrefix, MAC prefix too big '%s'", parts[0])
		}
		ret = append(ret, preferredInterface{macPrefix: data, intf: parts[1]})
	}
	return ret, nil
}

func (p *preferredInterface) matches(mac [6]uint8, macsMap map[[6]uint8]string) (string, bool) {
	for i := range p.macPrefix {
		if mac[i] != p.macPrefix[i] {
			return "", false
		}
	}
	for _, name := range macsMap {
		if name == p.intf {
			return name, true
		}
	}
	return "", false
}
