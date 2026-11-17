package ifaces

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

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
	ifaces              map[ifaceKey]map[[6]uint8]ifaceEntry
	mapSize             int
	bufLen              int
	deleteGrace         time.Duration
	preferredInterfaces []preferredInterface
	metrics             *metrics.Metrics
}

type ifaceEntry struct {
	name              string
	markedForDeletion bool
}

// ifaceKey identifies an interface by its network namespace cookie and OS index. The cookie is
// 0 when netns-cookie tracking is disabled, in which case lookups degrade to index-only (the
// historical behavior). Including the cookie disambiguates indexes that collide across namespaces.
type ifaceKey struct {
	cookie uint64
	index  int
}

func NewRegisterer(inner Informer, cfg *config.Agent, m *metrics.Metrics) (*Registerer, error) {
	pref, err := newPreferredInterfaces(cfg.PreferredInterfaceForMACPrefix)
	if err != nil {
		return nil, err
	}
	// Interfaces must survive at least for the next eviction round (+ 1s margin)
	deleteGrace := cfg.CacheActiveTimeout + time.Second
	if deleteGrace <= 0 {
		deleteGrace = time.Second
	}
	r := &Registerer{
		inner:               inner,
		bufLen:              cfg.BuffersLength,
		ifaces:              map[ifaceKey]map[[6]uint8]ifaceEntry{},
		deleteGrace:         deleteGrace,
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
				rlog.Debugf("Subscribe %d=%s", ev.Interface.Index, ev.Interface.Name)
				r.metrics.InterfaceEventsCounter.Increase("reg_subscribed", ev.Interface.Name, ev.Interface.Index, ev.Interface.NSName, ev.Interface.MAC, 1)
				key := ifaceKey{cookie: ev.Interface.NetNSCookie, index: ev.Interface.Index}
				r.m.Lock()
				if _, ok := r.ifaces[key]; !ok {
					r.ifaces[key] = map[[6]uint8]ifaceEntry{}
				}
				r.ifaces[key][ev.Interface.MAC] = ifaceEntry{name: ev.Interface.Name}
				r.mapSize = len(r.ifaces)
				r.m.Unlock()
			case EventDeleted:
				rlog.Debugf("Unsubscribe %d=%s", ev.Interface.Index, ev.Interface.Name)
				r.metrics.InterfaceEventsCounter.Increase("reg_unsubscribed", ev.Interface.Name, ev.Interface.Index, ev.Interface.NSName, ev.Interface.MAC, 1)
				key := ifaceKey{cookie: ev.Interface.NetNSCookie, index: ev.Interface.Index}
				r.m.Lock()
				// prevent removing an interface with the same index but different name
				// e.g. due to an out-of-order add/delete signaling
				if entry, ok := r.ifaces[key][ev.Interface.MAC]; ok && entry.name == ev.Interface.Name {
					// Keep the name resolvable until flows still referencing it are evicted.
					entry.markedForDeletion = true
					r.ifaces[key][ev.Interface.MAC] = entry
					time.AfterFunc(r.deleteGrace, func() { r.deleteFromCache(key, ev.Interface.MAC, ev.Interface.Name) })
				}
				r.m.Unlock()
			}
			out <- ev
		}
	}()
	return out, nil
}

func (r *Registerer) deleteFromCache(key ifaceKey, mac [6]uint8, name string) {
	r.m.Lock()
	defer r.m.Unlock()
	macs := r.ifaces[key]
	entry, ok := macs[mac]
	if !ok || entry.name != name || !entry.markedForDeletion {
		return
	}
	delete(macs, mac)
	if len(macs) == 0 {
		delete(r.ifaces, key)
	}
	r.mapSize = len(r.ifaces)
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
func (r *Registerer) IfaceNameForIndexAndMAC(idx int, cookie uint64, mac [6]uint8) (string, bool) {
	r.m.RLock()
	defer r.m.RUnlock()

	macsMap, ok := r.ifaces[ifaceKey{cookie: cookie, index: idx}]
	if !ok && cookie != 0 {
		// Degraded interface name attribution
		// Retry with cookie == 0, in case we failed to read the cookie at interface registration time
		macsMap, ok = r.ifaces[ifaceKey{cookie: 0, index: idx}]
	}
	if ok {
		if len(macsMap) == 1 {
			// No risk of collision, just return entry without checking for MAC
			for _, entry := range macsMap {
				return entry.name, true
			}
		} else if len(macsMap) > 1 {
			// Several entries, need to disambiguate by MAC
			entry, ok := macsMap[mac]
			if ok {
				return entry.name, true
			}
			// Not found => before falling back to syscall lookup that is CPU intensive, run this quick ovn optimization:
			// eth0 & ens5 often collide; MAC starting with 0A:58 should be eth0 and not ens5, but since the MAC captured in flow
			// doesn't match the actual interface MAC, we'll hardcode that.
			for i := range r.preferredInterfaces {
				if name, ok := r.preferredInterfaces[i].matches(mac, macsMap); ok {
					return name, true
				}
			}
			// ifindex was found but MAC not found. Use the ifindex anyway regardless of MAC, to avoid CPU penalty from syscall.
			if rlog.Logger.IsLevelEnabled(logrus.DebugLevel) {
				sMac := model.MacAddr(mac)
				rlog.Debugf("interface lookup found ifindex (%d) with MAC unmatched (%s)", idx, sMac.String())
				candidates := []string{}
				for m, e := range macsMap {
					sMac = model.MacAddr(m)
					candidates = append(candidates, fmt.Sprintf("%s (%s)", e.name, sMac.String()))
				}
				rlog.Debugf("picking first among candidates: %s", strings.Join(candidates, ", "))
			}
			for _, e := range macsMap {
				return e.name, true
			}
		}
	}
	if rlog.Logger.IsLevelEnabled(logrus.DebugLevel) {
		r.debugMiss(idx, cookie, mac)
	}
	return "", false
}

func (r *Registerer) debugMiss(idx int, cookie uint64, mac [6]uint8) {
	// Lookup miss. Dump what we know about this ifindex so we can tell a namespace that was never
	// enumerated (cookie unknown to us) from one whose interface is registered under another
	// cookie, e.g. an SR-IOV VF that kept its ifindex when moved from the host into a pod.
	// Debug-only: this scans the whole interface map, and runs per flow.
	var others []string
	for k, macs := range r.ifaces {
		if k.index != idx {
			continue
		}
		for m, e := range macs {
			otherMAC := model.MacAddr(m)
			state := ""
			if e.markedForDeletion {
				state = ", pending deletion"
			}
			others = append(others, fmt.Sprintf("%s (cookie=%d, mac=%s%s)", e.name, k.cookie, otherMAC.String(), state))
		}
	}
	sMac := model.MacAddr(mac)
	if len(others) == 0 {
		rlog.Debugf("interface lookup miss: ifindex=%d cookie=%d mac=%s; that ifindex is not registered under any cookie",
			idx, cookie, sMac.String())
	} else {
		rlog.Debugf("interface lookup miss: ifindex=%d cookie=%d mac=%s; same ifindex registered under: %s",
			idx, cookie, sMac.String(), strings.Join(others, ", "))
	}
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

func (p *preferredInterface) matches(mac [6]uint8, macsMap map[[6]uint8]ifaceEntry) (string, bool) {
	for i := range p.macPrefix {
		if mac[i] != p.macPrefix[i] {
			return "", false
		}
	}
	for _, entry := range macsMap {
		if entry.name == p.intf {
			return entry.name, true
		}
	}
	return "", false
}
