package ifaces

import (
	"context"
	"net"
	"sync"

	"github.com/sirupsen/logrus"
)

var rlog = logrus.WithField("component", "ifaces.Registerer")

// Registerer is an informer that wraps another informer implementation, and keeps track of
// the currently existing interfaces in the system, accessible through the IfaceNameForIndex method.
type Registerer struct {
	m      sync.RWMutex
	inner  Informer
	ifaces map[int]map[[6]uint8]string
	bufLen int
}

func NewRegisterer(inner Informer, bufLen int) *Registerer {
	return &Registerer{
		inner:  inner,
		bufLen: bufLen,
		ifaces: map[int]map[[6]uint8]string{},
	}
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
				r.m.Lock()
				if current, ok := r.ifaces[ev.Interface.Index]; ok {
					if _, alreadySet := current[ev.Interface.MAC]; !alreadySet {
						r.ifaces[ev.Interface.Index][ev.Interface.MAC] = ev.Interface.Name
					}
				} else {
					r.ifaces[ev.Interface.Index] = map[[6]uint8]string{ev.Interface.MAC: ev.Interface.Name}
				}
				r.m.Unlock()
			case EventDeleted:
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
				r.m.Unlock()
			}
			out <- ev
		}
	}()
	return out, nil
}

// IfaceNameForIndex gets the interface name given an index as recorded by the underlying
// interfaces' informer. It backs up into the net.InterfaceByIndex function if the interface
// has not been previously registered
func (r *Registerer) IfaceNameForIndexAndMAC(idx int, mac [6]uint8) (string, bool) {
	r.m.RLock()
	macsMap, ok := r.ifaces[idx]
	r.m.RUnlock()
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
			if mac[0] == 0x0a && mac[1] == 0x58 {
				for _, name := range macsMap {
					if name == "eth0" {
						return name, true
					}
				}
			}
			// ifindex was found but MAC not found. Use the ifindex anyway regardless of MAC, to avoid CPU penalty from syscall.
			for _, name := range macsMap {
				rlog.Debugf("Interface lookup found ifindex (%d) but not MAC; using %s anyway", idx, name)
				return name, true
			}
		}
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
	if current, ok := r.ifaces[idx]; ok {
		current[foundMAC] = iface.Name
	} else {
		r.ifaces[idx] = map[[6]uint8]string{foundMAC: iface.Name}
	}
	r.m.Unlock()
	return iface.Name, true
}
