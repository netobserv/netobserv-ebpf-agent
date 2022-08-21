package ifaces

import (
	"context"
	"sync"
)

// Registerer is an informer that wraps another informer implementation, and keeps track of
// the currently existing interfaces in the system, accessible through the IfaceNameForIndex method.
type Registerer struct {
	m      sync.RWMutex
	inner  Informer
	ifaces map[int]string
	bufLen int
}

func NewRegisterer(inner Informer, bufLen int) *Registerer {
	return &Registerer{
		inner:  inner,
		bufLen: bufLen,
		ifaces: map[int]string{},
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
				r.m.Lock()
				r.ifaces[ev.Interface.Index] = ev.Interface.Name
				r.m.Unlock()
			case EventDeleted:
				r.m.Lock()
				name, ok := r.ifaces[ev.Interface.Index]
				// prevent removing an interface with the same index but different name
				// e.g. due to an out-of-order add/delete signaling
				if ok && name == ev.Interface.Name {
					delete(r.ifaces, ev.Interface.Index)
				}
				r.m.Unlock()
			}
			out <- ev
		}
	}()
	return out, nil
}

func (r *Registerer) IfaceNameForIndex(idx int) (string, bool) {
	r.m.RLock()
	defer r.m.RUnlock()
	name, ok := r.ifaces[idx]
	return name, ok
}
