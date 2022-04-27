package ifaces

import (
	"context"

	"github.com/sirupsen/logrus"
)

// Name of an interface (e.g. eth0)
type Name string

// EventType for an interface: added, deleted
type EventType int

const (
	EventAdded EventType = iota
	EventDeleted
)

var ilog = logrus.WithField("component", "ifaces.Informer")

// Event of a network interface, given the type (added, removed) and the interface name
type Event struct {
	Type      EventType
	Interface Name
}

type NamesProvider interface {
	// Subscribe returns a channel that sends all the existing interfaces in a given moment.
	// Depending on the implementation, this moment can be periodically or on each addition
	Subscribe(ctx context.Context) (<-chan []Name, error)
}

func Informer(ctx context.Context, provider NamesProvider, bufLen int) (<-chan Event, error) {
	ilog.Debug("starting interfaces informer")
	namesCh, err := provider.Subscribe(ctx)
	if err != nil {
		return nil, err
	}
	events := make(chan Event, bufLen)
	go func() {
		current := map[Name]struct{}{}
		for {
			select {
			case <-ctx.Done():
				ilog.Debug("stopping interfaces informer")
				close(events)
				return
			case names := <-namesCh:
				notifyChanges(events, names, current)
			}
		}
	}()
	return events, nil
}

func notifyChanges(events chan Event, names []Name, current map[Name]struct{}) {
	// Check for new interfaces
	acquired := map[Name]struct{}{}
	for _, n := range names {
		acquired[n] = struct{}{}
		if _, ok := current[n]; !ok {
			ilog.WithField("interface", n).Debug("added network interface")
			current[n] = struct{}{}
			events <- Event{
				Type:      EventAdded,
				Interface: n,
			}
		}
	}
	// Check for deleted interfaces
	for n := range current {
		if _, ok := acquired[n]; !ok {
			delete(current, n)
			ilog.WithField("interface", n).Debug("deleted network interface")
			events <- Event{
				Type:      EventDeleted,
				Interface: n,
			}
		}
	}
}
