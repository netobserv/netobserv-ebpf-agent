package ifaces

import (
	"context"
	"fmt"
	"net"

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

func (e EventType) String() string {
	switch e {
	case EventAdded:
		return "Added"
	case EventDeleted:
		return "Deleted"
	default:
		return fmt.Sprintf("Unknown (%d)", e)
	}
}

var ilog = logrus.WithField("component", "ifaces.Informer")

// Event of a network interface, given the type (added, removed) and the interface name
type Event struct {
	Type      EventType
	Interface Name
}

type Informer interface {
	// Subscribe returns a channel that sends events
	// Depending on the implementation, this moment can be periodically or on each addition
	Subscribe(ctx context.Context) (<-chan Event, error)
}

func interfaces() ([]Name, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("can't fetch interfaces: %w", err)
	}
	names := make([]Name, len(ifs))
	for i, ifc := range ifs {
		names[i] = Name(ifc.Name)
	}
	return names, nil
}
