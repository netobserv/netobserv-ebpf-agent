package ifaces

import (
	"context"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"
)

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
	Interface Interface
}

type Interface struct {
	Name  string
	Index int
	NetNS netns.NsHandle
}

// Informer provides notifications about each network interface that is added or removed
// from the host. Production implementations: Poller and Watcher.
type Informer interface {
	// Subscribe returns a channel that sends Event instances.
	Subscribe(ctx context.Context) (<-chan Event, error)
}

func netInterfaces() ([]Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("can't fetch interfaces: %w", err)
	}
	names := make([]Interface, len(ifs))
	for i, ifc := range ifs {
		names[i] = Interface{Name: ifc.Name, Index: ifc.Index, NetNS: netns.None()}
	}
	return names, nil
}
