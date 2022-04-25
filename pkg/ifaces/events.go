package ifaces

import (
	"context"
)

// Name of an interface (e.g. eth0)
type Name string

// EventType for an interface: added, deleted
type EventType int

const (
	EventAdded EventType = iota
	EventDeleted
)

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
