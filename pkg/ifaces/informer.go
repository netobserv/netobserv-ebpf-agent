package ifaces

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
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
	InterfaceKey
	MAC   [6]uint8
	NetNS netns.NsHandle
}

type InterfaceKey struct {
	Index  int
	Name   string
	NSName string
}

func NewInterface(index int, name string, mac [6]uint8, netNS netns.NsHandle, nsname string) Interface {
	return Interface{
		InterfaceKey: InterfaceKey{
			Index:  index,
			Name:   name,
			NSName: nsname,
		},
		MAC:   mac,
		NetNS: netNS,
	}
}

// Informer provides notifications about each network interface that is added or removed
// from the host. Production implementations: Poller and Watcher.
type Informer interface {
	// Subscribe returns a channel that sends Event instances.
	Subscribe(ctx context.Context) (<-chan Event, error)
}

func netInterfaces(nsh netns.NsHandle, ns string) ([]Interface, error) {
	handle, err := netlink.NewHandleAt(nsh)
	if err != nil {
		return nil, fmt.Errorf("failed to create handle for netns (%s): %w", nsh.String(), err)
	}
	defer handle.Close()

	// Get a list of interfaces in the namespace
	links, err := handle.LinkList()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces in netns (%s): %w", nsh.String(), err)
	}

	intfs := make([]Interface, 0, len(links))
	for _, link := range links {
		log.Debugf(
			"found link: %s=>[Index=%d, MAC=%s, MasterIdx=%d, ParentIdx=%d, Namespace=%s]",
			link.Attrs().Name,
			link.Attrs().Index,
			link.Attrs().HardwareAddr.String(),
			link.Attrs().MasterIndex,
			link.Attrs().ParentIndex,
			ns,
		)
		if link.Attrs().HardwareAddr != nil {
			mac, err := macToFixed6(link.Attrs().HardwareAddr)
			if err != nil {
				log.WithField("link", link).Infof("ignoring link with invalid MAC: %s", err.Error())
				continue
			}
			intfs = append(intfs, NewInterface(link.Attrs().Index, link.Attrs().Name, mac, nsh, ns))
		}
	}
	return intfs, nil
}
