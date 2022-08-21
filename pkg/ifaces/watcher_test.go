package ifaces

import (
	"context"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func TestWatcher(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher := NewWatcher(10)
	// mock net.Interfaces and linkSubscriber to control which interfaces are discovered
	watcher.interfaces = func() ([]Interface, error) {
		return []Interface{{"foo", 1}, {"bar", 2}, {"baz", 3}}, nil
	}
	inputLinks := make(chan netlink.LinkUpdate, 10)
	watcher.linkSubscriber = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
		go func() {
			for link := range inputLinks {
				ch <- link
			}
		}()
		return nil
	}

	outputEvents, err := watcher.Subscribe(ctx)
	require.NoError(t, err)

	// initial set of fetched elements
	assert.Equal(t,
		Event{Type: EventAdded, Interface: Interface{"foo", 1}},
		getEvent(t, outputEvents, timeout))
	assert.Equal(t,
		Event{Type: EventAdded, Interface: Interface{"bar", 2}},
		getEvent(t, outputEvents, timeout))
	assert.Equal(t,
		Event{Type: EventAdded, Interface: Interface{"baz", 3}},
		getEvent(t, outputEvents, timeout))

	// updates
	inputLinks <- upAndRunning("bae", 4)
	inputLinks <- down("bar", 2)
	assert.Equal(t,
		Event{Type: EventAdded, Interface: Interface{"bae", 4}},
		getEvent(t, outputEvents, timeout))
	assert.Equal(t,
		Event{Type: EventDeleted, Interface: Interface{"bar", 2}},
		getEvent(t, outputEvents, timeout))

	// repeated updates that do not involve a change in the current track of interfaces
	// will be ignored
	inputLinks <- upAndRunning("bae", 4)
	inputLinks <- upAndRunning("foo", 1)
	inputLinks <- down("bar", 2)
	inputLinks <- down("eth0", 3)

	select {
	case ev := <-outputEvents:
		require.Failf(t, "unexpected event", "%#v", ev)
	default:
		// ok!
	}
}

func upAndRunning(name string, index int) netlink.LinkUpdate {
	return netlink.LinkUpdate{
		IfInfomsg: nl.IfInfomsg{IfInfomsg: unix.IfInfomsg{Flags: syscall.IFF_UP | syscall.IFF_RUNNING}},
		Link:      &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index}},
	}
}

func down(name string, index int) netlink.LinkUpdate {
	return netlink.LinkUpdate{
		Link: &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index}},
	}
}
