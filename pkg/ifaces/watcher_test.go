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
	watcher.interfaces = func() ([]Name, error) {
		return []Name{"foo", "bar", "baz"}, nil
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
	assert.Equal(t, Event{Type: EventAdded, Interface: "foo"}, getEvent(t, outputEvents, timeout))
	assert.Equal(t, Event{Type: EventAdded, Interface: "bar"}, getEvent(t, outputEvents, timeout))
	assert.Equal(t, Event{Type: EventAdded, Interface: "baz"}, getEvent(t, outputEvents, timeout))

	// updates
	inputLinks <- upAndRunning("bae")
	inputLinks <- down("bar")
	assert.Equal(t, Event{Type: EventAdded, Interface: "bae"}, getEvent(t, outputEvents, timeout))
	assert.Equal(t, Event{Type: EventDeleted, Interface: "bar"}, getEvent(t, outputEvents, timeout))

	// repeated updates that do not involve a change in the current track of interfaces
	// will be ignored
	inputLinks <- upAndRunning("bae")
	inputLinks <- upAndRunning("foo")
	inputLinks <- down("bar")
	inputLinks <- down("eth0")

	select {
	case ev := <-outputEvents:
		require.Failf(t, "unexpected event", "%#v", ev)
	default:
		// ok!
	}

	// updates of existing interfaces that are not UP and RUNNING will be deleted
}

func upAndRunning(name string) netlink.LinkUpdate {
	return netlink.LinkUpdate{
		IfInfomsg: nl.IfInfomsg{IfInfomsg: unix.IfInfomsg{Flags: syscall.IFF_UP | syscall.IFF_RUNNING}},
		Link:      &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name}},
	}
}

func down(name string) netlink.LinkUpdate {
	return netlink.LinkUpdate{
		Link: &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name}},
	}
}
