package ifaces

import (
	"context"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestWatcher(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher := NewWatcher(10)
	// mock net.Interfaces and linkSubscriber to control which interfaces are discovered
	watcher.interfaces = func(_ netns.NsHandle, _ string) ([]Interface, error) {
		return []Interface{{"foo", 1, netns.None(), ""}, {"bar", 2, netns.None(), ""}, {"baz", 3, netns.None(), ""}}, nil
	}
	inputLinks := make(chan netlink.LinkUpdate, 10)
	watcher.linkSubscriberAt = func(_ netns.NsHandle, ch chan<- netlink.LinkUpdate, _ <-chan struct{}) error {
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
		Event{Type: EventAdded, Interface: Interface{"foo", 1, netns.None(), ""}},
		getEvent(t, outputEvents, timeout))
	assert.Equal(t,
		Event{Type: EventAdded, Interface: Interface{"bar", 2, netns.None(), ""}},
		getEvent(t, outputEvents, timeout))
	assert.Equal(t,
		Event{Type: EventAdded, Interface: Interface{"baz", 3, netns.None(), ""}},
		getEvent(t, outputEvents, timeout))

	// updates
	inputLinks <- upAndRunning("bae", 4, netns.None())
	inputLinks <- down("bar", 2, netns.None())
	assert.Equal(t,
		Event{Type: EventAdded, Interface: Interface{"bae", 4, netns.None(), ""}},
		getEvent(t, outputEvents, timeout))
	assert.Equal(t,
		Event{Type: EventDeleted, Interface: Interface{"bar", 2, netns.None(), ""}},
		getEvent(t, outputEvents, timeout))

	// repeated updates that do not involve a change in the current track of interfaces
	// will be ignored
	inputLinks <- upAndRunning("bae", 4, netns.None())
	inputLinks <- upAndRunning("foo", 1, netns.None())
	inputLinks <- down("bar", 2, netns.None())
	inputLinks <- down("eth0", 3, netns.None())

	select {
	case ev := <-outputEvents:
		require.Failf(t, "unexpected event", "%#v", ev)
	default:
		// ok!
	}
}

func upAndRunning(name string, index int, netNS netns.NsHandle) netlink.LinkUpdate {
	return netlink.LinkUpdate{
		IfInfomsg: nl.IfInfomsg{IfInfomsg: unix.IfInfomsg{Flags: syscall.IFF_UP | syscall.IFF_RUNNING}},
		Link:      &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index, Namespace: netNS, OperState: netlink.OperUp}},
	}
}

func down(name string, index int, netNS netns.NsHandle) netlink.LinkUpdate {
	return netlink.LinkUpdate{
		Link: &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index, Namespace: netNS}},
	}
}
