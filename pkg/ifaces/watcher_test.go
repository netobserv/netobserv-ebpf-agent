package ifaces

import (
	"context"
	"net"
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
		return []Interface{
			simpleInterface(1, "foo", macFoo),
			simpleInterface(2, "bar", macBar),
			simpleInterface(3, "baz", macBaz),
		}, nil
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
		Event{Type: EventAdded, Interface: simpleInterface(1, "foo", macFoo)},
		getEvent(t, outputEvents, timeout))
	assert.Equal(t,
		Event{Type: EventAdded, Interface: simpleInterface(2, "bar", macBar)},
		getEvent(t, outputEvents, timeout))
	assert.Equal(t,
		Event{Type: EventAdded, Interface: simpleInterface(3, "baz", macBaz)},
		getEvent(t, outputEvents, timeout))

	// updates
	inputLinks <- upAndRunning("bae", 4, macBae[:], netns.None())
	inputLinks <- down("bar", 2, macBar[:], netns.None())
	assert.Equal(t,
		Event{Type: EventAdded, Interface: simpleInterface(4, "bae", macBae)},
		getEvent(t, outputEvents, timeout))
	assert.Equal(t,
		Event{Type: EventDeleted, Interface: simpleInterface(2, "bar", macBar)},
		getEvent(t, outputEvents, timeout))

	// repeated updates that do not involve a change in the current track of interfaces
	// will be ignored
	inputLinks <- upAndRunning("bae", 4, macBae[:], netns.None())
	inputLinks <- upAndRunning("foo", 1, macFoo[:], netns.None())
	inputLinks <- down("bar", 2, macBar[:], netns.None())
	inputLinks <- down("eth0", 3, macBaz[:], netns.None())

	select {
	case ev := <-outputEvents:
		require.Failf(t, "unexpected event", "%#v", ev)
	default:
		// ok!
	}
}

func upAndRunning(name string, index int, mac net.HardwareAddr, netNS netns.NsHandle) netlink.LinkUpdate {
	return netlink.LinkUpdate{
		IfInfomsg: nl.IfInfomsg{IfInfomsg: unix.IfInfomsg{Flags: syscall.IFF_UP | syscall.IFF_RUNNING}},
		Link:      &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index, Namespace: netNS, OperState: netlink.OperUp, HardwareAddr: mac}},
	}
}

func down(name string, index int, mac net.HardwareAddr, netNS netns.NsHandle) netlink.LinkUpdate {
	return netlink.LinkUpdate{
		Link: &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index, Namespace: netNS, HardwareAddr: mac}},
	}
}

func TestMACToFixed(t *testing.T) {
	mac, err := net.ParseMAC("01:02:03:04:05:06")
	assert.NoError(t, err)
	fixed, err := macToFixed6(mac)
	assert.NoError(t, err)
	assert.Equal(t, macFoo, fixed)
	fixed, err = macToFixed6([]uint8{1, 2, 3, 4, 5, 6})
	assert.NoError(t, err)
	assert.Equal(t, macFoo, fixed)
	fixed, err = macToFixed6([]uint8{1, 2, 3, 4, 5, 6, 7, 8})
	assert.NoError(t, err)
	assert.Equal(t, macFoo, fixed)
	_, err = macToFixed6([]uint8{1, 2, 3, 4})
	assert.Equal(t, "MAC too small: 01:02:03:04", err.Error())
}
