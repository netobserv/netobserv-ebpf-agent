package ifaces

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
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

	netnsResolver, cleanup := setupEmptyNetNS(t)
	defer cleanup()
	watcher := NewWatcher(10, netnsResolver, metrics.NoOp())
	// mock net.Interfaces and linkSubscriber to control which interfaces are discovered
	watcher.interfaces = func(_ netns.NsHandle, _ string, _ uint64) ([]Interface, error) {
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

func TestWatcherNoNetNs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher := NewWatcher(10, NewDisabledResolver(), metrics.NoOp())
	// mock net.Interfaces and linkSubscriber to control which interfaces are discovered
	watcher.interfaces = func(_ netns.NsHandle, _ string, _ uint64) ([]Interface, error) {
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

// setupNetNS is the non-empty counterpart of setupEmptyNetNS: entries listed in hostAliases are
// symlinked to the current namespace, standing in for the bind mounts CRI-O creates for every
// host-network pod (a real bind mount would need CAP_SYS_ADMIN). The others get their own identity.
func setupNetNS(t *testing.T, hostAliases, others []string) (NetnsResolver, func()) {
	t.Helper()
	dname, err := os.MkdirTemp("", "netns")
	require.NoError(t, err)
	for _, ns := range hostAliases {
		require.NoError(t, os.Symlink("/proc/self/ns/net", filepath.Join(dname, ns)))
	}
	for _, ns := range others {
		require.NoError(t, os.WriteFile(filepath.Join(dname, ns), nil, 0o600))
	}
	// Host alias dedup: get the host netns ID
	handle, err := netns.Get()
	require.NoError(t, err)
	defer handle.Close()
	return &netnsResolverImpl{netnsPath: dname, hostNetnsID: handle.UniqueId()}, func() { os.RemoveAll(dname) }
}

func TestWatcher_SkipsBindMountsOfHostNetns(t *testing.T) {
	// CRI-O creates a netns entry per pod sandbox, and a host-network pod's entry is a bind mount
	// of the host namespace. Subscribing to each entry separately meant the host was watched once
	// per such pod: on a real node that was 25 netlink sockets and 25 duplicate events for every
	// host interface (1005 add events for 40 distinct interfaces).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	netnsResolver, cleanup := setupNetNS(t,
		[]string{"hostnet-pod-a", "hostnet-pod-b", "hostnet-pod-c"},
		[]string{"real-pod"})
	defer cleanup()

	watcher := NewWatcher(50, netnsResolver, metrics.NoOp())
	watcher.interfaces = func(_ netns.NsHandle, _ string, _ uint64) ([]Interface, error) {
		return []Interface{simpleInterface(1, "foo", macFoo)}, nil
	}
	watcher.linkSubscriberAt = func(_ netns.NsHandle, _ chan<- netlink.LinkUpdate, _ <-chan struct{}) error {
		return nil
	}

	_, err := watcher.Subscribe(ctx)
	require.NoError(t, err)

	var subscribed []string
	watcher.nsDone.Range(func(k, _ any) bool {
		subscribed = append(subscribed, k.(string))
		return true
	})
	sort.Strings(subscribed)
	assert.Equal(t, []string{"", "real-pod"}, subscribed,
		"the host namespace must be subscribed once, not once per bind mount")

	// A host-network pod showing up later must not start another subscription either.
	require.NoError(t, os.Symlink("/proc/self/ns/net",
		filepath.Join(netnsResolver.getNetNSPath(), "hostnet-pod-d")))
	watcher.createNamespace(ctx, "hostnet-pod-d", make(chan Event, 10))
	_, ok := watcher.nsDone.Load("hostnet-pod-d")
	assert.False(t, ok, "a new bind mount of the host netns must not be subscribed")
}
