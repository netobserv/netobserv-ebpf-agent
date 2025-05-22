package ifaces

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestRegisterer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher := NewWatcher(10)
	registry := NewRegisterer(watcher, 10)
	// mock net.Interfaces and linkSubscriber to control which interfaces are discovered
	watcher.interfaces = func(_ netns.NsHandle, _ string) ([]Interface, error) {
		return []Interface{{"foo", 1, macFoo, netns.None(), ""}, {"bar", 2, macBar, netns.None(), ""}, {"baz", 3, macBaz, netns.None(), ""}}, nil
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

	outputEvents, err := registry.Subscribe(ctx)
	require.NoError(t, err)

	// initial set of fetched elements
	for i := 0; i < 3; i++ {
		getEvent(t, outputEvents, timeout)
	}
	assert.Equal(t, map[[6]uint8]string{macFoo: "foo"}, registry.ifaces[1])
	assert.Equal(t, map[[6]uint8]string{macBar: "bar"}, registry.ifaces[2])
	assert.Equal(t, map[[6]uint8]string{macBaz: "baz"}, registry.ifaces[3])

	// updates
	inputLinks <- upAndRunning("bae", 4, macBae[:], netns.None())
	inputLinks <- down("bar", 2, macBar[:], netns.None())
	for i := 0; i < 2; i++ {
		getEvent(t, outputEvents, timeout)
	}

	assert.Equal(t, map[[6]uint8]string{macFoo: "foo"}, registry.ifaces[1])
	assert.Nil(t, registry.ifaces[2])
	assert.Equal(t, map[[6]uint8]string{macBaz: "baz"}, registry.ifaces[3])
	assert.Equal(t, map[[6]uint8]string{macBae: "bae"}, registry.ifaces[4])

	inputLinks <- upAndRunning("fiu", 1, macOverlapped[:], netns.None())
	getEvent(t, outputEvents, timeout)

	assert.Equal(t, map[[6]uint8]string{macFoo: "foo", macOverlapped: "fiu"}, registry.ifaces[1])
	assert.Nil(t, registry.ifaces[2])
	assert.Equal(t, map[[6]uint8]string{macBaz: "baz"}, registry.ifaces[3])
	assert.Equal(t, map[[6]uint8]string{macBae: "bae"}, registry.ifaces[4])

	inputLinks <- down("foo", 1, macFoo[:], netns.None())
	getEvent(t, outputEvents, timeout)

	assert.Equal(t, map[[6]uint8]string{macOverlapped: "fiu"}, registry.ifaces[1])
	assert.Nil(t, registry.ifaces[2])
	assert.Equal(t, map[[6]uint8]string{macBaz: "baz"}, registry.ifaces[3])
	assert.Equal(t, map[[6]uint8]string{macBae: "bae"}, registry.ifaces[4])
}

func TestRegisterer_Lookup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		macEth0      = [6]uint8{0x0a, 0x58, 0x0a, 0x81, 0x02, 0x06}
		macEns5      = [6]uint8{0x06, 0x62, 0x90, 0x15, 0xba, 0x83}
		macOVN       = [6]uint8{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
		macMadeUpOVN = [6]uint8{0x0a, 0x58, 0x64, 0x58, 0x00, 0x07}
	)

	watcher := NewWatcher(10)
	registry := NewRegisterer(watcher, 10)
	// Set conflicting interfaces on ifindex 2 (they would have different netns, but that's not important for this test)
	watcher.interfaces = func(_ netns.NsHandle, _ string) ([]Interface, error) {
		return []Interface{
			{"ens5", 2, macEns5, netns.None(), ""},
			{"eth0", 2, macEth0, netns.None(), ""},
			{"a_pod_interface@if2", 10, macOVN, netns.None(), ""},
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

	outputEvents, err := registry.Subscribe(ctx)
	require.NoError(t, err)

	// initial set of fetched elements
	for i := 0; i < 3; i++ {
		getEvent(t, outputEvents, timeout)
	}

	// test perfect match without collision
	name, ok := registry.IfaceNameForIndexAndMAC(10, macOVN)
	assert.True(t, ok)
	assert.Equal(t, "a_pod_interface@if2", name)

	// test perfect match with collision
	name, ok = registry.IfaceNameForIndexAndMAC(2, macEns5)
	assert.True(t, ok)
	assert.Equal(t, "ens5", name)

	// test ovn optimization
	name, ok = registry.IfaceNameForIndexAndMAC(2, macMadeUpOVN)
	assert.True(t, ok)
	assert.Equal(t, "eth0", name)

	// test partial match best effort (good ifindex, wrong mac)
	name, ok = registry.IfaceNameForIndexAndMAC(2, [6]uint8{0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
	assert.True(t, ok)
	// first entry is returned, which can be either eth0 or ens5
	if name != "ens5" && name != "eth0" {
		assert.Fail(t, "should be either ens5 or eth0", "found %s", name)
	}

	// test no match (wrong ifindex)
	_, ok = registry.IfaceNameForIndexAndMAC(5, [6]uint8{0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
	assert.False(t, ok)
}
