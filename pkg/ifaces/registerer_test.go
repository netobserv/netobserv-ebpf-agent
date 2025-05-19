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
