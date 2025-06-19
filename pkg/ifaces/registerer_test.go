package ifaces

import (
	"context"
	"sync"
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestRegisterer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher := NewWatcher(10, metrics.NoOp())
	registry, err := NewRegisterer(watcher, &config.Agent{BuffersLength: 10}, metrics.NoOp())
	require.NoError(t, err)

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

	watcher := NewWatcher(10, metrics.NoOp())
	registry, err := NewRegisterer(watcher, &config.Agent{BuffersLength: 10, PreferredInterfaceForMACPrefix: "0a:58=eth0"}, metrics.NoOp())
	require.NoError(t, err)

	// Set conflicting interfaces on ifindex 2 (they would have different netns, but that's not important for this test)
	watcher.interfaces = func(_ netns.NsHandle, _ string) ([]Interface, error) {
		return []Interface{
			simpleInterface(2, "ens5", macEns5),
			simpleInterface(2, "eth0", macEth0),
			simpleInterface(10, "a_pod_interface@if2", macOVN),
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

func TestRegisterer_LookupRace(t *testing.T) {
	// No assertion here, purpose being to catch races
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher := NewWatcher(10, metrics.NoOp())
	registry, err := NewRegisterer(watcher, &config.Agent{BuffersLength: 10}, metrics.NoOp())
	require.NoError(t, err)

	// Start with empty interfaces
	watcher.interfaces = func(_ netns.NsHandle, _ string) ([]Interface, error) {
		return []Interface{}, nil
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

	// Process & consume interface events
	eventsCh, err := registry.Subscribe(ctx)
	require.NoError(t, err)
	go func() {
		for {
			<-eventsCh
		}
	}()

	wg := sync.WaitGroup{}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = registry.IfaceNameForIndexAndMAC(1, macFoo)
			_, _ = registry.IfaceNameForIndexAndMAC(2, macBar)
			_, _ = registry.IfaceNameForIndexAndMAC(3, macBaz)
			_, _ = registry.IfaceNameForIndexAndMAC(3, macBae)
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			inputLinks <- upAndRunning("bae", 3, macBae[:], netns.None())
			inputLinks <- upAndRunning("bar", 2, macBar[:], netns.None())
			inputLinks <- down("bae", 3, macBae[:], netns.None())
			inputLinks <- down("bar", 2, macBar[:], netns.None())
		}()
	}

	wg.Wait()
}

func TestRegisterer_PreferredInterfacesEdgeCases(t *testing.T) {
	pref, err := newPreferredInterfaces("")
	require.NoError(t, err)
	require.Len(t, pref, 0)

	pref, err = newPreferredInterfaces("invalid")
	require.ErrorContains(t, err, "bad format 'invalid'; expected 'mac_prefix=name'")
	require.Len(t, pref, 0)

	pref, err = newPreferredInterfaces("invalid=interface")
	require.ErrorContains(t, err, "bad MAC prefix 'invalid'; encoding/hex:")
	require.Len(t, pref, 0)

	pref, err = newPreferredInterfaces("=interface")
	require.ErrorContains(t, err, "empty MAC prefix in '=interface'")
	require.Len(t, pref, 0)

	pref, err = newPreferredInterfaces("aaaaaaaaaaaaaa=interface")
	require.ErrorContains(t, err, "MAC prefix too big 'aaaaaaaaaaaaaa'")
	require.Len(t, pref, 0)
}

func TestRegisterer_PreferredInterfacesNominal(t *testing.T) {
	var allowList = map[[6]uint8]string{
		{1}: "if1",
		{2}: "if2",
		{3}: "if3",
	}
	pref, err := newPreferredInterfaces("0a:58=if1,0b59=if2,0b62=if2bis,0c:60:80:=if3")
	require.NoError(t, err)
	assert.Equal(t, []preferredInterface{
		{
			macPrefix: []uint8{0x0a, 0x58},
			intf:      "if1",
		},
		{
			macPrefix: []uint8{0x0b, 0x59},
			intf:      "if2",
		},
		{
			macPrefix: []uint8{0x0b, 0x62},
			intf:      "if2bis",
		},
		{
			macPrefix: []uint8{0x0c, 0x60, 0x80},
			intf:      "if3",
		},
	}, pref)

	// Matches 0a:58=if1
	name, ok := pref[0].matches([6]uint8{0x0a, 0x58, 0x0a, 0x81, 0x02, 0x06}, allowList)
	assert.True(t, ok)
	assert.Equal(t, "if1", name)

	// No match 0b59=if2
	name, ok = pref[1].matches([6]uint8{0x0b, 0x62, 0x90, 0x15, 0xba, 0x83}, allowList)
	assert.False(t, ok)
	assert.Empty(t, name)

	// No match 0b62=if2bis because if2bis isn't in allow list
	name, ok = pref[2].matches([6]uint8{0x0b, 0x62, 0x90, 0x15, 0xba, 0x83}, allowList)
	assert.False(t, ok)
	assert.Empty(t, name)

	// Matches 0c:60:80:=if3
	name, ok = pref[3].matches([6]uint8{0x0c, 0x60, 0x80, 0x04, 0x05, 0x06}, allowList)
	assert.True(t, ok)
	assert.Equal(t, "if3", name)
}
