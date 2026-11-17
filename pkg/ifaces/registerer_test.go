package ifaces

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestRegisterer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	netnsResolver, cleanup := setupEmptyNetNS(t)
	defer cleanup()
	watcher := NewWatcher(10, netnsResolver, metrics.NoOp())
	registry, err := NewRegisterer(watcher, &config.Agent{Common: config.Common{BuffersLength: 10}}, metrics.NoOp())
	require.NoError(t, err)
	// Override grace period to 10ms
	registry.deleteGrace = 10 * time.Millisecond

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

	outputEvents, err := registry.Subscribe(ctx)
	require.NoError(t, err)

	// initial set of fetched elements
	for i := 0; i < 3; i++ {
		getEvent(t, outputEvents, timeout)
	}
	assert.Equal(t, map[[6]uint8]ifaceEntry{macFoo: {name: "foo"}}, registry.ifaces[ifaceKey{index: 1}])
	assert.Equal(t, map[[6]uint8]ifaceEntry{macBar: {name: "bar"}}, registry.ifaces[ifaceKey{index: 2}])
	assert.Equal(t, map[[6]uint8]ifaceEntry{macBaz: {name: "baz"}}, registry.ifaces[ifaceKey{index: 3}])

	// updates
	inputLinks <- upAndRunning("bae", 4, macBae[:], netns.None())
	inputLinks <- down("bar", 2, macBar[:], netns.None())
	for i := 0; i < 2; i++ {
		getEvent(t, outputEvents, timeout)
	}
	// Wait for delete grace period
	time.Sleep(50 * time.Millisecond)

	registry.m.RLock()
	assert.Equal(t, map[[6]uint8]ifaceEntry{macFoo: {name: "foo"}}, registry.ifaces[ifaceKey{index: 1}])
	assert.Nil(t, registry.ifaces[ifaceKey{index: 2}])
	assert.Equal(t, map[[6]uint8]ifaceEntry{macBaz: {name: "baz"}}, registry.ifaces[ifaceKey{index: 3}])
	assert.Equal(t, map[[6]uint8]ifaceEntry{macBae: {name: "bae"}}, registry.ifaces[ifaceKey{index: 4}])
	registry.m.RUnlock()

	inputLinks <- upAndRunning("fiu", 1, macOverlapped[:], netns.None())
	getEvent(t, outputEvents, timeout)

	assert.Equal(t, map[[6]uint8]ifaceEntry{macFoo: {name: "foo"}, macOverlapped: {name: "fiu"}}, registry.ifaces[ifaceKey{index: 1}])
	assert.Nil(t, registry.ifaces[ifaceKey{index: 2}])
	assert.Equal(t, map[[6]uint8]ifaceEntry{macBaz: {name: "baz"}}, registry.ifaces[ifaceKey{index: 3}])
	assert.Equal(t, map[[6]uint8]ifaceEntry{macBae: {name: "bae"}}, registry.ifaces[ifaceKey{index: 4}])

	inputLinks <- down("foo", 1, macFoo[:], netns.None())
	getEvent(t, outputEvents, timeout)
	// Wait for delete grace period
	time.Sleep(50 * time.Millisecond)

	registry.m.RLock()
	assert.Equal(t, map[[6]uint8]ifaceEntry{macOverlapped: {name: "fiu"}}, registry.ifaces[ifaceKey{index: 1}])
	assert.Nil(t, registry.ifaces[ifaceKey{index: 2}])
	assert.Equal(t, map[[6]uint8]ifaceEntry{macBaz: {name: "baz"}}, registry.ifaces[ifaceKey{index: 3}])
	assert.Equal(t, map[[6]uint8]ifaceEntry{macBae: {name: "bae"}}, registry.ifaces[ifaceKey{index: 4}])
	registry.m.RUnlock()
}

func TestRegistererNoNetNs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher := NewWatcher(10, NewDisabledResolver(), metrics.NoOp())
	registry, err := NewRegisterer(watcher, &config.Agent{Common: config.Common{BuffersLength: 10}}, metrics.NoOp())
	require.NoError(t, err)
	// Override grace period to 10ms
	registry.deleteGrace = 10 * time.Millisecond

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

	outputEvents, err := registry.Subscribe(ctx)
	require.NoError(t, err)

	// initial set of fetched elements
	for i := 0; i < 3; i++ {
		getEvent(t, outputEvents, timeout)
	}
	assert.Equal(t, map[[6]uint8]ifaceEntry{macFoo: {name: "foo"}}, registry.ifaces[ifaceKey{index: 1}])
	assert.Equal(t, map[[6]uint8]ifaceEntry{macBar: {name: "bar"}}, registry.ifaces[ifaceKey{index: 2}])
	assert.Equal(t, map[[6]uint8]ifaceEntry{macBaz: {name: "baz"}}, registry.ifaces[ifaceKey{index: 3}])

	// updates
	inputLinks <- upAndRunning("bae", 4, macBae[:], netns.None())
	inputLinks <- down("bar", 2, macBar[:], netns.None())
	for i := 0; i < 2; i++ {
		getEvent(t, outputEvents, timeout)
	}
	// Wait for delete grace period
	time.Sleep(50 * time.Millisecond)

	registry.m.RLock()
	assert.Equal(t, map[[6]uint8]ifaceEntry{macFoo: {name: "foo"}}, registry.ifaces[ifaceKey{index: 1}])
	assert.Nil(t, registry.ifaces[ifaceKey{index: 2}])
	assert.Equal(t, map[[6]uint8]ifaceEntry{macBaz: {name: "baz"}}, registry.ifaces[ifaceKey{index: 3}])
	assert.Equal(t, map[[6]uint8]ifaceEntry{macBae: {name: "bae"}}, registry.ifaces[ifaceKey{index: 4}])
	registry.m.RUnlock()

	inputLinks <- upAndRunning("fiu", 1, macOverlapped[:], netns.None())
	getEvent(t, outputEvents, timeout)

	assert.Equal(t, map[[6]uint8]ifaceEntry{macFoo: {name: "foo"}, macOverlapped: {name: "fiu"}}, registry.ifaces[ifaceKey{index: 1}])
	assert.Nil(t, registry.ifaces[ifaceKey{index: 2}])
	assert.Equal(t, map[[6]uint8]ifaceEntry{macBaz: {name: "baz"}}, registry.ifaces[ifaceKey{index: 3}])
	assert.Equal(t, map[[6]uint8]ifaceEntry{macBae: {name: "bae"}}, registry.ifaces[ifaceKey{index: 4}])

	inputLinks <- down("foo", 1, macFoo[:], netns.None())
	getEvent(t, outputEvents, timeout)
	// Wait for delete grace period
	time.Sleep(50 * time.Millisecond)

	registry.m.RLock()
	assert.Equal(t, map[[6]uint8]ifaceEntry{macOverlapped: {name: "fiu"}}, registry.ifaces[ifaceKey{index: 1}])
	assert.Nil(t, registry.ifaces[ifaceKey{index: 2}])
	assert.Equal(t, map[[6]uint8]ifaceEntry{macBaz: {name: "baz"}}, registry.ifaces[ifaceKey{index: 3}])
	assert.Equal(t, map[[6]uint8]ifaceEntry{macBae: {name: "bae"}}, registry.ifaces[ifaceKey{index: 4}])
	registry.m.RUnlock()
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

	netnsResolver, cleanup := setupEmptyNetNS(t)
	defer cleanup()
	watcher := NewWatcher(10, netnsResolver, metrics.NoOp())
	registry, err := NewRegisterer(watcher, &config.Agent{Common: config.Common{BuffersLength: 10, PreferredInterfaceForMACPrefix: "0a:58=eth0"}}, metrics.NoOp())
	require.NoError(t, err)

	// Set conflicting interfaces on ifindex 2 (they would have different netns, but that's not important for this test)
	watcher.interfaces = func(_ netns.NsHandle, _ string, _ uint64) ([]Interface, error) {
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
	name, ok := registry.IfaceNameForIndexAndMAC(10, 0, macOVN)
	assert.True(t, ok)
	assert.Equal(t, "a_pod_interface@if2", name)

	// test perfect match with collision
	name, ok = registry.IfaceNameForIndexAndMAC(2, 0, macEns5)
	assert.True(t, ok)
	assert.Equal(t, "ens5", name)

	// test ovn optimization
	name, ok = registry.IfaceNameForIndexAndMAC(2, 0, macMadeUpOVN)
	assert.True(t, ok)
	assert.Equal(t, "eth0", name)

	// test partial match best effort (good ifindex, wrong mac)
	name, ok = registry.IfaceNameForIndexAndMAC(2, 0, [6]uint8{0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
	assert.True(t, ok)
	// first entry is returned, which can be either eth0 or ens5
	if name != "ens5" && name != "eth0" {
		assert.Fail(t, "should be either ens5 or eth0", "found %s", name)
	}

	// test no match (wrong ifindex)
	_, ok = registry.IfaceNameForIndexAndMAC(20, 0, [6]uint8{0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
	// Note: if that test fails on your machine, it may be that you actually have a corresponding interface index; you can increase the index in this test
	assert.False(t, ok)
}

func TestRegisterer_CrossNetnsDisambiguation(t *testing.T) {
	// Same ifindex under two different netns cookies must resolve to distinct names.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		macNS1 = [6]uint8{0x0a, 0x00, 0x00, 0x00, 0x00, 0x01}
		macNS2 = [6]uint8{0x0a, 0x00, 0x00, 0x00, 0x00, 0x02}
	)

	netnsResolver, cleanup := setupEmptyNetNS(t)
	defer cleanup()
	watcher := NewWatcher(10, netnsResolver, metrics.NoOp())
	registry, err := NewRegisterer(watcher, &config.Agent{Common: config.Common{BuffersLength: 10}}, metrics.NoOp())
	require.NoError(t, err)

	watcher.interfaces = func(_ netns.NsHandle, _ string, _ uint64) ([]Interface, error) {
		i1 := simpleInterface(5, "eth0_ns1", macNS1)
		i1.NetNSCookie = 111
		i2 := simpleInterface(5, "eth0_ns2", macNS2)
		i2.NetNSCookie = 222
		i3 := simpleInterface(5, "eth0_ns3", macNS1) // same mac as i1
		i3.NetNSCookie = 333
		return []Interface{i1, i2, i3}, nil
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
	for i := 0; i < 3; i++ {
		getEvent(t, outputEvents, timeout)
	}

	// Same index (5), different cookies => distinct interfaces
	name, ok := registry.IfaceNameForIndexAndMAC(5, 111, macNS1)
	assert.True(t, ok)
	assert.Equal(t, "eth0_ns1", name)

	name, ok = registry.IfaceNameForIndexAndMAC(5, 222, macNS2)
	assert.True(t, ok)
	assert.Equal(t, "eth0_ns2", name)

	// MAC ambiguity is ignored thanks to the netns cookie
	name, ok = registry.IfaceNameForIndexAndMAC(5, 333, macNS1)
	assert.True(t, ok)
	assert.Equal(t, "eth0_ns3", name)
}

func TestRegisterer_LookupRace(t *testing.T) {
	// No assertion here, purpose being to catch races
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	netnsResolver, cleanup := setupEmptyNetNS(t)
	defer cleanup()
	watcher := NewWatcher(10, netnsResolver, metrics.NoOp())
	registry, err := NewRegisterer(watcher, &config.Agent{Common: config.Common{BuffersLength: 10}}, metrics.NoOp())
	require.NoError(t, err)

	// Start with empty interfaces
	watcher.interfaces = func(_ netns.NsHandle, _ string, _ uint64) ([]Interface, error) {
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
			_, _ = registry.IfaceNameForIndexAndMAC(1, 0, macFoo)
			_, _ = registry.IfaceNameForIndexAndMAC(2, 0, macBar)
			_, _ = registry.IfaceNameForIndexAndMAC(3, 0, macBaz)
			_, _ = registry.IfaceNameForIndexAndMAC(3, 0, macBae)
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
	var allowList = map[[6]uint8]ifaceEntry{
		{1}: {name: "if1"},
		{2}: {name: "if2"},
		{3}: {name: "if3"},
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

func TestRegisterer_LookupMissLogsClashingCookies(t *testing.T) {
	// This log is the diagnostic for cross-namespace ifindex reuse: an SR-IOV VF keeps its
	// ifindex when moved from the host netns into a pod, so the same index can be registered
	// under a cookie other than the one the flow reports. Check it actually says so.
	var buf bytes.Buffer
	prevOut, prevLevel := rlog.Logger.Out, rlog.Logger.Level
	rlog.Logger.SetOutput(&buf)
	rlog.Logger.SetLevel(logrus.DebugLevel)
	t.Cleanup(func() {
		rlog.Logger.SetOutput(prevOut)
		rlog.Logger.SetLevel(prevLevel)
	})

	registry := &Registerer{ifaces: map[ifaceKey]map[[6]uint8]ifaceEntry{
		{cookie: 111, index: 7}: {macFoo: {name: "net1"}},
	}}

	// Same ifindex, different namespace: report who does hold it.
	_, ok := registry.IfaceNameForIndexAndMAC(7, 222, macBar)
	assert.False(t, ok)
	assert.Contains(t, buf.String(), "ifindex=7 cookie=222")
	assert.Contains(t, buf.String(), "net1 (cookie=111")

	// Unknown ifindex: say that nothing holds it, rather than staying silent.
	buf.Reset()
	_, ok = registry.IfaceNameForIndexAndMAC(99, 222, macBar)
	assert.False(t, ok)
	assert.Contains(t, buf.String(), "not registered under any cookie")
}

func TestRegisterer_GracePeriod(t *testing.T) {
	// On interface deletion, lookup still works for a grace period
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	netnsResolver, cleanup := setupEmptyNetNS(t)
	defer cleanup()
	watcher := NewWatcher(10, netnsResolver, metrics.NoOp())
	registry, err := NewRegisterer(watcher,
		&config.Agent{Common: config.Common{BuffersLength: 10, CacheActiveTimeout: 15 * time.Second}},
		metrics.NoOp())
	require.NoError(t, err)
	require.Equal(t, 16*time.Second, registry.deleteGrace)
	// Override grace period for this test
	registry.deleteGrace = 150 * time.Millisecond

	watcher.interfaces = func(_ netns.NsHandle, _ string, _ uint64) ([]Interface, error) {
		return []Interface{simpleInterface(1, "foo", macFoo), simpleInterface(2, "bar", macBar)}, nil
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
	for i := 0; i < 2; i++ {
		getEvent(t, outputEvents, timeout)
	}

	// Interface goes away; a flow captured just before must still be nameable.
	inputLinks <- down("bar", 2, macBar[:], netns.None())
	getEvent(t, outputEvents, timeout)
	name, ok := registry.IfaceNameForIndexAndMAC(2, 0, macBar)
	assert.True(t, ok, "name must survive the link going down")
	assert.Equal(t, "bar", name)

	// It's deleted after the grace period.
	assert.Eventually(t, func() bool {
		_, found := registry.IfaceNameForIndexAndMAC(2, 0, macBar)
		return !found
	}, time.Second, 10*time.Millisecond, "entry should be dropped once the grace period elapses")

	// A re-add during the grace period cancels the pending removal.
	inputLinks <- upAndRunning("foo", 1, macFoo[:], netns.None())
	inputLinks <- down("foo", 1, macFoo[:], netns.None())
	getEvent(t, outputEvents, timeout)
	inputLinks <- upAndRunning("foo", 1, macFoo[:], netns.None())
	getEvent(t, outputEvents, timeout)

	time.Sleep(2 * registry.deleteGrace)
	name, ok = registry.IfaceNameForIndexAndMAC(1, 0, macFoo)
	assert.True(t, ok, "re-added interface must not be removed by the earlier deletion timer")
	assert.Equal(t, "foo", name)
}
