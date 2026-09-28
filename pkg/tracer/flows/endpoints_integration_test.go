//go:build linux && integration

package flows

import (
	"encoding/binary"
	"net"
	"runtime"
	"slices"
	"testing"
	"time"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	configflows "github.com/netobserv/netobserv-ebpf-agent/pkg/config/flows"
	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/attach"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// These tests require BPF/NET_ADMIN privileges and tracefs. Run them in an
// isolated privileged container; the drops test creates temporary veth links
// and a network namespace. No TC program is attached to a live interface.
func loadEndpointTestCollection(t *testing.T, capacity uint32, filter *attach.Filter, programs ...string) *cilium.Collection {
	t.Helper()
	require.NoError(t, rlimit.RemoveMemlock())
	spec, err := ebpf.LoadBpf()
	require.NoError(t, err)
	for name := range spec.Programs {
		if !slices.Contains(programs, name) {
			delete(spec.Programs, name)
		}
	}
	for _, m := range spec.Maps {
		m.Pinning = cilium.PinNone
		if m.Type == cilium.Hash || m.Type == cilium.PerCPUHash {
			m.MaxEntries = 16
		} else if m.Type == cilium.RingBuf {
			m.MaxEntries = 4096
		}
	}
	cfg := &tracer.FetcherConfig{Agent: config.Agent{Flows: configflows.Features{
		EndpointMapMaxEntries:         capacity,
		EnablePktDrops:                true,
		EnablePktTranslationTracking:  true,
		EnableRTT:                     true,
		EnableIPsecTracking:           true,
		EnableNetworkEventsMonitoring: true,
	}}}
	require.NoError(t, configureFlowSpecVariables(spec, cfg, filter))
	collection, err := cilium.NewCollection(spec)
	require.NoError(t, err, "%+v", err)
	t.Cleanup(collection.Close)
	return collection
}

func endpointTestPacket(dst byte) []byte {
	packet := make([]byte, 64)
	packet[12] = 8 // Ethernet: IPv4
	packet[14] = 0x45
	packet[17] = 50
	packet[22] = 64
	packet[23] = 17 // UDP
	copy(packet[26:30], []byte{192, 0, 2, 1})
	copy(packet[30:34], []byte{192, 0, 2, dst})
	binary.BigEndian.PutUint16(packet[34:36], 33123)
	binary.BigEndian.PutUint16(packet[36:38], 33124)
	binary.BigEndian.PutUint16(packet[38:40], 30)
	return packet
}

func TestEndpointDictionarySaturation(t *testing.T) {
	c := loadEndpointTestCollection(t, 2, nil, ebpf.BpfProgTcIngressFlowParse)
	program := c.Programs[ebpf.BpfProgTcIngressFlowParse]
	_, _, err := program.Test(endpointTestPacket(2))
	require.NoError(t, err)
	var key ebpf.BpfFlowId
	var value ebpf.BpfFlowMetrics
	iterator := c.Maps[ebpf.BpfMapAggregatedFlows].Iterate()
	require.True(t, iterator.Next(&key, &value))
	require.NoError(t, iterator.Err())
	require.NotZero(t, key.SrcId)
	require.NotZero(t, key.DstId)
	table := resolveEndpoints(slices.Values([]ebpf.BpfFlowId{key}), c.Maps[ebpf.BpfMapEndpointIps].Lookup)
	src, dst, ok := table.Addrs(key)
	require.True(t, ok)
	assert.Equal(t, "192.0.2.1", model.IP(src).String())
	assert.Equal(t, "192.0.2.2", model.IP(dst).String())
	require.NoError(t, c.Maps[ebpf.BpfMapAggregatedFlows].Delete(key))

	// Document the remaining lifecycle limitation: flow eviction cannot free
	// endpoint capacity, so an unseen address is lost even with an empty flow map.
	_, _, err = program.Test(endpointTestPacket(3))
	require.NoError(t, err)
	iterator = c.Maps[ebpf.BpfMapAggregatedFlows].Iterate()
	assert.False(t, iterator.Next(&key, &value))
	require.NoError(t, iterator.Err())
	var counters []uint32
	require.NoError(t, c.Maps[ebpf.BpfMapGlobalCounters].Lookup(uint32(ebpf.BpfGlobalCountersKeyTENDPOINT_INTERN_FAIL), &counters))
	var failures uint32
	for _, n := range counters {
		failures += n
	}
	assert.Equal(t, uint32(1), failures)
}

func TestEndpointTracingProgramsLoad(t *testing.T) {
	for _, program := range []string{
		ebpf.BpfProgKfreeSkb, ebpf.BpfProgTrackNatManipPkt,
		ebpf.BpfProgTcpRcvFentry, ebpf.BpfProgTcpRcvKprobe,
		ebpf.BpfProgNetworkEventsMonitoring,
		ebpf.BpfProgXfrmInputKprobe, ebpf.BpfProgXfrmInputKretprobe,
		ebpf.BpfProgXfrmOutputKprobe, ebpf.BpfProgXfrmOutputKretprobe,
	} {
		t.Run(program, func(t *testing.T) {
			loadEndpointTestCollection(t, 16, nil, program)
		})
	}
}

func TestDropsOnlyInternsUnseenEndpoints(t *testing.T) {
	filter := attach.NewFilter([]*attach.FilterConfig{{Action: "Accept", Drops: true}})
	c := loadEndpointTestCollection(t, 16, filter, ebpf.BpfProgTcIngressFlowParse, ebpf.BpfProgKfreeSkb)
	require.NoError(t, c.Maps[ebpf.BpfMapFilterMap].Update(
		ebpf.BpfFilterKeyT{PrefixLen: 30, IpData: [16]uint8{192, 0, 2, 0}},
		ebpf.BpfFilterValueT{Protocol: 17, DstPortStart: 33124, Direction: ebpf.BpfDirectionTMAX_DIRECTION,
			Action: ebpf.BpfFilterActionTACCEPT, FilterDrops: 1}, cilium.UpdateAny))

	// TC enables sampling, but drops-only filtering rejects the packet before
	// interning. The subsequent tracepoint must be able to create both IDs.
	_, _, err := c.Programs[ebpf.BpfProgTcIngressFlowParse].Test(endpointTestPacket(2))
	require.NoError(t, err)
	var id uint32
	var addr ebpf.BpfEndpointAddr
	iterator := c.Maps[ebpf.BpfMapEndpointIps].Iterate()
	require.False(t, iterator.Next(&id, &addr))
	require.NoError(t, iterator.Err())
	lnk, err := link.Tracepoint("skb", "kfree_skb", c.Programs[ebpf.BpfProgKfreeSkb], nil)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, lnk.Close()) })
	setupEndpointTestNetwork(t)
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 33123})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, socket.Close()) })
	var key ebpf.BpfFlowId
	var drops []ebpf.BpfPktDropMetrics
	require.Eventually(t, func() bool {
		_, writeErr := socket.WriteToUDP([]byte("endpoint test"), &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 33124})
		if writeErr != nil {
			return false
		}
		it := c.Maps[ebpf.BpfMapAggregatedFlowsPktDrop].Iterate()
		for it.Next(&key, &drops) {
			if key.SrcPort == 33123 && key.DstPort == 33124 {
				return true
			}
		}
		return false
	}, 5*time.Second, 50*time.Millisecond)
	table := resolveEndpoints(slices.Values([]ebpf.BpfFlowId{key}), c.Maps[ebpf.BpfMapEndpointIps].Lookup)
	src, dst, ok := table.Addrs(key)
	require.True(t, ok)
	assert.Equal(t, "192.0.2.1", model.IP(src).String())
	assert.Equal(t, "192.0.2.2", model.IP(dst).String())
}

func setupEndpointTestNetwork(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := netns.Get()
	require.NoError(t, err)
	defer func() { assert.NoError(t, original.Close()) }()
	peerNS, err := netns.New()
	require.NoError(t, err)
	require.NoError(t, netns.Set(original))
	t.Cleanup(func() { assert.NoError(t, peerNS.Close()) })
	peer, err := netlink.NewHandleAt(peerNS)
	require.NoError(t, err)
	t.Cleanup(peer.Close)
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "noep0"}, PeerName: "noep1", PeerNamespace: netlink.NsFd(peerNS)}
	require.NoError(t, netlink.LinkAdd(veth))
	t.Cleanup(func() { assert.NoError(t, netlink.LinkDel(veth)) })
	localAddr, err := netlink.ParseAddr("192.0.2.1/30")
	require.NoError(t, err)
	require.NoError(t, netlink.AddrAdd(veth, localAddr))
	require.NoError(t, netlink.LinkSetUp(veth))
	remote, err := peer.LinkByName("noep1")
	require.NoError(t, err)
	remoteAddr, err := netlink.ParseAddr("192.0.2.2/30")
	require.NoError(t, err)
	require.NoError(t, peer.AddrAdd(remote, remoteAddr))
	require.NoError(t, peer.LinkSetUp(remote))
}
