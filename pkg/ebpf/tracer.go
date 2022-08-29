package ebpf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gavv/monotime"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../../bpf/flows.c -- -I../../bpf/headers

const (
	qdiscType = "clsact"
	// constants defined in flows.c as "volatile const"
	constSampling   = "sampling"
	constIngressMap = "xflow_metric_map_ingress"
	constEgressMap  = "xflow_metric_map_egress"
)

var log = logrus.WithField("component", "ebpf.FlowTracer")

// FlowTracer reads and forwards the Flows from the Transmission Control, for a given interface.
type FlowTracer struct {
	evictionTimeout time.Duration
	objects         *bpfObjects
	qdiscs          map[ifaces.Interface]*netlink.GenericQdisc
	egressFilters   map[ifaces.Interface]*netlink.BpfFilter
	ingressFilters  map[ifaces.Interface]*netlink.BpfFilter
	flows           *ringbuf.Reader
	buffersLength   int
	accounter       *flow.Accounter
	interfaceNamer  flow.InterfaceNamer
	// manages the access to the eviction routines, avoiding two evictions happening at the same time
	ingressEviction *sync.Cond
	egressEviction  *sync.Cond
	lastEvictionNs  uint64
}

func NewFlowTracer(
	sampling, cacheMaxSize, buffersLength int,
	evictionTimeout time.Duration,
	namer flow.InterfaceNamer,
) (*FlowTracer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.WithError(err).
			Warn("can't remove mem lock. The agent could not be able to start eBPF programs")
	}

	objects := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
	}

	// Resize maps according to user-provided configuration
	spec.Maps[constIngressMap].MaxEntries = uint32(cacheMaxSize)
	spec.Maps[constEgressMap].MaxEntries = uint32(cacheMaxSize)

	if err := spec.RewriteConstants(map[string]interface{}{
		constSampling: uint32(sampling),
	}); err != nil {
		return nil, fmt.Errorf("rewriting BPF constants definition: %w", err)
	}
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	// read events from igress+egress ringbuffer
	flows, err := ringbuf.NewReader(objects.DirectFlows)
	if err != nil {
		return nil, fmt.Errorf("accessing to ringbuffer: %w", err)
	}
	return &FlowTracer{
		objects:         &objects,
		evictionTimeout: evictionTimeout,
		buffersLength:   buffersLength,
		accounter:       flow.NewAccounter(cacheMaxSize, evictionTimeout, namer, time.Now, monotime.Now),
		flows:           flows,
		egressFilters:   map[ifaces.Interface]*netlink.BpfFilter{},
		ingressFilters:  map[ifaces.Interface]*netlink.BpfFilter{},
		qdiscs:          map[ifaces.Interface]*netlink.GenericQdisc{},
		interfaceNamer:  namer,
		ingressEviction: sync.NewCond(&sync.Mutex{}),
		egressEviction:  sync.NewCond(&sync.Mutex{}),
		lastEvictionNs:  uint64(monotime.Now()),
	}, nil
}

// Register and links the eBPF tracer into the system. The program should invoke Unregister
// before exiting.
func (m *FlowTracer) Register(iface ifaces.Interface) error {
	ilog := log.WithField("iface", iface)
	// Load pre-compiled programs and maps into the kernel, and rewrites the configuration
	ipvlan, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		return fmt.Errorf("failed to lookup ipvlan device %d (%s): %w", iface.Index, iface.Name, err)
	}
	qdiscAttrs := netlink.QdiscAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: qdiscAttrs,
		QdiscType:  qdiscType,
	}
	if err := netlink.QdiscDel(qdisc); err == nil {
		ilog.Warn("qdisc clsact already existed. Deleted it")
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if errors.Is(err, fs.ErrExist) {
			ilog.WithError(err).Warn("qdisc clsact already exists. Ignoring")
		} else {
			return fmt.Errorf("failed to create clsact qdisc on %d (%s): %T %w", iface.Index, iface.Name, err, err)
		}
	}
	m.qdiscs[iface] = qdisc

	// Fetch events on egress
	egressAttrs := netlink.FilterAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  3,
		Priority:  1,
	}
	egressFilter := &netlink.BpfFilter{
		FilterAttrs:  egressAttrs,
		Fd:           m.objects.EgressFlowParse.FD(),
		Name:         "tc/egress_flow_parse",
		DirectAction: true,
	}
	if err := netlink.FilterDel(egressFilter); err == nil {
		ilog.Warn("egress filter already existed. Deleted it")
	}
	if err = netlink.FilterAdd(egressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			ilog.WithError(err).Warn("egress filter already exists. Ignoring")
		} else {
			return fmt.Errorf("failed to create egress filter: %w", err)
		}
	}
	m.egressFilters[iface] = egressFilter

	// Fetch events on ingress
	ingressAttrs := netlink.FilterAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	ingressFilter := &netlink.BpfFilter{
		FilterAttrs:  ingressAttrs,
		Fd:           m.objects.IngressFlowParse.FD(),
		Name:         "tc/ingress_flow_parse",
		DirectAction: true,
	}
	if err := netlink.FilterDel(ingressFilter); err == nil {
		ilog.Warn("ingress filter already existed. Deleted it")
	}
	if err = netlink.FilterAdd(ingressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			ilog.WithError(err).Warn("ingress filter already exists. Ignoring")
		} else {
			return fmt.Errorf("failed to create ingress filter: %w", err)
		}
	}
	m.ingressFilters[iface] = ingressFilter
	return nil
}

// Unregister the eBPF tracer from the system.
// We don't need an "Unregister(iface)" method because the filters and qdiscs
// are automatically removed when the interface is down
func (m *FlowTracer) unregisterEverything() error {
	var errs []error
	if m.flows != nil {
		if err := m.flows.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	for iface, ef := range m.egressFilters {
		log.WithField("interface", iface).Debug("deleting egress filter")
		if err := netlink.FilterDel(ef); err != nil {
			errs = append(errs, fmt.Errorf("deleting egress filter: %w", err))
		}
	}
	m.egressFilters = map[ifaces.Interface]*netlink.BpfFilter{}
	for iface, igf := range m.ingressFilters {
		log.WithField("interface", iface).Debug("deleting ingress filter")
		if err := netlink.FilterDel(igf); err != nil {
			errs = append(errs, fmt.Errorf("deleting ingress filter: %w", err))
		}
	}
	m.ingressFilters = map[ifaces.Interface]*netlink.BpfFilter{}
	for iface, qd := range m.qdiscs {
		log.WithField("interface", iface).Debug("deleting Qdisc")
		if err := netlink.QdiscDel(qd); err != nil {
			errs = append(errs, fmt.Errorf("deleting qdisc: %w", err))
		}
	}
	m.qdiscs = map[ifaces.Interface]*netlink.GenericQdisc{}
	if len(errs) == 0 {
		return nil
	}
	var errStrings []string
	for _, err := range errs {
		errStrings = append(errStrings, err.Error())
	}
	return errors.New(`errors: "` + strings.Join(errStrings, `", "`) + `"`)
}

func (m *FlowTracer) aggregate(metrics []flow.RecordMetrics) flow.RecordMetrics {
	if len(metrics) == 0 {
		log.Warn("invoked aggregate with no values")
		return flow.RecordMetrics{}
	}
	aggr := flow.RecordMetrics{}
	for _, mt := range metrics {
		// eBPF hashmap values are not zeroed when the entry is removed. That causes that we
		// might receive entries from previous collect-eviction timeslots.
		// We need to check the flow time and discard old flows.
		if mt.StartMonoTimeNs <= m.lastEvictionNs {
			continue
		}
		aggr.Accumulate(&mt)
	}
	return aggr
}

// Monitor Egress Map to evict flows based on logic
func (m *FlowTracer) pollAndForwardEgress(ctx context.Context, forwardFlows chan<- []*flow.Record) {
	m.pollAndForward(ctx, m.objects.XflowMetricMapEgress, forwardFlows, m.egressEviction)
}

// Monitor Ingress Map to evict flows based on logic
func (m *FlowTracer) pollAndForwardIngress(ctx context.Context, forwardFlows chan<- []*flow.Record) {
	m.pollAndForward(ctx, m.objects.XflowMetricMapIngress, forwardFlows, m.ingressEviction)
}

func (m *FlowTracer) pollAndForward(ctx context.Context, flowMap *ebpf.Map, forwardFlows chan<- []*flow.Record, evictor *sync.Cond) {
	tlog := log.WithField("map", flowMap.String())
	go func() {
		<-ctx.Done()
	}()
	go func() {
		for {
			// make sure we only evict once at a time, even if there are multiple eviction signals
			evictor.L.Lock()
			evictor.Wait()
			m.evictFlows(flowMap, tlog, forwardFlows)
			evictor.L.Unlock()

			// if context is canceled, stops the goroutine after evicting flows
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}()
	ticker := time.NewTicker(m.evictionTimeout)
	for {
		select {
		case <-ctx.Done():
			tlog.Debug("evicting flows after context cancelation")
			evictor.Broadcast()
			ticker.Stop()
			tlog.Debug("exiting monitor")
			return
		case <-ticker.C:
			tlog.Debug("evicting flows on timer")
			evictor.Broadcast()
		}
	}
}

func (m *FlowTracer) evictFlows(flowMap *ebpf.Map, tlog *logrus.Entry, forwardFlows chan<- []*flow.Record) {
	// it's important that this monotonic timer reports same or approximate values as kernel-side bpf_ktime_get_ns()
	monotonicTimeNow := monotime.Now()
	currentTime := time.Now()

	mapKeys, mapValues := m.lookupAndDeleteMapKeysValues(flowMap)

	var forwardingFlows []*flow.Record
	laterFlowNs := uint64(0)
	for nf, flowKey := range mapKeys {
		flowMetrics := mapValues[nf]
		aggregatedMetrics := m.aggregate(flowMetrics)
		if aggregatedMetrics.StartMonoTimeNs > laterFlowNs {
			laterFlowNs = aggregatedMetrics.StartMonoTimeNs
		}
		forwardingFlows = append(forwardingFlows, flow.NewRecord(
			flowKey,
			aggregatedMetrics,
			currentTime,
			uint64(monotonicTimeNow),
			m.interfaceNamer,
		))
	}
	m.lastEvictionNs = laterFlowNs
	forwardFlows <- forwardingFlows
	tlog.WithField("count", len(forwardingFlows)).Debug("flows evicted")
}

// Trace and forward the read flows until the passed context is Done
func (m *FlowTracer) Trace(ctx context.Context, forwardFlows chan<- []*flow.Record) {
	go func() {
		<-ctx.Done()
		// m.flows.Read is a blocking operation, so we need to close the ring buffer
		// from another goroutine to avoid the system not being able to exit if there
		// isn't traffic in a given interface
		if err := m.flows.Close(); err != nil {
			log.WithError(err).Warn("Tracer: can't close ring buffer")
		}
		m.unregisterEverything()
	}()
	go m.pollAndForwardIngress(ctx, forwardFlows)
	go m.pollAndForwardEgress(ctx, forwardFlows)
	m.listenAndForwardRingBuffer(ctx, forwardFlows)
}

func (m *FlowTracer) listenAndForwardRingBuffer(ctx context.Context, forwardFlows chan<- []*flow.Record) {
	flowAccount := make(chan *flow.RawRecord, m.buffersLength)
	go m.accounter.Account(flowAccount, forwardFlows)
	for {
		select {
		case <-ctx.Done():
			log.Debug("exiting flow tracer")
			return
		default:
			event, err := m.flows.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Debug("Received signal, exiting..")
					return
				}
				log.WithError(err).Warn("reading from ring buffer")
				continue
			}
			// Parses the ringbuf event entry into an Event structure.
			readFlow, err := flow.ReadFrom(bytes.NewBuffer(event.RawSample))
			if err != nil {
				log.WithError(err).Warn("reading ringbuf event")
				continue
			}
			log.WithField("direction", readFlow.Direction).
				Debug("received flow from ringbuffer. Evicting in-memory maps to leave free space")
			switch readFlow.Direction {
			case flow.DirectionIngress:
				m.ingressEviction.Broadcast()
			case flow.DirectionEgress:
				m.egressEviction.Broadcast()
			default:
				log.WithField("direction", readFlow.Direction).
					Warnf("received flow with incorrect direction: %#v", readFlow)
			}

			// Will need to send it to accounter anyway to account regardless of complete/ongoing flow
			flowAccount <- readFlow
		}
	}
}

// For synchronization purposes, we get/delete a whole snapshot of the flows map.
// This way we avoid missing packets that could be updated on the
// ebpf side while we process/aggregate them here
// TODO: detect whether BatchLookupAndDelete is supported (e.g. not supported in Openshift 4.10) and use it selectively
func (m *FlowTracer) lookupAndDeleteMapKeysValues(flowMap *ebpf.Map) ([]flow.RecordKey, [][]flow.RecordMetrics) {
	var flowKeys []flow.RecordKey
	var flowsValues [][]flow.RecordMetrics

	// Get all map keys
	var err error
	key := flow.RecordKey{}
	for err = flowMap.NextKey(nil, &key); err == nil; err = flowMap.NextKey(key, &key) {
		flowKeys = append(flowKeys, key)
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		log.WithError(err).Warnf("couldn't read all keys from eBPF map: %s", flowMap.String())
	}

	// Lookup and delete all map entries
	for _, key := range flowKeys {
		var v []flow.RecordMetrics
		if err := flowMap.LookupAndDelete(key, &v); err != nil {
			log.WithError(err).WithField("flowId", key).
				Warnf("couldn't read Flow information for entry")
		}
		flowsValues = append(flowsValues, v)
	}
	return flowKeys, flowsValues
}
