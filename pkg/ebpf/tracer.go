package ebpf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/gavv/monotime"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
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

func NewFlowTracerFactory(sampling, cacheMaxSize, buffersLength int, evictionTimeout time.Duration) (func(string) *FlowTracer, io.Closer, error) {
	objects := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		return nil, &objects, fmt.Errorf("loading BPF data: %w", err)
	}

	// Resize maps according to user-provided configuration
	spec.Maps[constIngressMap].MaxEntries = uint32(cacheMaxSize)
	spec.Maps[constEgressMap].MaxEntries = uint32(cacheMaxSize)

	if err := spec.RewriteConstants(map[string]interface{}{
		constSampling: uint32(sampling),
	}); err != nil {
		return nil, &objects, fmt.Errorf("rewriting BPF constants definition: %w", err)
	}
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, &objects, fmt.Errorf("loading and assigning BPF objects: %w", err)
	}
	return func(iface string) *FlowTracer {
		return NewFlowTracer(iface, &objects, cacheMaxSize, buffersLength, evictionTimeout)
	}, &objects, nil
}

// FlowTracer reads and forwards the Flows from the Transmission Control, for a given interface.
type FlowTracer struct {
	interfaceName   string
	evictionTimeout time.Duration
	objects         *bpfObjects
	qdisc           *netlink.GenericQdisc
	egressFilter    *netlink.BpfFilter
	ingressFilter   *netlink.BpfFilter
	flows           *ringbuf.Reader
	buffersLength   int
	accounter       *flow.Accounter
}

// NewFlowTracer fo a given interface type
func NewFlowTracer(
	iface string,
	objects *bpfObjects,
	cacheMaxFlows, buffersLength int,
	evictionTimeout time.Duration,
) *FlowTracer {
	log.WithField("iface", iface).Debug("Instantiating flow tracer")

	return &FlowTracer{
		interfaceName:   iface,
		objects:         objects,
		evictionTimeout: evictionTimeout,
		buffersLength:   buffersLength,
		accounter:       flow.NewAccounter(iface, cacheMaxFlows, evictionTimeout),
	}
}

// Register and links the eBPF tracer into the system. The program should invoke Unregister
// before exiting.
func (m *FlowTracer) Register() error {
	ilog := log.WithField("iface", m.interfaceName)
	// Load pre-compiled programs and maps into the kernel, and rewrites the configuration
	ipvlan, err := netlink.LinkByName(m.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to lookup ipvlan device %q: %w", m.interfaceName, err)
	}
	qdiscAttrs := netlink.QdiscAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	m.qdisc = &netlink.GenericQdisc{
		QdiscAttrs: qdiscAttrs,
		QdiscType:  qdiscType,
	}
	if err := netlink.QdiscDel(m.qdisc); err == nil {
		ilog.Warn("qdisc clsact already existed. Deleted it")
	}
	if err := netlink.QdiscAdd(m.qdisc); err != nil {
		if errors.Is(err, fs.ErrExist) {
			ilog.WithError(err).Warn("qdisc clsact already exists. Ignoring")
		} else {
			m.qdisc = nil
			return fmt.Errorf("failed to create clsact qdisc on %q: %T %w", m.interfaceName, err, err)
		}
	}
	// Fetch events on egress
	egressAttrs := netlink.FilterAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  3,
		Priority:  1,
	}
	m.egressFilter = &netlink.BpfFilter{
		FilterAttrs:  egressAttrs,
		Fd:           m.objects.EgressFlowParse.FD(),
		Name:         "tc/egress_flow_parse",
		DirectAction: true,
	}
	if err := netlink.FilterDel(m.egressFilter); err == nil {
		ilog.Warn("egress filter already existed. Deleted it")
	}
	if err = netlink.FilterAdd(m.egressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			ilog.WithError(err).Warn("egress filter already exists. Ignoring")
		} else {
			return fmt.Errorf("failed to create egress filter: %w", err)
		}
	}
	// Fetch events on ingress
	ingressAttrs := netlink.FilterAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	m.ingressFilter = &netlink.BpfFilter{
		FilterAttrs:  ingressAttrs,
		Fd:           m.objects.IngressFlowParse.FD(),
		Name:         "tc/ingress_flow_parse",
		DirectAction: true,
	}
	if err := netlink.FilterDel(m.ingressFilter); err == nil {
		ilog.Warn("ingress filter already existed. Deleted it")
	}
	if err = netlink.FilterAdd(m.ingressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			ilog.WithError(err).Warn("ingress filter already exists. Ignoring")
		} else {
			return fmt.Errorf("failed to create ingress filter: %w", err)
		}
	}

	// read events from igress+egress ringbuffer
	if m.flows, err = ringbuf.NewReader(m.objects.Flows); err != nil {
		return fmt.Errorf("accessing to ringbuffer: %w", err)
	}
	return nil
}

// Unregister the eBPF tracer from the system.
func (m *FlowTracer) Unregister() error {
	tlog := log.WithField("iface", m.interfaceName)
	var errs []error
	if m.flows != nil {
		if err := m.flows.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.egressFilter != nil {
		tlog.WithField("filter", m.egressFilter).Debug("deleting egress filter")
		if err := netlink.FilterDel(m.egressFilter); err != nil {
			errs = append(errs, fmt.Errorf("deleting egress filter: %w", err))
		}
	}
	if m.ingressFilter != nil {
		tlog.WithField("filter", m.ingressFilter).Debug("deleting ingress filter")
		if err := netlink.FilterDel(m.ingressFilter); err != nil {
			errs = append(errs, fmt.Errorf("deleting ingress filter: %w", err))
		}
	}
	if m.qdisc != nil {
		tlog.WithField("qdisc", m.qdisc).Debug("deleting Qdisc")
		if err := netlink.QdiscDel(m.qdisc); err != nil {
			errs = append(errs, fmt.Errorf("deleting qdisc: %w", err))
		}
	}
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
	for i := range metrics {
		// a zero-valued recordValue in a given array slot means that no record has been processed
		// by this given CPU. We just ignore it
		if metrics[i].StartMonoTimeNs == 0 {
			continue
		}
		aggr.Accumulate(&metrics[i])
	}
	return aggr
}

// Monitor Egress Map to evict flows based on logic
func (m *FlowTracer) pollAndForwardEgress(ctx context.Context, forwardFlows chan<- []*flow.Record) {
	m.pollAndForward(ctx, m.objects.XflowMetricMapEgress, forwardFlows)
}

// Monitor Ingress Map to evict flows based on logic
func (m *FlowTracer) pollAndForwardIngress(ctx context.Context, forwardFlows chan<- []*flow.Record) {
	m.pollAndForward(ctx, m.objects.XflowMetricMapIngress, forwardFlows)
}

func (m *FlowTracer) pollAndForward(ctx context.Context, flowMap *ebpf.Map, forwardFlows chan<- []*flow.Record) {
	tlog := log.WithField("iface", m.interfaceName)
	go func() {
		<-ctx.Done()
	}()
	ticker := time.NewTicker(m.evictionTimeout)
	lastIterationFlowCount := 0
	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			tlog.Debug("exiting monitor")
			return
		case <-ticker.C:
			tlog.Debug("evicting flows")
			// it's important that this monotonic timer reports same or approximate values as kernel-side bpf_ktime_get_ns()
			monotonicTimeNow := monotime.Now()
			currentTime := time.Now()

			// dimension flows' slice to minimize slice resizings, assuming each iteration
			// will probably have a similar number of flows
			forwardingFlows := make([]*flow.Record, 0, lastIterationFlowCount)
			lastIterationFlowCount = 0

			var mapKey flow.RecordKey
			var mapValues []flow.RecordMetrics
			mapIterator := flowMap.Iterate()
			for mapIterator.Next(&mapKey, &mapValues) {
				// I fear an improbable race condition if the kernel space adds information in
				// the lapse between getting and deleting the map entry
				// TODO: try with combining NextKey and LookupAndDelete or BatchLookupAndDelete
				if err := flowMap.Delete(mapKey); err != nil {
					tlog.WithError(err).WithField("flowRecord", mapKey).
						Warn("couldn't delete flow from map")
				}
				forwardingFlows = append(forwardingFlows, flow.NewRecord(
					mapKey,
					m.aggregate(mapValues),
					currentTime,
					uint64(monotonicTimeNow),
					m.interfaceName,
				))
			}
			lastIterationFlowCount = len(forwardingFlows)
			if lastIterationFlowCount == 0 {
				log.Debug("no flows to forward")
			} else {
				forwardFlows <- forwardingFlows
				tlog.WithField("count", lastIterationFlowCount).Debug("flows evicted")
			}
		}
	}
}

// Trace and forward the read flows until the passed context is Done
func (m *FlowTracer) Trace(ctx context.Context, forwardFlows chan<- []*flow.Record) {
	tlog := log.WithField("iface", m.interfaceName)
	go func() {
		<-ctx.Done()
		// m.flows.Read is a blocking operation, so we need to close the ring buffer
		// from another goroutine to avoid the system not being able to exit if there
		// isn't traffic in a given interface
		if err := m.flows.Close(); err != nil {
			tlog.WithError(err).Warn("can't close ring buffer")
		}
	}()
	go m.pollAndForwardIngress(ctx, forwardFlows)
	go m.pollAndForwardEgress(ctx, forwardFlows)
	m.pollAndForwardRingbuffer(ctx, forwardFlows)
}

func (m *FlowTracer) pollAndForwardRingbuffer(ctx context.Context, forwardFlows chan<- []*flow.Record) {
	tlog := log.WithField("iface", m.interfaceName)
	flowAccount := make(chan *flow.RawRecord, m.buffersLength)
	go m.accounter.Account(flowAccount, forwardFlows)
	for {
		select {
		case <-ctx.Done():
			tlog.Debug("exiting flow tracer")
			return
		default:
			event, err := m.flows.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					tlog.Debug("Received signal, exiting..")
					return
				}
				tlog.WithError(err).Warn("reading from ring buffer")
				continue
			}
			// Parses the ringbuf event entry into an Event structure.
			readFlow, err := flow.ReadFrom(bytes.NewBuffer(event.RawSample))
			if err != nil {
				tlog.WithError(err).Warn("reading ringbuf event")
				continue
			}
			// Will need to send it to accounter anyway to account regardless of complete/ongoing flow
			flowAccount <- readFlow
		}
	}
}
