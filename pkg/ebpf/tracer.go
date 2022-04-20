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

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
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
	constSampling = "sampling"
)

var log = logrus.WithField("component", "ebpf.FlowTracer")

// FlowTracer reads and forwards the Flows from the Transmission Control, for a given interface.
type FlowTracer struct {
	interfaceName string
	sampling      uint32
	objects       bpfObjects
	qdisc         *netlink.GenericQdisc
	egressFilter  *netlink.BpfFilter
	ingressFilter *netlink.BpfFilter
	flows         *ringbuf.Reader
}

// NewFlowTracer fo a given interface type
func NewFlowTracer(iface string, sampling uint32) *FlowTracer {
	log.WithField("iface", iface).Debug("Instantiating flow tracer")
	return &FlowTracer{
		interfaceName: iface,
		sampling:      sampling,
	}
}

// Register and links the eBPF tracer into the system. The program should invoke Unregister
// before exiting.
func (m *FlowTracer) Register() error {
	ilog := log.WithField("iface", m.interfaceName)
	// Allow the current process to lock memory for eBPF resources.
	// TODO: manually invoke unix.Prlimit with lower/reasonable rlimit
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing mem lock: %w", err)
	}
	// Load pre-compiled programs and maps into the kernel, and rewrites the configuration
	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("loading BPF data: %w", err)
	}
	if err := spec.RewriteConstants(map[string]interface{}{
		constSampling: m.sampling,
	}); err != nil {
		return fmt.Errorf("rewriting BPF constants definition: %w", err)
	}
	if err := spec.LoadAndAssign(&m.objects, nil); err != nil {
		return fmt.Errorf("loading and assigning BPF objects: %w", err)
	}
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
	doClose := func(o io.Closer) {
		if o == nil {
			return
		}
		if err := o.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	doClose(m.flows)
	doClose(&m.objects)
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

// Trace and forward the read flows until the passed context is Done
func (m *FlowTracer) Trace(ctx context.Context, forwardFlows chan<- *flow.Record) {
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
			now := time.Now()
			// Parses the ringbuf event entry into an Event structure.
			readFlow, err := flow.ReadFrom(bytes.NewBuffer(event.RawSample))
			if err != nil {
				tlog.WithError(err).Warn("reading ringbuf event")
				continue
			}
			// Fills the Record with information that can't be provided by eBPF
			readFlow.Packets = 1
			readFlow.TimeFlowStart = now
			readFlow.TimeFlowEnd = now
			readFlow.Interface = m.interfaceName

			forwardFlows <- readFlow
		}
	}
}
