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

const TCPFinFlag = 0x1
const EGRESS = 0x1

var log = logrus.WithField("component", "ebpf.FlowTracer")

//ongoingFlowMap = make(map[key]*Record, maxEntries),

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

type recordKeyV4 struct {
	Protocol  uint16 `json:"Etype"`
	DataLink  flow.DataLink
	Network   flow.Network
	Transport flow.Transport
}

// type recordKeyV6 struct {
// 	Protocol  uint16 `json:"Etype"`
// 	DataLink  flow.DataLink
// 	NetworkV6 flow.NetworkV6
// 	Transport flow.Transport
// 	// TODO: add TOS field
// }

type recordValue struct {
	Packets       uint32
	Bytes         flow.HumanBytes
	FlowStartTime flow.Timestamp
	FlowEndTime   flow.Timestamp
	Flags         uint32
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
		fmt.Printf("%s\n", m.objects)
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

func (m *FlowTracer) scrubFlow(readFlow *flow.Record) error {
	mapKey := recordKeyV4{Protocol: readFlow.Protocol,
		DataLink:  readFlow.DataLink,
		Network:   readFlow.Network,
		Transport: readFlow.Transport}
	// mapKeyReverse := recordKeyV4{Protocol: readFlow.Protocol,
	// 	DataLink:  DataLink{SrcMac: readFlow.DataLink.DstMac, DstMac: readFlow.DataLink.SrcMac},
	// 	Network:   Network{SrcAddr: readFlow.Network.DstAddr, DstAddr: readFlow.Network.SrcAddr},
	// 	Transport: Transport{SrcPort: readFlow.Transport.DstPort, DstPort: readFlow.Transport.SrcPort, Protocol: readFlow.Transport.Protocol}

	fmt.Printf("%+v\n", mapKey)

	var mapValues []recordValue

	if readFlow.Direction == EGRESS {
		var nextKey recordKeyV4
		fmt.Printf("Checking Egress: \n")
		err := m.objects.XflowMetricMapEgress.NextKey(nil, nextKey)
		for err != nil {
			fmt.Printf("%+v\n", nextKey)
			err = m.objects.XflowMetricMapEgress.NextKey(nil, nextKey)
		}

		if err = m.objects.XflowMetricMapEgress.Lookup(mapKey, &mapValues); err != nil {
			fmt.Printf("\nreading map: %v", err)
		}

		fmt.Printf("%+v\n", mapValues)
		// for i, mapValue := range mapValues {
		// 	// Aggregate values here
		//
		// }
	}
	return nil
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
			// Parses the ringbuf event entry into an Event structure.
			// The tracer receives a ringbuffer event
			readFlow, err := flow.ReadFrom(bytes.NewBuffer(event.RawSample))
			if err != nil {
				tlog.WithError(err).Warn("reading ringbuf event")
				continue
			}

			//  Upon an entry regarding the flow from ringbuffer, there are two possibilities:
			// 	1) TCP FIN Packet :
			// 		In this case, perfom eviction of this flow from ingress and
			// 		egress maps, and interim map in the userspace.
			// 	2) Normal Packet coming to userspace because of insufficient space in the map:
			// 		Send this packet to accounter without further action

			readFlow.Interface = m.interfaceName
			fmt.Printf("%+v\n", readFlow)

			if (readFlow.Flags & TCPFinFlag) == TCPFinFlag {
				// TODO : Need to check if we need update a flag if the flow is complete?

				// If we receive a FIN packet from the ring buffer, we need to perform the following:
				//	1) Check the direction of record : 1 for Egress, and 0 for Ingress
				//	2) Lookup and delete the key in the corresponding Map (e.g. egress), and send the record upwards
				//	3) Reverse the key and lookup and delete the other direction's Map (ingress now), and send the record upwards

				fmt.Printf("Complete Flow!")
				readFlow.TimeFlowEnd = time.Now()
				// Currently, time provided by eBPF cannot be converted into time in go
				// since bpf_get_time_ns() uses CLOCK_MONOTIC which is majorly to measure delay.
				// Need to understand if we need a global time, which can be calculated as below:
				// readFlow.TimeFlowStart = readFlow.rawRecord.TimeEnd - delay (FlowEndTime - FlowStartTime)

				err := m.scrubFlow(readFlow)
				if err != nil {
					tlog.Debug("scrubFlow did not happen! (either nothing else remaining in the map)")
				}
				// if readFlow.Protocol == flow.IPv6Type {
				// 	mapKey := recordKeyV6{Protocol: readFlow.Protocol,
				// 		 DataLink: readFlow.DataLink,
				// 		 NetworkV6: readFlow.NetworkV6,
				// 		 Transport: readFlow.Transport}
				// } else {

			}
			// Will need to send it to accounter anyway to account regardless of complete/ongoing flow
			forwardFlows <- readFlow

		}
	}
}
