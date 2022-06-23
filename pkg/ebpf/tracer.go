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

/*
#include <time.h>
static unsigned long long get_nsecs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000UL + ts.tv_nsec;
}
*/
import "C"

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../../bpf/flows.c -- -I../../bpf/headers

const (
	qdiscType = "clsact"
	// constants defined in flows.c as "volatile const"
	constSampling = "sampling"
)

const TCPFinFlag = 0x1
const TCPRstFlag = 0x10
const EvictionTimeout = 5000000000 // 5 seconds

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
	Bytes         uint64
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

func aggregateValues(mapValues []recordValue) recordValue {
	var aggRecord recordValue

	for _, mapValue := range mapValues {
		//fmt.Printf("%+v\n", mapValue)
		aggRecord.Packets += mapValue.Packets
		aggRecord.Bytes += mapValue.Bytes
		if mapValue.FlowStartTime != 0 {
			aggRecord.FlowStartTime = mapValue.FlowStartTime
		}
		if mapValue.FlowEndTime > aggRecord.FlowEndTime {
			aggRecord.FlowEndTime = mapValue.FlowEndTime
		}

	}
	return aggRecord
}

func makeRecord(mapKey recordKeyV4, mapValue recordValue, direction uint8) *flow.Record {
	var myFlow flow.Record
	myFlow.EthProtocol = mapKey.Protocol
	myFlow.Direction = direction
	myFlow.DataLink = mapKey.DataLink
	myFlow.Network = mapKey.Network
	myFlow.Transport = mapKey.Transport
	myFlow.Packets = mapValue.Packets
	myFlow.Bytes = mapValue.Bytes
	myFlow.FlowStartTime = mapValue.FlowStartTime
	myFlow.FlowEndTime = mapValue.FlowEndTime

	//TODO : Need to calculate current time in perspective
	return &myFlow
}
func (m *FlowTracer) aggregateEntries(mapKey recordKeyV4, direction uint8) (recordValue, error) {
	var err error
	var mapValues []recordValue

	if direction == EGRESS {
		// Get the individual map values from Egress per-cpu hash
		if err = m.objects.XflowMetricMapEgress.Lookup(mapKey, &mapValues); err != nil {
			fmt.Printf("\nFailed in reading egress map: %v", err)
			return recordValue{}, err
		}
		if err = m.objects.XflowMetricMapEgress.Delete(mapKey); err != nil {
			fmt.Printf("\nFailed in delete map: %v", err)
		}
	} else {
		// Get the individual map values from Ingress per-cpu hash
		if err = m.objects.XflowMetricMapIngress.Lookup(mapKey, &mapValues); err != nil {
			fmt.Printf("\nFailed in reading ingress map: %v", err)
			return recordValue{}, err
		}
		if err = m.objects.XflowMetricMapIngress.Delete(mapKey); err != nil {
			fmt.Printf("\nFailed in delete map: %v", err)
		}
	}
	// var sumPackets uint32
	// var sumBytes flow.HumanBytes
	// var FirstPktTime flow.Timestamp
	// var LastPktTime flow.Timestamp

	aggRecord := aggregateValues(mapValues)
	fmt.Printf("Aggregated Values : %+v", aggRecord)

	return aggRecord, nil
}

func (m *FlowTracer) scrubFlow(readFlow *flow.Record) error {
	mapKey := recordKeyV4{Protocol: readFlow.EthProtocol,
		DataLink:  readFlow.DataLink,
		Network:   readFlow.Network,
		Transport: readFlow.Transport}

	fmt.Printf("Scrub Flow : %+v\n", mapKey)

	aggRecord, err := m.aggregateEntries(mapKey, readFlow.Direction)

	if err == nil {
		// Modify the readFlow record which was the evicted entry from the hash map
		readFlow.Packets += aggRecord.Packets
		readFlow.Bytes += aggRecord.Bytes
		readFlow.FlowStartTime = aggRecord.FlowStartTime
		readFlow.FlowEndTime = aggRecord.FlowEndTime
	}
	return err
}

// func (m *FlowTracer) scrubReverseFlow(readFlow *flow.Record) (*flow.Record, error) {
// 	mapKeyReverse := recordKeyV4{
// 		Protocol: readFlow.Protocol,
// 		DataLink: flow.DataLink{
// 			SrcMac: readFlow.DataLink.DstMac,
// 			DstMac: readFlow.DataLink.SrcMac,
// 		},
// 		Network: flow.Network{
// 			SrcAddr: readFlow.Network.DstAddr,
// 			DstAddr: readFlow.Network.SrcAddr,
// 		},
// 		Transport: flow.Transport{
// 			SrcPort: readFlow.Transport.DstPort,
// 			DstPort: readFlow.Transport.SrcPort,
// 			Protocol: readFlow.Transport.Protocol,
// 		},
// 	}
//
// 	var readFlowReverse flow.Record
// 	readFlowReverse.Protocol = readFlow.Protocol
// 	readFlowReverse.Direction = readFlow.Direction
// 	readFlowReverse.DataLink = mapKeyReverse.DataLink
// 	readFlowReverse.Network = mapKeyReverse.Network
// 	readFlowReverse.Transport = mapKeyReverse.Transport
//
//
// 	fmt.Printf("ScrubFlow reverse: %+v\n", mapKeyReverse)
//
//
// 	aggRecord,err := m.aggregateEntries(mapKeyReverse, readFlowReverse.Direction)
//
// 	if err == nil {
// 		// Modify the readFlow record which was the evicted entry from the hash map
// 		readFlowReverse.Packets = aggRecord.Packets
// 		readFlowReverse.Bytes = aggRecord.Bytes
// 		readFlowReverse.FlowStartTime = aggRecord.FlowStartTime
// 		readFlowReverse.FlowEndTime = aggRecord.FlowEndTime
// 	}
// 	return &readFlowReverse, err
// }

// Trace and forward the read flows until the passed context is Done
func (m *FlowTracer) MonitorEgress(ctx context.Context, forwardFlows chan<- *flow.Record) {
	tlog := log.WithField("iface", m.interfaceName)
	var myDirection uint8 = 1
	go func() {
		<-ctx.Done()
	}()
	for {
		select {
		case <-ctx.Done():
			tlog.Debug("exiting monitor")
			return
		default:
			egressMapIterator := m.objects.XflowMetricMapEgress.Iterate()
			// Check Egress Map
			var entriesAvail = true
			for entriesAvail {
				var mapKey recordKeyV4
				var mapValues []recordValue
				fmt.Println("Iterating Egress Entries..")
				timeNow := flow.Timestamp(C.get_nsecs())
				entriesAvail = egressMapIterator.Next(&mapKey, &mapValues)
				aggRecord := aggregateValues(mapValues)
				fmt.Printf("%+v..%+v\n", mapKey, aggRecord)
				// Eviction Logic can be based on the following three metrics:
				//   1) LastPacket > 5 sec ?
				//		The problem with this is how to check the time
				//   2) Packet/Byte count?
				//   3) Number of entries
				fmt.Println(timeNow)
				var timediff flow.Timestamp
				if timeNow > aggRecord.FlowEndTime {
					timediff = timeNow - aggRecord.FlowEndTime
				} else {
					timediff = aggRecord.FlowEndTime - timeNow
				}
				if (aggRecord.FlowEndTime != 0) && (timediff > EvictionTimeout) {
					fmt.Println("Evicting entry")
					myFlow := makeRecord(mapKey, aggRecord, myDirection)
					fmt.Printf("%+v\n", myFlow)
					myFlow.Interface = m.interfaceName
					forwardFlows <- myFlow
					if err := m.objects.XflowMetricMapEgress.Delete(mapKey); err != nil {
						fmt.Printf("\nFailed in delete map: %v", err)
					}
				}
			}
			time.Sleep(5 * time.Second)
		}
	}
}

// Trace and forward the read flows until the passed context is Done
func (m *FlowTracer) MonitorIngress(ctx context.Context, forwardFlows chan<- *flow.Record) {
	tlog := log.WithField("iface", m.interfaceName)
	var myDirection uint8 = 1
	go func() {
		<-ctx.Done()
	}()
	for {
		select {
		case <-ctx.Done():
			tlog.Debug("exiting monitor")
			return
		default:
			egressMapIterator := m.objects.XflowMetricMapIngress.Iterate()
			// Check Egress Map
			var entriesAvail = true
			for entriesAvail {
				var mapKey recordKeyV4
				var mapValues []recordValue
				fmt.Println("Iterating Ingress Entries..")
				timeNow := flow.Timestamp(C.get_nsecs())
				entriesAvail = egressMapIterator.Next(&mapKey, &mapValues)
				aggRecord := aggregateValues(mapValues)
				fmt.Printf("%+v..%+v\n", mapKey, aggRecord)
				// Eviction Logic can be based on the following three metrics:
				//   1) LastPacket > 5 sec ?
				//		The problem with this is how to check the time
				//   2) Packet/Byte count?
				//   3) Number of entries
				fmt.Println(timeNow)
				var timediff flow.Timestamp
				if timeNow > aggRecord.FlowEndTime {
					timediff = timeNow - aggRecord.FlowEndTime
				} else {
					timediff = aggRecord.FlowEndTime - timeNow
				}
				if (aggRecord.FlowEndTime != 0) && (timediff > EvictionTimeout) {
					fmt.Println("Evicting entry")
					myFlow := makeRecord(mapKey, aggRecord, myDirection)
					fmt.Printf("%+v\n", myFlow)
					myFlow.Interface = m.interfaceName
					forwardFlows <- myFlow
					if err := m.objects.XflowMetricMapIngress.Delete(mapKey); err != nil {
						fmt.Printf("\nFailed in delete map: %v", err)
					}
				}
			}
			time.Sleep(5 * time.Second)
		}
	}
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

			if ((readFlow.Flags & TCPFinFlag) == TCPFinFlag) || ((readFlow.Flags & TCPRstFlag) == TCPRstFlag) {
				// TODO : Need to check if we need update a flag if the flow is complete?

				// If we receive a FIN packet from the ring buffer, we need to perform the following:
				//	1) Check the direction of record : 1 for Egress, and 0 for Ingress
				//	2) Lookup and delete the key in the corresponding Map (e.g. egress), and send the record upwards
				//	3) Optional : Reverse the key and lookup and delete the other direction's Map (ingress now), and send the record upwards.
				//     This is not needed as you get ACK eitherwise.

				fmt.Printf("Received Complete Flag %X!\n", readFlow.Flags)
				readFlow.TimeFlowEnd = time.Now()
				// Currently, time provided by eBPF cannot be converted into time in go
				// since bpf_get_time_ns() uses CLOCK_MONOTIC which is majorly to measure delay.
				// Need to understand if we need a global time, which can be calculated as below:
				// readFlow.TimeFlowStart = readFlow.rawRecord.TimeEnd - delay (FlowEndTime - FlowStartTime)

				err := m.scrubFlow(readFlow)
				if err != nil {
					tlog.Debug("scrubFlow did not happen! (either nothing else remaining in the map)")
				}
				fmt.Printf("After Scrubbing: %+v\n", readFlow)

				// readFlowReverse, err := m.scrubReverseFlow(readFlow)
				// if err != nil {
				// 	tlog.Debug("scrubReverseFlow did not happen! (either nothing else remaining in the map)")
				// }
				//
				// fmt.Printf("After Scrubbing Reverse: %+v\n", readFlowReverse)
				//
				// forwardFlows <- readFlow

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
