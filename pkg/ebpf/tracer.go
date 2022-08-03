package ebpf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"runtime"
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
	constSampling = "sampling"
)

const TCPFinFlag = 0x1
const TCPRstFlag = 0x10
const CollisionFlag = 0x100

const INGRESS = 0x0
const EGRESS = 0x1

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

type recordKey struct {
	Protocol  uint16 `json:"Etype"`
	Direction uint8  `json:"FlowDirection"`
	DataLink  flow.DataLink
	Network   flow.Network
	Transport flow.Transport
}

type recordValue struct {
	recordKey
	Packets       uint32
	Bytes         uint64
	FlowStartTime flow.Timestamp
	FlowEndTime   flow.Timestamp
	Flags         uint32
	// Flow ID Signature to verify
}

var resetMapValues []recordValue

var totalCollisions = 0
var ebpfCollisions = 0

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

// Aggregates and consolidates the record values obtained the Per-CPU Hash Map
func (m *FlowTracer) aggregateValues(mapKey recordKey, mapValues []recordValue) (recordValue, []recordValue) {
	tlog := log.WithField("iface", m.interfaceName)

	var aggRecord recordValue
	var collidedRecords []recordValue
	// Iterates over the array of record values and aggregates them into a single record
	for i, mapValue := range mapValues {
		if (mapKey.Transport.SrcPort == mapValue.Transport.SrcPort) &&
			(mapKey.Transport.DstPort == mapValue.Transport.DstPort) &&
			(mapKey.Transport.Protocol == mapValue.Transport.Protocol) {
			// Compare bare-minimum flow key value for sanity check and to
			// aggregate only packets of the correct Flow-id (to handle collisions)
			aggRecord.Packets += mapValue.Packets
			aggRecord.Bytes += mapValue.Bytes
			if mapValue.FlowStartTime != 0 {
				aggRecord.FlowStartTime = mapValue.FlowStartTime
			}
			if mapValue.FlowEndTime > aggRecord.FlowEndTime {
				aggRecord.FlowEndTime = mapValue.FlowEndTime
			}
		} else {
			if mapValue.Protocol != 0 {
				// Non-zero Eth Protocol indicates presence of a non-empty entry
				// which was added to the same map based on the hash, but is not the same key
				tlog.WithFields(logrus.Fields{
					"Core":       i,
					"FlowValues": mapValue,
					"Actual Key": mapKey,
				}).Debug("Encountered Hash Collisions")
				collidedRecords = append(collidedRecords, mapValue)
			}
		}
	}
	return aggRecord, collidedRecords
}

// Converts a <mapKey,mapValue> pair to a flow record
func makeRecord(mapKey recordKey, mapValue *recordValue) *flow.Record {
	var myFlow flow.Record
	myFlow.EthProtocol = mapKey.Protocol
	myFlow.Direction = mapKey.Direction
	myFlow.DataLink = mapKey.DataLink
	myFlow.Network = mapKey.Network
	myFlow.Transport = mapKey.Transport
	myFlow.Packets = mapValue.Packets
	myFlow.Bytes = mapValue.Bytes
	myFlow.FlowStartTime = mapValue.FlowStartTime
	myFlow.FlowEndTime = mapValue.FlowEndTime
	return &myFlow
}

// Converts a recordValue to flow.Record
func ConvertToRecord(mapValue *recordValue, timeNow flow.Timestamp, interfaceName string) *flow.Record {
	var myFlow flow.Record
	myFlow.EthProtocol = mapValue.Protocol
	myFlow.Direction = mapValue.Direction
	myFlow.DataLink = mapValue.DataLink
	myFlow.Network = mapValue.Network
	myFlow.Transport = mapValue.Transport

	myFlow.FlowStartTime = mapValue.FlowStartTime
	myFlow.FlowEndTime = mapValue.FlowEndTime
	myFlow.Interface = interfaceName
	myFlow.Packets = mapValue.Packets
	myFlow.Bytes = mapValue.Bytes
	timeDelta := timeNow - mapValue.FlowEndTime
	computeFlowTime(&myFlow, timeDelta)

	return &myFlow
}

// Computes the real clock time from eBPF CLOCK_MONOTONIC timestamps
func computeFlowTime(myFlow *flow.Record, timeDelta flow.Timestamp) {
	currentTime := time.Now()
	// TimeFlowEnd = currentTime - (Duration)timeDelta
	myFlow.TimeFlowEnd = currentTime.Add(time.Duration(-timeDelta))
	// TimeFlowStart = TimeFlowEnd - (Duration)(FlowEndTime - FlowStartTime)
	flowDuration := flow.Timestamp(0)
	if myFlow.FlowStartTime != 0 {
		flowDuration = myFlow.FlowEndTime - myFlow.FlowStartTime
	}
	myFlow.TimeFlowStart = myFlow.TimeFlowEnd.Add(time.Duration(-flowDuration))
}

// Eviction logic based on timeout of last seen packet of a flow
func evictInactiveFlows(mapKey recordKey, aggRecord *recordValue, evictionTimeout time.Duration, timeNow flow.Timestamp) (*flow.Record, bool) {
	var myFlow *flow.Record
	evict := false
	// Logic 1:
	if aggRecord.FlowEndTime == 0 {
		return myFlow, evict
	}
	var timeDelta flow.Timestamp
	if timeNow > aggRecord.FlowEndTime {
		timeDelta = timeNow - aggRecord.FlowEndTime
	} else {
		timeDelta = aggRecord.FlowEndTime - timeNow
	}
	if timeDelta > flow.Timestamp(evictionTimeout.Nanoseconds()) {
		evict = true
	}
	if evict {
		myFlow = makeRecord(mapKey, aggRecord)
		computeFlowTime(myFlow, timeDelta)
	}
	return myFlow, evict
}

// Obtains individual values based on a flow-id from the Per-CPU Hash Map and aggregates them
func (m *FlowTracer) aggregateEntries(mapKey recordKey) (recordValue, []recordValue, error) {
	var err error
	var mapValues []recordValue

	if mapKey.Direction == EGRESS {
		// Get the individual map values from Egress per-cpu hash
		if err = m.objects.XflowMetricMapEgress.Lookup(mapKey, &mapValues); err != nil {
			return recordValue{}, mapValues, err
		}
	} else {
		// Get the individual map values from Ingress per-cpu hash
		if err = m.objects.XflowMetricMapIngress.Lookup(mapKey, &mapValues); err != nil {
			return recordValue{}, mapValues, err
		}
	}
	m.resetEntriesAndDelete(mapKey)

	aggRecord, collidedRecords := m.aggregateValues(mapKey, mapValues)

	return aggRecord, collidedRecords, nil
}

// Scrubs a particular flow-id to be sent to accounter
func (m *FlowTracer) scrubFlow(readFlow *flow.Record) error {
	mapKey := recordKey{Protocol: readFlow.EthProtocol,
		Direction: readFlow.Direction,
		DataLink:  readFlow.DataLink,
		Network:   readFlow.Network,
		Transport: readFlow.Transport}

	aggRecord, collidedRecords, err := m.aggregateEntries(mapKey)
	totalCollisions += len(collidedRecords)
	if err == nil {
		// Modify the readFlow record which was the evicted entry from the hash map
		readFlow.Packets += aggRecord.Packets
		readFlow.Bytes += aggRecord.Bytes
		readFlow.FlowStartTime = aggRecord.FlowStartTime
		readFlow.FlowEndTime = aggRecord.FlowEndTime
		flowDuration := aggRecord.FlowEndTime - aggRecord.FlowStartTime
		readFlow.TimeFlowStart = readFlow.TimeFlowEnd.Add(time.Duration(-flowDuration))
	}
	return err
}

func initResetMapEntries() {
	resetMapValues = make([]recordValue, runtime.NumCPU())
}

// We Reset the entries before deletion, since we observe the entries are not cleared upon deletion,
// and when a new flow maps to the same entry, it has some zombie entries.
// TODO : Investigate if this is a generic issue and can it fixed in libbpf/gobpf?
func (m *FlowTracer) resetEntriesAndDelete(mapKey recordKey) {
	tlog := log.WithField("iface", m.interfaceName)
	if mapKey.Transport.Protocol == 1 {
		tlog.WithFields(logrus.Fields{
			"mapKey": mapKey,
		}).Debug("Deleting Record")
	}
	if mapKey.Direction == EGRESS {
		if err := m.objects.XflowMetricMapEgress.Update(mapKey, resetMapValues, ebpf.UpdateExist); err != nil {
			tlog.WithError(err).Warn("Failed in reset map")
		}
		if err := m.objects.XflowMetricMapEgress.Delete(mapKey); err != nil {
			tlog.WithError(err).Warn("Failed in delete map")
		}
	} else {
		if err := m.objects.XflowMetricMapIngress.Update(mapKey, resetMapValues, ebpf.UpdateExist); err != nil {
			tlog.WithError(err).Warn("Failed in reset map")
		}
		if err := m.objects.XflowMetricMapIngress.Delete(mapKey); err != nil {
			tlog.WithError(err).Warn("Failed in delete map")
		}
	}
}

// Monitor Egress Map to evict flows based on logic
func (m *FlowTracer) MonitorEgress(ctx context.Context, evictionTimeout time.Duration, forwardFlows chan<- *flow.Record) {
	tlog := log.WithField("iface", m.interfaceName)
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
			var mapEntries = 0
			// Check Egress Map
			var entriesAvail = true
			timeNow := flow.Timestamp(monotime.Now())
			for entriesAvail {
				var mapKey recordKey
				var mapValues []recordValue
				entriesAvail = egressMapIterator.Next(&mapKey, &mapValues)
				if !entriesAvail {
					break
				}
				mapEntries++
				aggRecord, collidedRecords := m.aggregateValues(mapKey, mapValues)

				// Eviction Logic can be based on the following three metrics:
				//   1) LastPacket > n sec ?
				//   2) Packet/Byte count > Threshold ?
				//   3) Number of Map entries > Threshold
				// 			Perform more aggressive eviction by reducing the flow timeout duration
				//   4) Regular Eviction (every n seconds)

				// Logic 1:
				// Evict if a flow has not seen any packet for the last "EvictionTimeout" seconds
				myFlow, evict := evictInactiveFlows(mapKey, &aggRecord, evictionTimeout, timeNow)
				if evict {
					m.resetEntriesAndDelete(mapKey)
					myFlow.Interface = m.interfaceName
					forwardFlows <- myFlow
					totalCollisions += len(collidedRecords)
					for _, colrecValue := range collidedRecords {
						colRecord := ConvertToRecord(&colrecValue, timeNow, m.interfaceName)
						tlog.WithFields(logrus.Fields{
							"collidedRecords": colRecord,
						}).Debug("Collided Record")

						forwardFlows <- colRecord
					}
				}
				// In Future, other eviction logic can be implemented here based on the use-case
			}
			tlog.WithFields(logrus.Fields{
				"Entries":        mapEntries,
				"Collisions":     totalCollisions,
				"ebpfCollisions": ebpfCollisions,
			}).Debug("Egress Map")
			time.Sleep(1 * time.Second)
		}
	}
}

// Monitor Ingress Map to evict flows based on logic
func (m *FlowTracer) MonitorIngress(ctx context.Context, evictionTimeout time.Duration, forwardFlows chan<- *flow.Record) {
	tlog := log.WithField("iface", m.interfaceName)
	go func() {
		<-ctx.Done()
	}()
	for {
		select {
		case <-ctx.Done():
			tlog.Debug("exiting monitor")
			return
		default:
			ingressMapIterator := m.objects.XflowMetricMapIngress.Iterate()
			var mapEntries = 0
			timeNow := flow.Timestamp(monotime.Now())
			// Check Ingress Map
			var entriesAvail = true
			for entriesAvail {
				var mapKey recordKey
				var mapValues []recordValue
				entriesAvail = ingressMapIterator.Next(&mapKey, &mapValues)
				if !entriesAvail {
					break
				}
				mapEntries++
				aggRecord, collidedRecords := m.aggregateValues(mapKey, mapValues)
				// Logic 1:
				// Evict if a flow has not seen any packet for the last "EvictionTimeout" seconds
				myFlow, evict := evictInactiveFlows(mapKey, &aggRecord, evictionTimeout, timeNow)

				if evict {
					m.resetEntriesAndDelete(mapKey)
					myFlow.Interface = m.interfaceName
					forwardFlows <- myFlow
					totalCollisions += len(collidedRecords)
					for _, colrecValue := range collidedRecords {
						colRecord := ConvertToRecord(&colrecValue, timeNow, m.interfaceName)
						forwardFlows <- colRecord
					}
				}
				// In Future, other eviction logic can be implemented here based on the use-case
			}
			tlog.WithFields(logrus.Fields{
				"Entries":        mapEntries,
				"Collisions":     totalCollisions,
				"ebpfCollisions": ebpfCollisions,
			}).Debug("Ingress Map")
			time.Sleep(1 * time.Second)
		}
	}
}

// Trace and forward the read flows until the passed context is Done
func (m *FlowTracer) Trace(ctx context.Context, forwardFlows chan<- *flow.Record) {
	tlog := log.WithField("iface", m.interfaceName)
	initResetMapEntries()
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
			now := time.Now()
			if ((readFlow.Flags & TCPFinFlag) == TCPFinFlag) || ((readFlow.Flags & TCPRstFlag) == TCPRstFlag) {

				// If we receive a FIN packet from the ring buffer, we need to perform the following:
				//	1) Check the direction of record : 1 for Egress, and 0 for Ingress
				//	2) Lookup and delete the key in the corresponding Map (e.g. egress), and send the record upwards
				//	3) Optional : Reverse the key and lookup and delete the other direction's Map (ingress now), and send the record upwards.
				//     This is not needed as you get ACK eitherwise.

				readFlow.TimeFlowEnd = now
				// TimeFlowStart is computed after scrubbing the flow from Per-CPU Hash Map

				err := m.scrubFlow(readFlow)
				if err != nil {
					tlog.Debug("scrubFlow did not happen! (possbibly nothing else remaining in the map (Multiple RST packets))")
					continue
				}
			} else {
				// Packet Records that came here due to hash collisions or a fully occupied map.
				readFlow.Packets = 1
				readFlow.TimeFlowStart = now
				readFlow.TimeFlowEnd = now
				readFlow.Interface = m.interfaceName
				if readFlow.Flags == CollisionFlag {
					ebpfCollisions++
				}
			}

			// Will need to send it to accounter anyway to account regardless of complete/ongoing flow
			forwardFlows <- readFlow

		}
	}
}
