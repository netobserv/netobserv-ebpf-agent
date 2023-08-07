package ebpf

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/utils"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type flow_metrics_t -type flow_id_t -type flow_record_t -type tcp_drops_t -type dns_record_t Bpf ../../bpf/flows.c -- -I../../bpf/headers

const (
	qdiscType = "clsact"
	// ebpf map names as defined in flows.c
	aggregatedFlowsMap = "aggregated_flows"
	flowSequencesMap   = "flow_sequences"
	// constants defined in flows.c as "volatile const"
	constSampling      = "sampling"
	constTraceMessages = "trace_messages"
	constEnableRtt     = "enable_rtt"
	tcpDropHook        = "kfree_skb"
	dnsTraceHook       = "net_dev_queue"
	constPcaPort       = "pca_port"
	constPcaProto      = "pca_proto"
)

var log = logrus.WithField("component", "ebpf.FlowFetcher")
var plog = logrus.WithField("component", "ebpf.PacketFetcher")

// FlowFetcher reads and forwards the Flows from the Traffic Control hooks in the eBPF kernel space.
// It provides access both to flows that are aggregated in the kernel space (via PerfCPU hashmap)
// and to flows that are forwarded by the kernel via ringbuffer because could not be aggregated
// in the map
type FlowFetcher struct {
	objects              *BpfObjects
	qdiscs               map[ifaces.Interface]*netlink.GenericQdisc
	egressFilters        map[ifaces.Interface]*netlink.BpfFilter
	ingressFilters       map[ifaces.Interface]*netlink.BpfFilter
	ringbufReader        *ringbuf.Reader
	cacheMaxSize         int
	enableIngress        bool
	enableEgress         bool
	tcpDropsTracePoint   link.Link
	dnsTrackerTracePoint link.Link
}

type FlowFetcherConfig struct {
	EnableIngress bool
	EnableEgress  bool
	Debug         bool
	Sampling      int
	CacheMaxSize  int
	TCPDrops      bool
	DNSTracker    bool
	EnableRTT     bool
}

func NewFlowFetcher(cfg *FlowFetcherConfig) (*FlowFetcher, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.WithError(err).
			Warn("can't remove mem lock. The agent could not be able to start eBPF programs")
	}

	objects := BpfObjects{}
	spec, err := LoadBpf()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
	}

	// Resize maps according to user-provided configuration
	spec.Maps[aggregatedFlowsMap].MaxEntries = uint32(cfg.CacheMaxSize)
	spec.Maps[flowSequencesMap].MaxEntries = uint32(cfg.CacheMaxSize)

	traceMsgs := 0
	if cfg.Debug {
		traceMsgs = 1
	}

	enableRtt := 0
	if cfg.EnableRTT {
		if !(cfg.EnableEgress && cfg.EnableIngress) {
			log.Warnf("ENABLE_RTT is set to true. But both Ingress AND Egress are not enabled. Disabling ENABLE_RTT")
			enableRtt = 0
		} else {
			enableRtt = 1
		}
	}

	if enableRtt == 0 {
		// Cannot set the size of map to be 0 so set it to 1.
		spec.Maps[flowSequencesMap].MaxEntries = uint32(1)
	}

	if err := spec.RewriteConstants(map[string]interface{}{
		constSampling:      uint32(cfg.Sampling),
		constTraceMessages: uint8(traceMsgs),
		constEnableRtt:     uint8(enableRtt),
	}); err != nil {
		return nil, fmt.Errorf("rewriting BPF constants definition: %w", err)
	}

	oldKernel := utils.IskernelOlderthan514()

	log.Debugf("Deleting specs for PCA")
	objects.EgressPcaParse = nil
	objects.IngressPcaParse = nil
	delete(spec.Programs, constPcaPort)
	delete(spec.Programs, constPcaProto)

	// For older kernel (< 5.14) kfree_sbk drop hook doesn't exists
	if oldKernel {
		// Here we define another structure similar to the bpf2go created one but w/o the hooks that does not exist in older kernel
		// Note: if new hooks are added in the future we need to update the following structures manually
		type NewBpfPrograms struct {
			EgressFlowParse  *ebpf.Program `ebpf:"egress_flow_parse"`
			IngressFlowParse *ebpf.Program `ebpf:"ingress_flow_parse"`
			TraceNetPackets  *ebpf.Program `ebpf:"trace_net_packets"`
		}
		type NewBpfObjects struct {
			NewBpfPrograms
			BpfMaps
		}
		var newObjects NewBpfObjects
		// remove tcpdrop hook from the spec
		delete(spec.Programs, tcpDropHook)

		newObjects.NewBpfPrograms = NewBpfPrograms{}
		if err := spec.LoadAndAssign(&newObjects, nil); err != nil {
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				// Using %+v will print the whole verifier error, not just the last
				// few lines.
				log.Infof("Verifier error: %+v", ve)
			}
			return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
		}
		// Manually assign maps and programs to the original objects variable
		// Note for any future maps or programs make sure to copy them manually here
		objects.DirectFlows = newObjects.DirectFlows
		objects.AggregatedFlows = newObjects.AggregatedFlows
		objects.FlowSequences = newObjects.FlowSequences
		objects.EgressFlowParse = newObjects.EgressFlowParse
		objects.IngressFlowParse = newObjects.IngressFlowParse
		objects.TraceNetPackets = newObjects.TraceNetPackets
		objects.KfreeSkb = nil

	} else {
		if err := spec.LoadAndAssign(&objects, nil); err != nil {
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				// Using %+v will print the whole verifier error, not just the last
				// few lines.
				log.Infof("Verifier error: %+v", ve)
			}
			return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
		}
	}

	/*
	 * since we load the program only when the we start we need to release
	 * memory used by cached kernel BTF see https://github.com/cilium/ebpf/issues/1063
	 * for more details.
	 */
	btf.FlushKernelSpec()

	var tcpDropsLink link.Link
	if cfg.TCPDrops && !oldKernel {
		tcpDropsLink, err = link.Tracepoint("skb", tcpDropHook, objects.KfreeSkb, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to attach the BPF program to kfree_skb tracepoint: %w", err)
		}
	}

	var dnsTrackerLink link.Link
	if cfg.DNSTracker {
		dnsTrackerLink, err = link.Tracepoint("net", dnsTraceHook, objects.TraceNetPackets, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to attach the BPF program to trace_net_packets: %w", err)
		}
	}

	// read events from igress+egress ringbuffer
	flows, err := ringbuf.NewReader(objects.DirectFlows)
	if err != nil {
		return nil, fmt.Errorf("accessing to ringbuffer: %w", err)
	}
	return &FlowFetcher{
		objects:              &objects,
		ringbufReader:        flows,
		egressFilters:        map[ifaces.Interface]*netlink.BpfFilter{},
		ingressFilters:       map[ifaces.Interface]*netlink.BpfFilter{},
		qdiscs:               map[ifaces.Interface]*netlink.GenericQdisc{},
		cacheMaxSize:         cfg.CacheMaxSize,
		enableIngress:        cfg.EnableIngress,
		enableEgress:         cfg.EnableEgress,
		tcpDropsTracePoint:   tcpDropsLink,
		dnsTrackerTracePoint: dnsTrackerLink,
	}, nil
}

func registerInterface(iface ifaces.Interface) (*netlink.GenericQdisc, netlink.Link, error) {
	ilog := plog.WithField("iface", iface)
	ipvlan, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to lookup ipvlan device %d (%s): %w", iface.Index, iface.Name, err)
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
			return nil, nil, fmt.Errorf("failed to create clsact qdisc on %d (%s): %w", iface.Index, iface.Name, err)
		}
	}
	return qdisc, ipvlan, nil
}

// Register and links the eBPF fetcher into the system. The program should invoke Unregister
// before exiting.
func (m *FlowFetcher) Register(iface ifaces.Interface) error {
	qdisc, ipvlan, err := registerInterface(iface)
	if err != nil {
		return err
	}
	m.qdiscs[iface] = qdisc

	if err := m.registerEgress(iface, ipvlan); err != nil {
		return err
	}
	return m.registerIngress(iface, ipvlan)
}

func fetchEgressEvents(iface ifaces.Interface, ipvlan netlink.Link, parser *ebpf.Program, name string) (*netlink.BpfFilter, error) {
	ilog := plog.WithField("iface", iface)
	egressAttrs := netlink.FilterAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  3,
		Priority:  1,
	}
	egressFilter := &netlink.BpfFilter{
		FilterAttrs:  egressAttrs,
		Fd:           parser.FD(),
		Name:         "tc/" + name,
		DirectAction: true,
	}
	if err := netlink.FilterDel(egressFilter); err == nil {
		ilog.Warn("egress filter already existed. Deleted it")
	}
	if err := netlink.FilterAdd(egressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			ilog.WithError(err).Warn("egress filter already exists. Ignoring")
		} else {
			return nil, fmt.Errorf("failed to create egress filter: %w", err)
		}
	}
	return egressFilter, nil

}

func (p *PacketFetcher) registerEgress(iface ifaces.Interface, ipvlan netlink.Link) error {
	egressFilter, err := fetchEgressEvents(iface, ipvlan, p.objects.EgressPcaParse, "egress_pca_parse")
	if err != nil {
		return err
	}

	p.egressFilters[iface] = egressFilter
	return nil
}

func fetchIngressEvents(iface ifaces.Interface, ipvlan netlink.Link, parser *ebpf.Program, name string) (*netlink.BpfFilter, error) {
	ilog := plog.WithField("iface", iface)
	ingressAttrs := netlink.FilterAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  3,
		Priority:  1,
	}
	ingressFilter := &netlink.BpfFilter{
		FilterAttrs:  ingressAttrs,
		Fd:           parser.FD(),
		Name:         "tc/" + name,
		DirectAction: true,
	}
	if err := netlink.FilterDel(ingressFilter); err == nil {
		ilog.Warn("egress filter already existed. Deleted it")
	}
	if err := netlink.FilterAdd(ingressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			ilog.WithError(err).Warn("ingress filter already exists. Ignoring")
		} else {
			return nil, fmt.Errorf("failed to create egress filter: %w", err)
		}
	}
	return ingressFilter, nil

}

func (m *FlowFetcher) registerEgress(iface ifaces.Interface, ipvlan netlink.Link) error {
	egressFilter, err := fetchEgressEvents(iface, ipvlan, m.objects.EgressFlowParse, "egress_flow_parse")
	if err != nil {
		return err
	}

	m.egressFilters[iface] = egressFilter
	return nil
}

func (m *FlowFetcher) registerIngress(iface ifaces.Interface, ipvlan netlink.Link) error {
	ingressFilter, err := fetchIngressEvents(iface, ipvlan, m.objects.IngressFlowParse, "ingress_flow_parse")
	if err != nil {
		return err
	}

	m.ingressFilters[iface] = ingressFilter
	return nil
}

// Close the eBPF fetcher from the system.
// We don't need an "Close(iface)" method because the filters and qdiscs
// are automatically removed when the interface is down
func (m *FlowFetcher) Close() error {
	log.Debug("unregistering eBPF objects")

	var errs []error

	if m.tcpDropsTracePoint != nil {
		m.tcpDropsTracePoint.Close()
	}

	if m.dnsTrackerTracePoint != nil {
		m.dnsTrackerTracePoint.Close()
	}
	// m.ringbufReader.Read is a blocking operation, so we need to close the ring buffer
	// from another goroutine to avoid the system not being able to exit if there
	// isn't traffic in a given interface
	if m.ringbufReader != nil {
		if err := m.ringbufReader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.objects != nil {
		if err := m.objects.EgressFlowParse.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.IngressFlowParse.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.AggregatedFlows.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.DirectFlows.Close(); err != nil {
			errs = append(errs, err)
		}
		m.objects = nil
	}
	for iface, ef := range m.egressFilters {
		log := log.WithField("interface", iface)
		log.Debug("deleting egress filter")
		if err := doIgnoreNoDev(netlink.FilterDel, netlink.Filter(ef), log); err != nil {
			errs = append(errs, fmt.Errorf("deleting egress filter: %w", err))
		}
	}
	m.egressFilters = map[ifaces.Interface]*netlink.BpfFilter{}
	for iface, igf := range m.ingressFilters {
		log := log.WithField("interface", iface)
		log.Debug("deleting ingress filter")
		if err := doIgnoreNoDev(netlink.FilterDel, netlink.Filter(igf), log); err != nil {
			errs = append(errs, fmt.Errorf("deleting ingress filter: %w", err))
		}
	}
	m.ingressFilters = map[ifaces.Interface]*netlink.BpfFilter{}
	for iface, qd := range m.qdiscs {
		log := log.WithField("interface", iface)
		log.Debug("deleting Qdisc")
		if err := doIgnoreNoDev(netlink.QdiscDel, netlink.Qdisc(qd), log); err != nil {
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

// doIgnoreNoDev runs the provided syscall over the provided device and ignores the error
// if the cause is a non-existing device (just logs the error as debug).
// If the agent is deployed as part of the Network Observability pipeline, normally
// undeploying the FlowCollector could cause the agent to try to remove resources
// from Pods that have been removed immediately before (e.g. flowlogs-pipeline or the
// console plugin), so we avoid logging some errors that would unnecessarily raise the
// user's attention.
// This function uses generics because the set of provided functions accept different argument
// types.
func doIgnoreNoDev[T any](sysCall func(T) error, dev T, log *logrus.Entry) error {
	if err := sysCall(dev); err != nil {
		if errors.Is(err, unix.ENODEV) {
			log.WithError(err).Error("can't delete. Ignore this error if other pods or interfaces " +
				" are also being deleted at this moment. For example, if you are undeploying " +
				" a FlowCollector or Deployment where this agent is part of")
		} else {
			return err
		}
	}
	return nil
}

func (m *FlowFetcher) ReadRingBuf() (ringbuf.Record, error) {
	return m.ringbufReader.Read()
}

// LookupAndDeleteMap reads all the entries from the eBPF map and removes them from it.
// It returns a map where the key
// For synchronization purposes, we get/delete a whole snapshot of the flows map.
// This way we avoid missing packets that could be updated on the
// ebpf side while we process/aggregate them here
// Changing this method invocation by BatchLookupAndDelete could improve performance
// TODO: detect whether BatchLookupAndDelete is supported (Kernel>=5.6) and use it selectively
// Supported Lookup/Delete operations by kernel: https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
// Race conditions here causes that some flows are lost in high-load scenarios
func (m *FlowFetcher) LookupAndDeleteMap() map[BpfFlowId]*BpfFlowMetrics {
	flowMap := m.objects.AggregatedFlows

	iterator := flowMap.Iterate()
	var flow = make(map[BpfFlowId]*BpfFlowMetrics, m.cacheMaxSize)
	var id BpfFlowId
	var metric BpfFlowMetrics

	// Changing Iterate+Delete by LookupAndDelete would prevent some possible race conditions
	// TODO: detect whether LookupAndDelete is supported (Kernel>=4.20) and use it selectively
	for iterator.Next(&id, &metric) {
		if err := flowMap.Delete(id); err != nil {
			log.WithError(err).WithField("flowId", id).
				Warnf("couldn't delete flow entry")
		}
		metricPtr := new(BpfFlowMetrics)
		*metricPtr = metric
		flow[id] = metricPtr
	}
	return flow
}

// It provides access to packets from  the kernel space (via PerfCPU hashmap)
type PacketFetcher struct {
	objects        *BpfObjects
	qdiscs         map[ifaces.Interface]*netlink.GenericQdisc
	egressFilters  map[ifaces.Interface]*netlink.BpfFilter
	ingressFilters map[ifaces.Interface]*netlink.BpfFilter
	perfReader     *perf.Reader
	cacheMaxSize   int
	enableIngress  bool
	enableEgress   bool
}

func NewPacketFetcher(
	cacheMaxSize int,
	pcaFilters string,
	ingress, egress bool,
) (*PacketFetcher, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.WithError(err).
			Warn("can't remove mem lock. The agent could not be able to start eBPF programs")
	}

	objects := BpfObjects{}
	spec, err := LoadBpf()
	if err != nil {
		return nil, err
	}

	pcaPort := 0
	pcaProto := 0
	filters := strings.Split(pcaFilters, ",")
	if filters[0] == "tcp" {
		pcaProto = syscall.IPPROTO_TCP
	} else {
		pcaProto = syscall.IPPROTO_UDP
	}
	pcaPort, err = strconv.Atoi(filters[1])
	if err != nil {
		return nil, err
	}

	if err := spec.RewriteConstants(map[string]interface{}{
		constPcaPort:  uint16(pcaPort),
		constPcaProto: uint8(pcaProto),
	}); err != nil {
		return nil, fmt.Errorf("rewriting BPF constants definition: %w", err)
	}
	plog.Infof("PCA Filter- Protocol: %d, Port: %d", pcaProto, pcaPort)

	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// Using %+v will print the whole verifier error, not just the last
			// few lines.
			plog.Infof("Verifier error: %+v", ve)
		}
		return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	if err != nil {
		return nil, err
	}
	// read packets from igress+egress perf array
	packets, err := perf.NewReader(objects.PacketRecord, os.Getpagesize())
	if err != nil {
		return nil, fmt.Errorf("accessing to perf: %w", err)
	}

	return &PacketFetcher{
		objects:        &objects,
		perfReader:     packets,
		egressFilters:  map[ifaces.Interface]*netlink.BpfFilter{},
		ingressFilters: map[ifaces.Interface]*netlink.BpfFilter{},
		qdiscs:         map[ifaces.Interface]*netlink.GenericQdisc{},
		cacheMaxSize:   cacheMaxSize,
		enableIngress:  ingress,
		enableEgress:   egress,
	}, nil
}

func (p *PacketFetcher) Register(iface ifaces.Interface) error {

	qdisc, ipvlan, err := registerInterface(iface)
	if err != nil {
		return err
	}
	p.qdiscs[iface] = qdisc

	if err := p.registerEgress(iface, ipvlan); err != nil {
		return err
	}
	return p.registerIngress(iface, ipvlan)
}

func (p *PacketFetcher) registerIngress(iface ifaces.Interface, ipvlan netlink.Link) error {
	ingressFilter, err := fetchIngressEvents(iface, ipvlan, p.objects.IngressPcaParse, "ingress_pca_parse")
	if err != nil {
		return err
	}

	p.ingressFilters[iface] = ingressFilter
	return nil
}

// Close the eBPF fetcher from the system.
// We don't need an "Close(iface)" method because the filters and qdiscs
// are automatically removed when the interface is down
func (p *PacketFetcher) Close() error {
	log.Debug("unregistering eBPF objects")

	var errs []error
	if p.perfReader != nil {
		if err := p.perfReader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if p.objects != nil {
		if err := p.objects.EgressPcaParse.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := p.objects.IngressPcaParse.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := p.objects.PacketRecord.Close(); err != nil {
			errs = append(errs, err)
		}
		p.objects = nil
	}
	for iface, ef := range p.egressFilters {
		log.WithField("interface", iface).Debug("deleting egress filter")
		if err := netlink.FilterDel(ef); err != nil {
			errs = append(errs, fmt.Errorf("deleting egress filter: %w", err))
		}
	}
	p.egressFilters = map[ifaces.Interface]*netlink.BpfFilter{}
	for iface, igf := range p.ingressFilters {
		log.WithField("interface", iface).Debug("deleting ingress filter")
		if err := netlink.FilterDel(igf); err != nil {
			errs = append(errs, fmt.Errorf("deleting ingress filter: %w", err))
		}
	}
	p.ingressFilters = map[ifaces.Interface]*netlink.BpfFilter{}
	for iface, qd := range p.qdiscs {
		log.WithField("interface", iface).Debug("deleting Qdisc")
		if err := netlink.QdiscDel(qd); err != nil {
			errs = append(errs, fmt.Errorf("deleting qdisc: %w", err))
		}
	}
	p.qdiscs = map[ifaces.Interface]*netlink.GenericQdisc{}
	if len(errs) == 0 {
		return nil
	}

	var errStrings []string
	for _, err := range errs {
		errStrings = append(errStrings, err.Error())
	}
	return errors.New(`errors: "` + strings.Join(errStrings, `", "`) + `"`)
}

func (p *PacketFetcher) ReadPerf() (perf.Record, error) {
	return p.perfReader.Read()
}

func (p *PacketFetcher) LookupAndDeleteMap() map[int][]*byte {
	packetMap := p.objects.PacketRecord
	iterator := packetMap.Iterate()
	packets := make(map[int][]*byte, p.cacheMaxSize)

	var id int
	var metrics []*byte
	for iterator.Next(&id, &metrics) {
		if err := packetMap.Delete(id); err != nil {
			log.WithError(err).WithField("flowId", id).
				Warnf("couldn't delete  entry")
		}
		packets[id] = append(packets[id], metrics...)
	}
	return packets
}
