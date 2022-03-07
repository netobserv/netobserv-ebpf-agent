package connect

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"strings"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../../bpf/flows.c -- -I../../bpf/headers

const (
	qdiscType       = "clsact"
	readStatsBuffer = 100
)

type Monitor struct {
	interfaceName string
	objects       bpfObjects
	qdisc         *netlink.GenericQdisc
	egressFilter  *netlink.BpfFilter
	ingressFilter *netlink.BpfFilter
	flows         *ringbuf.Reader
	stats         Registry
	readStats     chan RawStats
}

func NewMonitor(iface string) Monitor {
	return Monitor{
		interfaceName: iface,
		readStats:     make(chan RawStats, readStatsBuffer),
		stats:         Registry{elements: map[statsKey]*Stats{}},
	}
}

func (m *Monitor) Start() error {
	go m.stats.Accum(m.readStats)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing mem lock: %w", err)
	}
	// Load pre-compiled programs and maps into the kernel.
	if err := loadBpfObjects(&m.objects, nil); err != nil {
		return fmt.Errorf("loading objects: %w", err)
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
	if err := netlink.QdiscAdd(m.qdisc); err != nil {
		if errors.Is(err, fs.ErrExist) {
			log.Printf("qdisc clsact already exists. Ignoring")
		} else {
			m.qdisc = nil
			return fmt.Errorf("failed to create clsact qdisc on %q: %s %T", m.interfaceName, err, err)
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
		Fd:           m.objects.FlowParse.FD(),
		Name:         "tc/flow_parse",
		DirectAction: true,
	}
	if err = netlink.FilterAdd(m.egressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			log.Printf("egress filter already exists. Ignoring")
		} else {
			return fmt.Errorf("failed to create egress filter: %w", err)
		}
	}
	// Fetch events on ingress
	ingressAttrs := netlink.FilterAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  3,
		Priority:  1,
	}
	m.ingressFilter = &netlink.BpfFilter{
		FilterAttrs:  ingressAttrs,
		Fd:           m.objects.FlowParse.FD(),
		Name:         "tc/flow_parse",
		DirectAction: true,
	}
	if err = netlink.FilterAdd(m.ingressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			log.Printf("ingress filter already exists. Ignoring")
		} else {
			return fmt.Errorf("failed to create ingress filter: %w", err)
		}
	}

	// read events from igress+egress ringbuffer
	if m.flows, err = ringbuf.NewReader(m.objects.Flows); err != nil {
		return fmt.Errorf("accessing to ringbuffer: %w", err)
	}
	go func() {
		for {
			event, err := m.flows.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}
			// Parse the ringbuf event entry into an Event structure.
			rawSample, err := ReadRaw(bytes.NewBuffer(event.RawSample))
			if err != nil {
				log.Printf("reading ringbuf event: %s", err)
				continue
			}
			m.readStats <- rawSample
		}
	}()
	return nil
}

func (m *Monitor) Stats() []*Stats {
	return m.stats.List()
}

func (m *Monitor) Stop() error {
	var errs []error
	doClose := func(o io.Closer) {
		if o == nil {
			return
		}
		if err := o.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	close(m.readStats)
	doClose(m.flows)
	doClose(&m.objects)
	if m.qdisc != nil {
		if err := netlink.QdiscDel(m.qdisc); err != nil {
			errs = append(errs, err)
		}
	}
	if m.egressFilter != nil {
		if err := netlink.FilterDel(m.egressFilter); err != nil {
			errs = append(errs, err)
		}
	}
	if m.ingressFilter != nil {
		if err := netlink.FilterDel(m.ingressFilter); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	var errStrings []string
	for _, err := range errs {
		errStrings = append(errStrings, err.Error())
	}
	return errors.New("errors during close: " + strings.Join(errStrings, ", "))
}
