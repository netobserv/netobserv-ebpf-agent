// Package netattach provides TC/qdisc helpers shared by flow and packet fetchers.
package netattach

import (
	"errors"
	"fmt"
	"io/fs"
	"runtime"
	"strings"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
)

const (
	QdiscType                   = "clsact"
	NetworkEventsMonitoringHook = "psample_sample_packet"
	DNSDefaultPort              = 53
	DefaultNetworkEventsGroupID = 10
)

const (
	TCXAnchorNone = "none"
	TCXAnchorHead = "head"
	TCXAnchorTail = "tail"
)

// VariableMapping maps a BPF collection variable name to its value.
type VariableMapping struct {
	Key   string
	Value interface{}
}

// SetVariable sets a BPF collection variable.
func SetVariable(spec *cilium.CollectionSpec, key string, value interface{}) error {
	if err := spec.Variables[key].Set(value); err != nil {
		return fmt.Errorf("setting %s: %w", key, err)
	}
	return nil
}

// TCXAnchor returns the TCX attach anchor for the given configuration value.
func TCXAnchor(anchor string) link.Anchor {
	switch anchor {
	case TCXAnchorHead:
		return link.Head()
	case TCXAnchorTail:
		return link.Tail()
	case TCXAnchorNone:
		return nil
	default:
		return nil
	}
}

// WithNetNS runs fn in the target network namespace.
func WithNetNS(targetNS netns.NsHandle, fn func() error) error {
	if targetNS == netns.None() {
		return fn()
	}
	originalNS, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get current netns: %w", err)
	}
	defer func() {
		_ = netns.Set(originalNS)
		originalNS.Close()
	}()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Setns(int(targetNS), unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("failed to setns to %s: %w", targetNS, err)
	}
	return fn()
}

// RemoveTCFilters removes all TC filters on the given interface direction.
func RemoveTCFilters(ifName string, tcDir uint32) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

	filters, err := netlink.FilterList(link, tcDir)
	if err != nil {
		return err
	}
	var errs []error
	for _, f := range filters {
		if err := netlink.FilterDel(f); err != nil {
			errs = append(errs, err)
		}
	}

	return kerrors.NewAggregate(errs)
}

// Unregister removes stale TC filters for the given interface and program names.
func Unregister(iface *ifaces.Interface, ingressProgName, egressProgName string, log *logrus.Entry) error {
	ilog := log.WithField("iface", iface)
	ilog.Debugf("looking for previously installed TC filters on %s", iface.Name)
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("retrieving all netlink devices: %w", err)
	}

	egressDevs := []netlink.Link{}
	ingressDevs := []netlink.Link{}
	for _, l := range links {
		if l.Attrs().Name != iface.Name {
			continue
		}
		ingressFilters, err := netlink.FilterList(l, netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			return fmt.Errorf("listing ingress filters: %w", err)
		}
		for _, filter := range ingressFilters {
			if bpfFilter, ok := filter.(*netlink.BpfFilter); ok {
				if strings.HasPrefix(bpfFilter.Name, ingressProgName) {
					ingressDevs = append(ingressDevs, l)
				}
			}
		}

		egressFilters, err := netlink.FilterList(l, netlink.HANDLE_MIN_EGRESS)
		if err != nil {
			return fmt.Errorf("listing egress filters: %w", err)
		}
		for _, filter := range egressFilters {
			if bpfFilter, ok := filter.(*netlink.BpfFilter); ok {
				if strings.HasPrefix(bpfFilter.Name, egressProgName) {
					egressDevs = append(egressDevs, l)
				}
			}
		}
	}

	for _, dev := range ingressDevs {
		ilog.Debugf("removing ingress stale tc filters from %s", dev.Attrs().Name)
		err = RemoveTCFilters(dev.Attrs().Name, netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			ilog.WithError(err).Errorf("couldn't remove ingress tc filters from %s", dev.Attrs().Name)
		}
	}

	for _, dev := range egressDevs {
		ilog.Debugf("removing egress stale tc filters from %s", dev.Attrs().Name)
		err = RemoveTCFilters(dev.Attrs().Name, netlink.HANDLE_MIN_EGRESS)
		if err != nil {
			ilog.WithError(err).Errorf("couldn't remove egress tc filters from %s", dev.Attrs().Name)
		}
	}

	return nil
}

// DoIgnoreNoDev runs a syscall and ignores ENODEV errors.
func DoIgnoreNoDev[T any](sysCall func(T) error, dev T, log *logrus.Entry) error {
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

// RegisterInterface creates a clsact qdisc on the interface.
func RegisterInterface(iface *ifaces.Interface, log *logrus.Entry) (*netlink.GenericQdisc, netlink.Link, error) {
	ilog := log.WithField("iface", iface)
	handle, err := netlink.NewHandleAt(iface.NetNS)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create handle for netns (%s): %w", iface.NetNS.String(), err)
	}
	defer handle.Close()

	ipvlan, err := handle.LinkByIndex(iface.Index)
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
		QdiscType:  QdiscType,
	}
	if err := handle.QdiscDel(qdisc); err == nil {
		ilog.Warn("qdisc clsact already existed. Deleted it")
	}
	if err := handle.QdiscAdd(qdisc); err != nil {
		if errors.Is(err, fs.ErrExist) {
			ilog.WithError(err).Warn("qdisc clsact already exists. Ignoring")
		} else {
			return nil, nil, fmt.Errorf("failed to create clsact qdisc on %d (%s): %w", iface.Index, iface.Name, err)
		}
	}
	return qdisc, ipvlan, nil
}

// FetchEgressEvents attaches a TC egress BPF filter.
func FetchEgressEvents(iface *ifaces.Interface, ipvlan netlink.Link, parser *cilium.Program, name string, log *logrus.Entry) (*netlink.BpfFilter, error) {
	ilog := log.WithField("iface", iface)
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

// FetchIngressEvents attaches a TC ingress BPF filter.
func FetchIngressEvents(iface *ifaces.Interface, ipvlan netlink.Link, parser *cilium.Program, name string, log *logrus.Entry) (*netlink.BpfFilter, error) {
	ilog := log.WithField("iface", iface)
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
		ilog.Warn("ingress filter already existed. Deleted it")
	}
	if err := netlink.FilterAdd(ingressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			ilog.WithError(err).Warn("ingress filter already exists. Ignoring")
		} else {
			return nil, fmt.Errorf("failed to create ingress filter: %w", err)
		}
	}
	return ingressFilter, nil
}
