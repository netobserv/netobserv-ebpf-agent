package attach

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"

	cilium "github.com/cilium/ebpf"
	ebpfflows "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/packets"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var filterLog = logrus.WithField("component", "tracer.attach.Filter")

// FilterConfig describes a TC filter rule shared by flow and packet modes.
type FilterConfig struct {
	Direction       string
	IPCIDR          string
	Protocol        string
	SourcePort      intstr.IntOrString
	DestinationPort intstr.IntOrString
	Port            intstr.IntOrString
	IcmpType        int
	IcmpCode        int
	PeerIP          string
	PeerCIDR        string
	Action          string
	TCPFlags        string
	Drops           bool
	Sample          uint32
}

// Filter programs BPF filter maps from configuration.
type Filter struct {
	config []*FilterConfig
}

// NewFilter builds a filter from configuration rules.
func NewFilter(cfg []*FilterConfig) *Filter {
	return &Filter{config: cfg}
}

// ProgramFilter programs filter maps on the flow BPF object.
func (f *Filter) ProgramFilter(objects *ebpfflows.BpfObjects) error {
	for _, config := range f.config {
		filterLog.Infof("Filter config: %v", f.config)
		key, err := f.getFilterKey(config)
		if err != nil {
			return fmt.Errorf("failed to get filter key: %w", err)
		}

		val, err := f.getFilterValue(config)
		if err != nil {
			return fmt.Errorf("failed to get filter value: %w", err)
		}

		if val.DoPeerCIDR_lookup == 1 {
			peerVal := uint8(1)
			peerKey, err := f.getPeerFilterKey(config)
			if err != nil {
				return fmt.Errorf("failed to get peer filter key: %w", err)
			}
			err = objects.PeerFilterMap.Update(peerKey, peerVal, cilium.UpdateAny)
			if err != nil {
				return fmt.Errorf("failed to update peer filter map: %w", err)
			}
			filterLog.Infof("Programmed filter with PeerCIDR: %v", peerKey)
		}
		err = objects.FilterMap.Update(key, val, cilium.UpdateAny)
		if err != nil {
			return fmt.Errorf("failed to update filter map: %w", err)
		}

		filterLog.Infof("Programmed filter with key: %v, value: %v", key, val)
	}
	return nil
}

// ProgramPacketsFilter programs filter maps on the packet BPF object.
func (f *Filter) ProgramPacketsFilter(objects *packets.PacketsObjects) error {
	for _, config := range f.config {
		filterLog.Infof("Filter config: %v", f.config)
		key, err := f.getFilterKey(config)
		if err != nil {
			return fmt.Errorf("failed to get filter key: %w", err)
		}
		val, err := f.getFilterValue(config)
		if err != nil {
			return fmt.Errorf("failed to get filter value: %w", err)
		}
		pkKey := bpfKeyToPacketsKey(key)
		pkVal := bpfValToPacketsVal(val)
		if val.DoPeerCIDR_lookup == 1 {
			peerVal := uint8(1)
			peerKey, err := f.getPeerFilterKey(config)
			if err != nil {
				return fmt.Errorf("failed to get peer filter key: %w", err)
			}
			pkPeerKey := bpfKeyToPacketsKey(peerKey)
			if err := objects.PeerFilterMap.Update(pkPeerKey, peerVal, cilium.UpdateAny); err != nil {
				return fmt.Errorf("failed to update peer filter map: %w", err)
			}
		}
		if err := objects.FilterMap.Update(pkKey, pkVal, cilium.UpdateAny); err != nil {
			return fmt.Errorf("failed to update filter map: %w", err)
		}
	}
	return nil
}

func bpfKeyToPacketsKey(k ebpfflows.BpfFilterKeyT) packets.PacketsFilterKeyT {
	return packets.PacketsFilterKeyT{PrefixLen: k.PrefixLen, IpData: k.IpData}
}

func bpfValToPacketsVal(v ebpfflows.BpfFilterValueT) packets.PacketsFilterValueT {
	return packets.PacketsFilterValueT{
		Protocol:          v.Protocol,
		DstPortStart:      v.DstPortStart,
		DstPortEnd:        v.DstPortEnd,
		DstPort1:          v.DstPort1,
		DstPort2:          v.DstPort2,
		SrcPortStart:      v.SrcPortStart,
		SrcPortEnd:        v.SrcPortEnd,
		SrcPort1:          v.SrcPort1,
		SrcPort2:          v.SrcPort2,
		PortStart:         v.PortStart,
		PortEnd:           v.PortEnd,
		Port1:             v.Port1,
		Port2:             v.Port2,
		IcmpType:          v.IcmpType,
		IcmpCode:          v.IcmpCode,
		Direction:         uint32(v.Direction),
		Action:            uint32(v.Action),
		TcpFlags:          uint32(v.TcpFlags),
		FilterDrops:       v.FilterDrops,
		Sample:            v.Sample,
		DoPeerCIDR_lookup: v.DoPeerCIDR_lookup,
	}
}

func (f *Filter) buildFilterKey(cidr, ipStr string) (ebpfflows.BpfFilterKeyT, error) {
	key := ebpfflows.BpfFilterKeyT{}
	if cidr != "" {
		ip, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return key, fmt.Errorf("failed to parse CIDR: %w", err)
		}
		if ip.To4() != nil {
			copy(key.IpData[:], ip.To4())
		} else {
			copy(key.IpData[:], ip.To16())
		}
		pfLen, _ := ipNet.Mask.Size()
		key.PrefixLen = uint32(pfLen)
	} else if ipStr != "" {
		ip := net.ParseIP(ipStr)
		if ip.To4() != nil {
			copy(key.IpData[:], ip.To4())
			key.PrefixLen = 32
		} else {
			copy(key.IpData[:], ip.To16())
			key.PrefixLen = 128
		}
	}
	return key, nil
}

func (f *Filter) getFilterKey(config *FilterConfig) (ebpfflows.BpfFilterKeyT, error) {
	if config.IPCIDR == "" {
		config.IPCIDR = "0.0.0.0/0"
	}
	return f.buildFilterKey(config.IPCIDR, "")
}

func (f *Filter) getPeerFilterKey(config *FilterConfig) (ebpfflows.BpfFilterKeyT, error) {
	return f.buildFilterKey(config.PeerCIDR, config.PeerIP)
}

// nolint:cyclop
func (f *Filter) getFilterValue(config *FilterConfig) (ebpfflows.BpfFilterValueT, error) {
	val := ebpfflows.BpfFilterValueT{}

	switch config.Direction {
	case "Ingress":
		val.Direction = ebpfflows.BpfDirectionTINGRESS
	case "Egress":
		val.Direction = ebpfflows.BpfDirectionTEGRESS
	default:
		val.Direction = ebpfflows.BpfDirectionTMAX_DIRECTION
	}

	switch config.Action {
	case "Reject":
		val.Action = ebpfflows.BpfFilterActionTREJECT
	case "Accept":
		val.Action = ebpfflows.BpfFilterActionTACCEPT
	default:
		val.Action = ebpfflows.BpfFilterActionTMAX_FILTER_ACTIONS
	}

	switch config.Protocol {
	case "TCP":
		val.Protocol = syscall.IPPROTO_TCP
	case "UDP":
		val.Protocol = syscall.IPPROTO_UDP
	case "SCTP":
		val.Protocol = syscall.IPPROTO_SCTP
	case "ICMP":
		val.Protocol = syscall.IPPROTO_ICMP
	case "ICMPv6":
		val.Protocol = syscall.IPPROTO_ICMPV6
	}

	val.DstPortStart, val.DstPortEnd = getDstPortsRange(config)
	val.DstPort1, val.DstPort2 = getDstPorts(config)
	val.SrcPortStart, val.SrcPortEnd = getSrcPortsRange(config)
	val.SrcPort1, val.SrcPort2 = getSrcPorts(config)
	val.PortStart, val.PortEnd = getPortsRange(config)
	val.Port1, val.Port2 = getPorts(config)
	val.IcmpType = uint8(config.IcmpType)
	val.IcmpCode = uint8(config.IcmpCode)

	switch config.TCPFlags {
	case "SYN":
		val.TcpFlags = ebpfflows.BpfTcpFlagsTSYN_FLAG
	case "SYN-ACK":
		val.TcpFlags = ebpfflows.BpfTcpFlagsTSYN_ACK_FLAG
	case "ACK":
		val.TcpFlags = ebpfflows.BpfTcpFlagsTACK_FLAG
	case "FIN":
		val.TcpFlags = ebpfflows.BpfTcpFlagsTFIN_FLAG
	case "RST":
		val.TcpFlags = ebpfflows.BpfTcpFlagsTRST_FLAG
	case "PUSH":
		val.TcpFlags = ebpfflows.BpfTcpFlagsTPSH_FLAG
	case "URG":
		val.TcpFlags = ebpfflows.BpfTcpFlagsTURG_FLAG
	case "ECE":
		val.TcpFlags = ebpfflows.BpfTcpFlagsTECE_FLAG
	case "CWR":
		val.TcpFlags = ebpfflows.BpfTcpFlagsTCWR_FLAG
	case "FIN-ACK":
		val.TcpFlags = ebpfflows.BpfTcpFlagsTFIN_ACK_FLAG
	case "RST-ACK":
		val.TcpFlags = ebpfflows.BpfTcpFlagsTRST_ACK_FLAG
	}

	if config.Drops {
		val.FilterDrops = 1
	}

	if config.Sample != 0 {
		val.Sample = config.Sample
	}
	if config.PeerCIDR != "" || config.PeerIP != "" {
		val.DoPeerCIDR_lookup = 1
	}
	return val, nil
}

func getSrcPortsRange(config *FilterConfig) (uint16, uint16) {
	if config.SourcePort.Type == intstr.Int {
		return uint16(config.SourcePort.IntVal), 0
	}
	start, end, err := getPortsFromString(config.SourcePort.String(), "-")
	if err != nil {
		return 0, 0
	}
	return start, end
}

func getSrcPorts(config *FilterConfig) (uint16, uint16) {
	port1, port2, err := getPortsFromString(config.SourcePort.String(), ",")
	if err != nil {
		return 0, 0
	}
	return port1, port2
}

func getDstPortsRange(config *FilterConfig) (uint16, uint16) {
	if config.DestinationPort.Type == intstr.Int {
		return uint16(config.DestinationPort.IntVal), 0
	}
	start, end, err := getPortsFromString(config.DestinationPort.String(), "-")
	if err != nil {
		return 0, 0
	}
	return start, end
}

func getDstPorts(config *FilterConfig) (uint16, uint16) {
	port1, port2, err := getPortsFromString(config.DestinationPort.String(), ",")
	if err != nil {
		return 0, 0
	}
	return port1, port2
}

func getPortsRange(config *FilterConfig) (uint16, uint16) {
	if config.Port.Type == intstr.Int {
		return uint16(config.Port.IntVal), 0
	}
	start, end, err := getPortsFromString(config.Port.String(), "-")
	if err != nil {
		return 0, 0
	}
	return start, end
}

func getPorts(config *FilterConfig) (uint16, uint16) {
	port1, port2, err := getPortsFromString(config.Port.String(), ",")
	if err != nil {
		return 0, 0
	}
	return port1, port2
}

func getPortsFromString(s, sep string) (uint16, uint16, error) {
	ps := strings.SplitN(s, sep, 2)
	if len(ps) != 2 {
		return 0, 0, fmt.Errorf("invalid ports range. Expected two integers separated by %s but found %s", sep, s)
	}
	startPort, err := strconv.ParseUint(ps[0], 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start port number %w", err)
	}
	endPort, err := strconv.ParseUint(ps[1], 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end port number %w", err)
	}
	if sep == "-" && startPort > endPort {
		return 0, 0, fmt.Errorf("invalid port range. Start port is greater than end port")
	}
	if startPort == endPort {
		return 0, 0, fmt.Errorf("invalid port range. Start and end port are equal. Remove the %s and enter a single port", sep)
	}
	if startPort == 0 {
		return 0, 0, fmt.Errorf("invalid start port 0")
	}
	return uint16(startPort), uint16(endPort), nil
}

// ConvertFilterPortsToInstr converts JSON filter port fields to intstr.IntOrString.
func ConvertFilterPortsToInstr(intPort int32, rangePorts, ports string) intstr.IntOrString {
	if rangePorts != "" {
		return intstr.FromString(rangePorts)
	}
	if ports != "" {
		return intstr.FromString(ports)
	}
	return intstr.FromInt32(intPort)
}

// HasSampling reports whether any rule sets a per-flow sample rate.
func (f *Filter) HasSampling() uint8 {
	for _, r := range f.config {
		if r.Sample > 0 {
			return 1
		}
	}
	return 0
}
