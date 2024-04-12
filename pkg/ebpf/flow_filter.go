package ebpf

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type FlowFilterConfig struct {
	FlowFilterDirection       string
	FlowFilterIPCIDR          string
	FlowFilterProtocol        string
	FlowFilterSourcePort      intstr.IntOrString
	FlowFilterDestinationPort intstr.IntOrString
	FlowFilterPort            intstr.IntOrString
	FlowFilterIcmpType        int
	FlowFilterIcmpCode        int
	FlowFilterPeerIP          string
	FlowFilterAction          string
}

type FlowFilter struct {
	// eBPF objs to create/update eBPF maps
	objects *BpfObjects
	config  *FlowFilterConfig
}

func NewFlowFilter(objects *BpfObjects, cfg *FlowFilterConfig) *FlowFilter {
	return &FlowFilter{
		objects: objects,
		config:  cfg,
	}
}

func (f *FlowFilter) ProgramFlowFilter() error {
	log.Infof("Flow filter config: %v", f.config)
	key, err := f.getFlowFilterKey(f.config)
	if err != nil {
		return fmt.Errorf("failed to get flow filter key: %w", err)
	}

	val, err := f.getFlowFilterValue(f.config)
	if err != nil {
		return fmt.Errorf("failed to get flow filter value: %w", err)
	}

	err = f.objects.FilterMap.Update(key, val, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed to update flow filter map: %w", err)
	}

	log.Infof("Programmed flow filter with key: %v, value: %v", key, val)

	return nil
}

func (f *FlowFilter) getFlowFilterKey(config *FlowFilterConfig) (BpfFilterKeyT, error) {
	key := BpfFilterKeyT{}

	ip, ipNet, err := net.ParseCIDR(config.FlowFilterIPCIDR)
	if err != nil {
		return key, fmt.Errorf("failed to parse FlowFilterIPCIDR: %w", err)
	}
	if ip.To4() != nil {
		copy(key.IpData[:], ip.To4())
	} else {
		copy(key.IpData[:], ip.To16())
	}
	pfLen, _ := ipNet.Mask.Size()
	key.PrefixLen = uint32(pfLen)

	return key, nil
}

func (f *FlowFilter) getFlowFilterValue(config *FlowFilterConfig) (BpfFilterValueT, error) {
	val := BpfFilterValueT{}

	switch config.FlowFilterDirection {
	case "Ingress":
		val.Direction = BpfDirectionTINGRESS
	case "Egress":
		val.Direction = BpfDirectionTEGRESS
	default:
		val.Direction = BpfDirectionTMAX_DIRECTION
	}

	switch config.FlowFilterAction {
	case "Reject":
		val.Action = BpfFilterActionTREJECT
	case "Accept":
		val.Action = BpfFilterActionTACCEPT
	default:
		val.Action = BpfFilterActionTMAX_FILTER_ACTIONS
	}

	switch config.FlowFilterProtocol {
	case "TCP":
		val.Protocol = syscall.IPPROTO_TCP
		val.DstPortStart, val.DstPortEnd = getDstPorts(config)
		val.SrcPortStart, val.SrcPortEnd = getSrcPorts(config)
		val.PortStart, val.PortEnd = getPorts(config)
	case "UDP":
		val.Protocol = syscall.IPPROTO_UDP
		val.DstPortStart, val.DstPortEnd = getDstPorts(config)
		val.SrcPortStart, val.SrcPortEnd = getSrcPorts(config)
		val.PortStart, val.PortEnd = getPorts(config)
	case "SCTP":
		val.Protocol = syscall.IPPROTO_SCTP
		val.DstPortStart, val.DstPortEnd = getDstPorts(config)
		val.SrcPortStart, val.SrcPortEnd = getSrcPorts(config)
		val.PortStart, val.PortEnd = getPorts(config)
	case "ICMP":
		val.Protocol = syscall.IPPROTO_ICMP
		val.IcmpType = uint8(config.FlowFilterIcmpType)
		val.IcmpCode = uint8(config.FlowFilterIcmpCode)
	case "ICMPv6":
		val.Protocol = syscall.IPPROTO_ICMPV6
		val.IcmpType = uint8(config.FlowFilterIcmpType)
		val.IcmpCode = uint8(config.FlowFilterIcmpCode)
	}

	if config.FlowFilterPeerIP != "" {
		ip := net.ParseIP(config.FlowFilterPeerIP)
		if ip.To4() != nil {
			copy(val.Ip[:], ip.To4())
		} else {
			copy(val.Ip[:], ip.To16())
		}
	}
	return val, nil
}

func getSrcPorts(config *FlowFilterConfig) (uint16, uint16) {
	if config.FlowFilterSourcePort.Type == intstr.Int {
		return uint16(config.FlowFilterSourcePort.IntVal), 0
	}
	start, end, err := getPortsFromString(config.FlowFilterSourcePort.String())
	if err != nil {
		return 0, 0
	}
	return start, end
}

func getDstPorts(config *FlowFilterConfig) (uint16, uint16) {
	if config.FlowFilterDestinationPort.Type == intstr.Int {
		return uint16(config.FlowFilterDestinationPort.IntVal), 0
	}
	start, end, err := getPortsFromString(config.FlowFilterDestinationPort.String())
	if err != nil {
		return 0, 0
	}
	return start, end
}

func getPorts(config *FlowFilterConfig) (uint16, uint16) {
	if config.FlowFilterDestinationPort.Type == intstr.Int {
		return uint16(config.FlowFilterPort.IntVal), 0
	}
	start, end, err := getPortsFromString(config.FlowFilterPort.String())
	if err != nil {
		return 0, 0
	}
	return start, end
}

func getPortsFromString(s string) (uint16, uint16, error) {
	ps := strings.SplitN(s, "-", 2)
	if len(ps) != 2 {
		return 0, 0, fmt.Errorf("invalid ports range. Expected two integers separated by hyphen but found %s", s)
	}
	startPort, err := strconv.ParseUint(ps[0], 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start port number %w", err)
	}
	endPort, err := strconv.ParseUint(ps[1], 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end port number %w", err)
	}
	if startPort > endPort {
		return 0, 0, fmt.Errorf("invalid port range. Start port is greater than end port")
	}
	if startPort == endPort {
		return 0, 0, fmt.Errorf("invalid port range. Start and end port are equal. Remove the hyphen and enter a single port")
	}
	if startPort == 0 {
		return 0, 0, fmt.Errorf("invalid start port 0")
	}
	return uint16(startPort), uint16(endPort), nil
}

func ConvertFilterPortsToInstr(intPort int32, rangePorts string) intstr.IntOrString {
	if rangePorts == "" {
		return intstr.FromInt32(intPort)
	}
	return intstr.FromString(rangePorts)
}
