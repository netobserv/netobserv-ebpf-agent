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

type FilterConfig struct {
	FilterDirection       string
	FilterIPCIDR          string
	FilterProtocol        string
	FilterSourcePort      intstr.IntOrString
	FilterDestinationPort intstr.IntOrString
	FilterPort            intstr.IntOrString
	FilterIcmpType        int
	FilterIcmpCode        int
	FilterPeerIP          string
	FilterAction          string
}

type Filter struct {
	// eBPF objs to create/update eBPF maps
	objects *BpfObjects
	config  *FilterConfig
}

func NewFilter(objects *BpfObjects, cfg *FilterConfig) *Filter {
	return &Filter{
		objects: objects,
		config:  cfg,
	}
}

func (f *Filter) ProgramFilter() error {
	log.Infof("Flow filter config: %v", f.config)
	key, err := f.getFilterKey(f.config)
	if err != nil {
		return fmt.Errorf("failed to get filter key: %w", err)
	}

	val, err := f.getFilterValue(f.config)
	if err != nil {
		return fmt.Errorf("failed to get filter value: %w", err)
	}

	err = f.objects.FilterMap.Update(key, val, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed to update filter map: %w", err)
	}

	log.Infof("Programmed filter with key: %v, value: %v", key, val)

	return nil
}

func (f *Filter) getFilterKey(config *FilterConfig) (BpfFilterKeyT, error) {
	key := BpfFilterKeyT{}

	ip, ipNet, err := net.ParseCIDR(config.FilterIPCIDR)
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

func (f *Filter) getFilterValue(config *FilterConfig) (BpfFilterValueT, error) {
	val := BpfFilterValueT{}

	switch config.FilterDirection {
	case "Ingress":
		val.Direction = BpfDirectionTINGRESS
	case "Egress":
		val.Direction = BpfDirectionTEGRESS
	default:
		val.Direction = BpfDirectionTMAX_DIRECTION
	}

	switch config.FilterAction {
	case "Reject":
		val.Action = BpfFilterActionTREJECT
	case "Accept":
		val.Action = BpfFilterActionTACCEPT
	default:
		val.Action = BpfFilterActionTMAX_FILTER_ACTIONS
	}

	switch config.FilterProtocol {
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
		val.IcmpType = uint8(config.FilterIcmpType)
		val.IcmpCode = uint8(config.FilterIcmpCode)
	case "ICMPv6":
		val.Protocol = syscall.IPPROTO_ICMPV6
		val.IcmpType = uint8(config.FilterIcmpType)
		val.IcmpCode = uint8(config.FilterIcmpCode)
	}

	if config.FilterPeerIP != "" {
		ip := net.ParseIP(config.FilterPeerIP)
		if ip.To4() != nil {
			copy(val.Ip[:], ip.To4())
		} else {
			copy(val.Ip[:], ip.To16())
		}
	}
	return val, nil
}

func getSrcPorts(config *FilterConfig) (uint16, uint16) {
	if config.FilterSourcePort.Type == intstr.Int {
		return uint16(config.FilterSourcePort.IntVal), 0
	}
	start, end, err := getPortsFromString(config.FilterSourcePort.String())
	if err != nil {
		return 0, 0
	}
	return start, end
}

func getDstPorts(config *FilterConfig) (uint16, uint16) {
	if config.FilterDestinationPort.Type == intstr.Int {
		return uint16(config.FilterDestinationPort.IntVal), 0
	}
	start, end, err := getPortsFromString(config.FilterDestinationPort.String())
	if err != nil {
		return 0, 0
	}
	return start, end
}

func getPorts(config *FilterConfig) (uint16, uint16) {
	if config.FilterDestinationPort.Type == intstr.Int {
		return uint16(config.FilterPort.IntVal), 0
	}
	start, end, err := getPortsFromString(config.FilterPort.String())
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
