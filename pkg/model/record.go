package model

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/utils"

	ovnobserv "github.com/ovn-org/ovn-kubernetes/go-controller/observability-lib/sampledecoder"
	"github.com/sirupsen/logrus"
)

// Values according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
const (
	DirectionIngress = 0
	DirectionEgress  = 1
	MacLen           = 6
	// IPv4Type / IPv6Type value as defined in IEEE 802: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
	IPv6Type                 = 0x86DD
	NetworkEventsMaxEventsMD = 8
	MaxNetworkEvents         = 4
	MaxObservedInterfaces    = 6
)

var recordLog = logrus.WithField("component", "model")

type HumanBytes uint64
type MacAddr [MacLen]uint8
type Direction uint8

// IPAddr encodes v4 and v6 IPs with a fixed length.
// IPv4 addresses are encoded as IPv6 addresses with prefix ::ffff/96
// as described in https://datatracker.ietf.org/doc/html/rfc4038#section-4.2
// (same behavior as Go's net.IP type)
type IPAddr [net.IPv6len]uint8

type InterfaceNamer func(ifIndex int, mac MacAddr) string

var (
	agentIP        net.IP
	interfaceNamer InterfaceNamer = func(ifIndex int, _ MacAddr) string { return fmt.Sprintf("[namer unset] %d", ifIndex) }
)

func SetGlobalIP(ip net.IP) {
	agentIP = ip
}

func SetInterfaceNamer(ifaceNamer InterfaceNamer) {
	interfaceNamer = ifaceNamer
}

// record structure as parsed from eBPF
type RawRecord ebpf.BpfFlowRecordT

// Record contains accumulated metrics from a flow
type Record struct {
	ID      ebpf.BpfFlowId
	Metrics BpfFlowContent

	// TODO: redundant field from RecordMetrics. Reorganize structs
	TimeFlowStart time.Time
	TimeFlowEnd   time.Time
	DNSLatency    time.Duration
	Interfaces    []IntfDirUdn
	// AgentIP provides information about the source of the flow (the Agent that traced it)
	AgentIP net.IP
	// Calculated RTT which is set when record is created by calling NewRecord
	TimeFlowRtt            time.Duration
	NetworkMonitorEventsMD []map[string]string
}

func NewRecord(
	key ebpf.BpfFlowId,
	metrics *BpfFlowContent,
	currentTime time.Time,
	monotonicCurrentTime uint64,
	s *ovnobserv.SampleDecoder,
	udnsCache map[string]string,
) *Record {
	startDelta := time.Duration(monotonicCurrentTime - metrics.StartMonoTimeTs)
	endDelta := time.Duration(monotonicCurrentTime - metrics.EndMonoTimeTs)

	var record = Record{
		ID:            key,
		Metrics:       *metrics,
		TimeFlowStart: currentTime.Add(-startDelta),
		TimeFlowEnd:   currentTime.Add(-endDelta),
		AgentIP:       agentIP,
	}
	lMAC := metrics.SrcMac
	if metrics.DirectionFirstSeen == 0 {
		lMAC = metrics.DstMac
	}
	record.Interfaces = []IntfDirUdn{NewIntfDirUdn(interfaceNamer(int(metrics.IfIndexFirstSeen), lMAC),
		int(metrics.DirectionFirstSeen),
		udnsCache)}

	for i := uint8(0); i < record.Metrics.NbObservedIntf; i++ {
		record.Interfaces = append(record.Interfaces, NewIntfDirUdn(
			interfaceNamer(int(metrics.ObservedIntf[i]), lMAC),
			int(metrics.ObservedDirection[i]),
			udnsCache,
		))
	}

	if metrics.AdditionalMetrics != nil {
		if metrics.AdditionalMetrics.FlowRtt != 0 {
			record.TimeFlowRtt = time.Duration(metrics.AdditionalMetrics.FlowRtt)
		}
		if metrics.AdditionalMetrics.DnsRecord.Latency != 0 {
			record.DNSLatency = time.Duration(metrics.AdditionalMetrics.DnsRecord.Latency)
		}
	}
	if s != nil && metrics.AdditionalMetrics != nil {
		seen := make(map[string]bool)
		record.NetworkMonitorEventsMD = make([]map[string]string, 0)
		for _, metadata := range metrics.AdditionalMetrics.NetworkEvents {
			if !AllZerosMetaData(metadata) {
				if md, err := s.DecodeCookie8Bytes(metadata); err == nil {
					mdStr := md.String()
					if !seen[mdStr] {
						asMap := utils.NetworkEventToMap(md)
						record.NetworkMonitorEventsMD = append(record.NetworkMonitorEventsMD, asMap)
						seen[mdStr] = true
					}
				}
			}
		}
	}
	return &record
}

type IntfDirUdn struct {
	Interface string
	Direction int
	Udn       string
}

func NewIntfDirUdn(intf string, dir int, cache map[string]string) IntfDirUdn {
	udn := ""
	if len(cache) == 0 {
		return IntfDirUdn{Interface: intf, Direction: dir, Udn: udn}
	}

	// Look up the interface in the cache
	if v, ok := cache[intf]; ok {
		if v != "" {
			udn = v
		} else {
			udn = "default"
		}
	}
	recordLog.Debugf("intf %s dir %d udn %s", intf, dir, udn)
	return IntfDirUdn{Interface: intf, Direction: dir, Udn: udn}
}

func networkEventsMDExist(events [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8, md [NetworkEventsMaxEventsMD]uint8) bool {
	for _, e := range events {
		if reflect.DeepEqual(e, md) {
			return true
		}
	}
	return false
}

// IP returns the net.IP equivalent object
func IP(ia IPAddr) net.IP {
	return ia[:]
}

// IntEncodeV4 encodes an IPv4 address as an integer (in network encoding, big endian).
// It assumes that the passed IP is already IPv4. Otherwise, it would just encode the
// last 4 bytes of an IPv6 address
func IntEncodeV4(ia [net.IPv6len]uint8) uint32 {
	return binary.BigEndian.Uint32(ia[net.IPv6len-net.IPv4len : net.IPv6len])
}

// IPAddrFromNetIP returns IPAddr from net.IP
func IPAddrFromNetIP(netIP net.IP) IPAddr {
	var arr [net.IPv6len]uint8
	copy(arr[:], (netIP)[0:net.IPv6len])
	return arr
}

func (ia *IPAddr) MarshalJSON() ([]byte, error) {
	return []byte(`"` + IP(*ia).String() + `"`), nil
}

func (m *MacAddr) String() string {
	t := net.HardwareAddr(m[:])
	return t.String()
}

func (m *MacAddr) MarshalJSON() ([]byte, error) {
	return []byte("\"" + m.String() + "\""), nil
}

// ReadFrom reads a Record from a binary source, in LittleEndian order
func ReadFrom(reader io.Reader) (*RawRecord, error) {
	var fr RawRecord
	err := binary.Read(reader, binary.LittleEndian, &fr)
	return &fr, err
}

func AllZerosMetaData(s [NetworkEventsMaxEventsMD]uint8) bool {
	for _, v := range s {
		if v != 0 {
			return false
		}
	}
	return true
}

func AllZeroIP(ip net.IP) bool {
	if ip.Equal(net.IPv4zero) || ip.Equal(net.IPv6zero) {
		return true
	}
	return false
}
