package flow

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const MacLen = 6
const IP6Len = 16
const IPv6Type = 0x86DD

// IPv6Type value as defined in IEEE 802: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml

type RawIP uint32
type HumanBytes uint64
type Timestamp uint64
type MacAddr [MacLen]uint8
type Direction uint8
type TransportProtocol uint8
type IP6Addr [IP6Len]uint8

type DataLink struct {
	SrcMac MacAddr
	DstMac MacAddr
}

type Network struct {
	SrcAddr RawIP
	DstAddr RawIP
}

type NetworkV6 struct {
	SrcAddr IP6Addr
	DstAddr IP6Addr
}

type Transport struct {
	SrcPort  uint16
	DstPort  uint16
	Protocol TransportProtocol `json:"Proto"`
}

// what identifies a flow
type key struct {
	Protocol  uint16 `json:"Etype"`
	Direction Direction
	DataLink  DataLink
	Network   Network
	NetworkV6 NetworkV6
	Transport Transport
	// TODO: add TOS field
}

// record structure as parsed from eBPF
// it's important to emphasize that the fields in this structure have to coincide,
// byte by byte, with the flow structure in the bpf/flow.h file
// TODO: generate flow.h file from this structure
/*

typedef struct flow_id_t {
	u16 eth_protocol;
	u8 src_mac[ETH_ALEN];
	u8 dst_mac[ETH_ALEN];
	u32 src_ip;
	u32 dst_ip;
	u16 src_port;
	u16 dst_port;
	u8 protocol;
} __attribute__((packed)) flow_id;

typedef struct flow_metrics_t {
	__u32 packets;
	__u64 bytes;
	__u64 flow_start_ts;
	__u64 last_pkt_ts;
	__u32 flags;  // Could be used to indicate certain things
} __attribute__((packed)) flow_metrics;

typedef struct flow_record_t {
	flow_id id;
	flow_metrics metrics;
} __attribute__((packed)) flow_record;
*/
type rawRecord struct {
	key
	Packets uint32
	Bytes HumanBytes
	FlowStartTime Timestamp
	FlowEndTime Timestamp
	Flags uint32
}

// Record contains accumulated metrics from a flow
type Record struct {
	rawRecord
	TimeFlowStart time.Time
	TimeFlowEnd   time.Time
	Interface     string
	Packets       int
}

func (r *Record) Accumulate(src *Record) {
	// assuming that the src record is later in time than the destination record
	r.TimeFlowEnd = src.TimeFlowStart
	r.Bytes += src.Bytes
	r.Packets += src.Packets
}

func (p TransportProtocol) String() string {
	switch p {
	case 0:
		return "IP"
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 4:
		return "IPIP"
	case 6:
		return "TCP"
	case 8:
		return "EGP"
	case 12:
		return "PUP"
	case 17:
		return "UDP"
	case 22:
		return "IDP"
	case 29:
		return "TP"
	case 33:
		return "DCCP"
	case 41:
		return "IPV6"
	case 46:
		return "RSVP"
	case 136:
		return "UDPLITE"
	default:
		return "other"
	}
}

func (p TransportProtocol) MarshalJSON() ([]byte, error) {
	return []byte("\"" + p.String() + "\""), nil
}

func (i RawIP) String() string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, uint32(i))
	return ip.String()
}

func (i RawIP) MarshalJSON() ([]byte, error) {
	return []byte("\"" + i.String() + "\""), nil
}

const (
	kibi = 1024
	mibi = kibi * 1024
	gibi = mibi * 1024
)

func (b HumanBytes) String() string {
	if b < kibi {
		return strconv.FormatUint(uint64(b), 10)
	}
	if b < mibi {
		return fmt.Sprintf("%.2f KiB", float64(b)/float64(kibi))
	}
	if b < gibi {
		return fmt.Sprintf("%.2f MiB", float64(b)/float64(mibi))
	}
	return fmt.Sprintf("%.2f MiB", float64(b)/float64(gibi))
}

func (m *MacAddr) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

func (m *MacAddr) MarshalJSON() ([]byte, error) {
	return []byte("\"" + m.String() + "\""), nil
}

func (d Direction) MarshalJSON() ([]byte, error) {
	switch d {
	case 0:
		return []byte(`"INGRESS"`), nil
	case 1:
		return []byte(`"EGRESS"`), nil
	default:
		return []byte(`"UNKNOWN"`), nil
	}
}



// ReadFrom reads a Record from a binary source, in LittleEndian order
func ReadFrom(reader io.Reader) (*Record, error) {
	var fr rawRecord
	err := binary.Read(reader, binary.LittleEndian, &fr)
	fmt.Printf("%+v\n", fr)
	return &Record{rawRecord: fr}, err
}
