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
type rawRecord struct {
	key
	Bytes HumanBytes
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
	return &Record{rawRecord: fr}, err
}
