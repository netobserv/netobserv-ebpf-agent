package flow

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const MacLen = 6

var MAXNS int64 = 1000000000

// IPv6Type value as defined in IEEE 802: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
const IPv6Type = 0x86DD

type HumanBytes uint64
type Timestamp uint64
type MacAddr [MacLen]uint8
type Direction uint8

// IPAddr encodes v4 and v6 IPs with a fixed length.
// IPv4 addresses are encoded as IPv6 addresses with prefix ::ffff/96
// as described in https://datatracker.ietf.org/doc/html/rfc4038#section-4.2
// (same behavior as Go's net.IP type)
type IPAddr [net.IPv6len]uint8

type DataLink struct {
	SrcMac MacAddr
	DstMac MacAddr
}

type Network struct {
	SrcAddr IPAddr
	DstAddr IPAddr
}

type Transport struct {
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8 `json:"Proto"`
}

// what identifies a flow
type key struct {
	EthProtocol uint16 `json:"Etype"`
	Direction   uint8  `json:"FlowDirection"`
	DataLink
	Network
	Transport
}

// record structure as parsed from eBPF
// it's important to emphasize that the fields in this structure have to coincide,
// byte by byte, with the flow structure in the bpf/flow.h file

type rawRecord struct {
	key
	Pkts          uint32
	Bytes         uint64
	FlowStartTime Timestamp
	FlowEndTime   Timestamp
	Flags         uint32
}

// Record contains accumulated metrics from a flow
type Record struct {
	rawRecord
	TimeFlowStart time.Time
	TimeFlowEnd   time.Time
	Interface     string
	Packets       uint32
}

func (r *Record) Accumulate(src *Record) {
	// assuming that the src record is later in time than the destination record
	r.TimeFlowEnd = src.TimeFlowStart
	r.Bytes += src.Bytes
	r.Packets += src.Packets
}

// IP returns the net.IP equivalent object
func (ia *IPAddr) IP() net.IP {
	return ia[:]
}

// IntEncodeV4 encodes an IPv4 address as an integer (in network encoding, big endian).
// It assumes that the passed IP is already IPv4. Otherwise it would just encode the
// last 4 bytes of an IPv6 address
func (ia *IPAddr) IntEncodeV4() uint32 {
	return binary.BigEndian.Uint32(ia[net.IPv6len-net.IPv4len : net.IPv6len])
}

func (ia *IPAddr) MarshalJSON() ([]byte, error) {
	return []byte(`"` + ia.IP().String() + `"`), nil
}

func (m *MacAddr) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

func (m *MacAddr) MarshalJSON() ([]byte, error) {
	return []byte("\"" + m.String() + "\""), nil
}

// ReadFrom reads a Record from a binary source, in LittleEndian order
func ReadFrom(reader io.Reader) (*Record, error) {
	var fr rawRecord
	err := binary.Read(reader, binary.LittleEndian, &fr)
	return &Record{rawRecord: fr}, err
}
