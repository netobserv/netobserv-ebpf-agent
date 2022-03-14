package flow

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

type Protocol uint8
type RawIP uint32
type HumanBytes uint64

// what identifies a flow
type key struct {
	SrcIP    RawIP
	SrcPort  uint16
	DstIP    RawIP
	DstPort  uint16
	Protocol Protocol
	// TODO: add service field
}

// record structure as parsed from eBPF
type rawRecord struct {
	key
	Bytes HumanBytes
}

// Record contains accumulated metrics from a flow
type Record struct {
	rawRecord
	Packets int
}

func (r *Record) Accumulate(src *Record) {
	r.Bytes += src.Bytes
	r.Packets += src.Packets
}

func (proto Protocol) String() string {
	switch proto {
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

func (r RawIP) String() string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, uint32(r))
	return ip.String()
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

// ReadFrom reads a Record from a binary source, in LittleEndian order
func ReadFrom(reader io.Reader) (*Record, error) {
	var fr rawRecord
	err := binary.Read(reader, binary.LittleEndian, &fr)
	return &Record{rawRecord: fr, Packets: 1}, err
}
