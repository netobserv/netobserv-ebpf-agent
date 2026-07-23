package model

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/gavv/monotime"
)

const (
	PlaintextDirectionWrite = "write"
	PlaintextDirectionRead  = "read"
)

const (
	TLSSourceOpenSSL = "openssl"
	TLSSourceGoTLS   = "gotls"
	TLSSourceKTLS    = "ktls"
)

// PlaintextRecord holds TLS plaintext captured via uprobes or kTLS.
type PlaintextRecord struct {
	Timestamp time.Time
	Pid       uint32
	Tgid      uint32
	Data      []byte
	Direction string
	TLSSource string
	SSLType   uint8
	SrcAddr   string
	DstAddr   string
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	SocketFd  int32
	ConnPtr   uint64
}

func tlsSourceName(source uint8) string {
	switch source {
	case 0:
		return TLSSourceOpenSSL
	case 1:
		return TLSSourceGoTLS
	case 2:
		return TLSSourceKTLS
	default:
		return "unknown"
	}
}

func directionName(dir uint8) string {
	if dir == 1 {
		return PlaintextDirectionRead
	}
	return PlaintextDirectionWrite
}

// ReadPlaintextFrom parses an ssl_data_event_t ringbuf sample.
func ReadPlaintextFrom(r io.Reader) (*PlaintextRecord, error) {
	var timestamp uint64
	var pidTgid uint64
	var dataLen int32
	var sslType, direction, tlsSource uint8

	if err := binary.Read(r, binary.LittleEndian, &timestamp); err != nil {
		return nil, fmt.Errorf("reading timestamp: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &pidTgid); err != nil {
		return nil, fmt.Errorf("reading pid_tgid: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &dataLen); err != nil {
		return nil, fmt.Errorf("reading data_len: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &sslType); err != nil {
		return nil, fmt.Errorf("reading ssl_type: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &direction); err != nil {
		return nil, fmt.Errorf("reading direction: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &tlsSource); err != nil {
		return nil, fmt.Errorf("reading tls_source: %w", err)
	}
	var tupleValid uint8
	if err := binary.Read(r, binary.LittleEndian, &tupleValid); err != nil {
		return nil, fmt.Errorf("reading tuple_valid: %w", err)
	}
	var srcPort, dstPort uint16
	if err := binary.Read(r, binary.LittleEndian, &srcPort); err != nil {
		return nil, fmt.Errorf("reading src_port: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &dstPort); err != nil {
		return nil, fmt.Errorf("reading dst_port: %w", err)
	}
	var srcAddr, dstAddr [16]byte
	if _, err := io.ReadFull(r, srcAddr[:]); err != nil {
		return nil, fmt.Errorf("reading src_addr: %w", err)
	}
	if _, err := io.ReadFull(r, dstAddr[:]); err != nil {
		return nil, fmt.Errorf("reading dst_addr: %w", err)
	}
	var socketFd int32
	if err := binary.Read(r, binary.LittleEndian, &socketFd); err != nil {
		return nil, fmt.Errorf("reading socket_fd: %w", err)
	}
	var connPtr uint64
	if err := binary.Read(r, binary.LittleEndian, &connPtr); err != nil {
		return nil, fmt.Errorf("reading conn_user_ptr: %w", err)
	}

	rec := &PlaintextRecord{
		Timestamp: bootTimeToWall(int64(timestamp)),
		Pid:       uint32(pidTgid >> 32),
		Tgid:      uint32(pidTgid),
		Direction: directionName(direction),
		TLSSource: tlsSourceName(tlsSource),
		SSLType:   sslType,
		SocketFd:  socketFd,
		ConnPtr:   connPtr,
	}

	if dataLen > 0 {
		rec.Data = make([]byte, dataLen)
		if _, err := io.ReadFull(r, rec.Data); err != nil {
			return nil, fmt.Errorf("reading plaintext data: %w", err)
		}
	}

	if tupleValid != 0 {
		if srcIP := ipFromEventAddr(srcAddr[:]); srcIP != nil {
			rec.SrcAddr = srcIP.String()
		}
		if dstIP := ipFromEventAddr(dstAddr[:]); dstIP != nil {
			rec.DstAddr = dstIP.String()
		}
		rec.SrcPort = srcPort
		rec.DstPort = dstPort
		rec.Protocol = "TCP"
	}

	return rec, nil
}

func ipFromEventAddr(raw []byte) net.IP {
	if len(raw) != 16 {
		return nil
	}
	if v4, ok := ipv4FromMapped(raw); ok {
		return v4
	}
	return net.IP(raw)
}

func ipv4FromMapped(raw []byte) (net.IP, bool) {
	for i := 0; i < 10; i++ {
		if raw[i] != 0 {
			return nil, false
		}
	}
	if raw[10] != 0xff || raw[11] != 0xff {
		return nil, false
	}
	return net.IPv4(raw[15], raw[14], raw[13], raw[12]), true
}

func bootTimeToWall(bootNs int64) time.Time {
	if bootNs <= 0 {
		return time.Time{}
	}
	now := time.Now()
	monoNow := int64(monotime.Now())
	delta := time.Duration(monoNow - bootNs)
	return now.Add(-delta)
}
