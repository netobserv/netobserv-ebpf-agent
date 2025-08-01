package model

import (
	"encoding/binary"
	"io"
	"time"

	"github.com/gavv/monotime"
)

type RawByte byte

type PacketRecord struct {
	Stream []byte
	Time   time.Time
}

// NewPacketRecord contains packet bytes
func NewPacketRecord(
	stream []byte,
	length uint32,
	ts time.Time,
) *PacketRecord {
	pr := PacketRecord{}
	pr.Time = ts
	pr.Stream = make([]byte, length)
	pr.Stream = stream
	return &pr
}

// ReadRawPacket reads a PacketRecord from a binary source, in NativeEndian order
func ReadRawPacket(reader io.Reader) (*PacketRecord, error) {
	var pr PacketRecord
	currentTime := time.Now()
	monotonicTimeNow := monotime.Now()
	getLen := make([]byte, 4)
	packetTimestamp := make([]byte, 8)
	// Read IfIndex and discard it: To be used in other use cases
	_ = binary.Read(reader, binary.NativeEndian, make([]byte, 4))
	// Read Length of a packet
	_ = binary.Read(reader, binary.NativeEndian, getLen)
	pr.Stream = make([]byte, binary.NativeEndian.Uint32(getLen))
	// Read TimeStamp of a packet
	_ = binary.Read(reader, binary.NativeEndian, packetTimestamp)
	// The assumption is monotonic time should be as close to time recorded by ebpf.
	// The difference is considered the delta time from current time.
	tsDelta := time.Duration(uint64(monotonicTimeNow) - binary.NativeEndian.Uint64(packetTimestamp))
	pr.Time = currentTime.Add(-tsDelta)

	err := binary.Read(reader, binary.NativeEndian, &pr.Stream)
	return &pr, err
}
