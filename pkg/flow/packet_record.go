package flow

import (
	"encoding/binary"
	"io"
	"time"

	"github.com/sirupsen/logrus"
)

var plog = logrus.WithField("component", "packet/PerfBuffer")

type RawByte byte

type PacketRecord struct {
	Stream []byte
	Time   time.Time
}

// NewPacketRecord contains packet bytes
func NewPacketRecord(
	stream []byte,
	len uint16,
	ts time.Time,
) *PacketRecord {
	pr := PacketRecord{}
	pr.Time = ts
	pr.Stream = make([]byte, len)
	pr.Stream = stream
	return &pr
}

// ReadRawPacket reads a PacketRecord from a binary source, in LittleEndian order
func ReadRawPacket(reader io.Reader) (*PacketRecord, error) {
	var pr PacketRecord
	var tm time.Time
	getLen := make([]byte, 2)
	// Read IfIndex and discard it: To be used in other usecases
	_ = binary.Read(reader, binary.LittleEndian, make([]byte, 2))
	// Read Length of packet
	_ = binary.Read(reader, binary.LittleEndian, getLen)
	plog.Debugf("Reading packet of length: %d", binary.LittleEndian.Uint16(getLen))
	pr.Stream = make([]byte, binary.LittleEndian.Uint16(getLen))
	plog.Infof("Reading packet of length: %d", binary.LittleEndian.Uint16(getLen))
	// Read TimeStamp of packet
	packetTimestamp := make([]byte, 8)
	_ = binary.Read(reader, binary.LittleEndian, packetTimestamp)
	_ = tm.UnmarshalBinary(packetTimestamp)
	pr.Time = tm
	err := binary.Read(reader, binary.LittleEndian, &pr.Stream)
	return &pr, err
}
