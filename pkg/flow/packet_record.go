package flow

import (
	"encoding/binary"
	"io"

	"github.com/sirupsen/logrus"
)

var plog = logrus.WithField("component", "packet/PerfBuffer")

type RawByte byte

type PacketRecord struct {
	Stream []byte
}

// NewPacketRecord contains packet bytes
func NewPacketRecord(
	stream []byte,
	len uint16,
) *PacketRecord {
	pr := PacketRecord{}
	pr.Stream = make([]byte, len)
	pr.Stream = stream
	return &pr
}

// ReadRawPacket reads a PacketRecord from a binary source, in LittleEndian order
func ReadRawPacket(reader io.Reader) (*PacketRecord, error) {
	var pr PacketRecord
	getLen := make([]byte, 2)
	// Read IfIndex and discard it: To be used in other usecases
	_ = binary.Read(reader, binary.LittleEndian, make([]byte, 2))
	// Read Length of packet
	_ = binary.Read(reader, binary.LittleEndian, getLen)
	plog.Debugf("Reading packet of length: %d", binary.LittleEndian.Uint16(getLen))
	pr.Stream = make([]byte, binary.LittleEndian.Uint16(getLen))
	err := binary.Read(reader, binary.LittleEndian, &pr.Stream)
	return &pr, err
}
