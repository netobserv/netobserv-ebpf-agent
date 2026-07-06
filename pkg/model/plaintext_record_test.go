package model

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestReadPlaintextFromKernelTuple(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint64(1_700_000_000_000))
	_ = binary.Write(&buf, binary.LittleEndian, uint64(0x1234_0000_5678))
	_ = binary.Write(&buf, binary.LittleEndian, int32(3))
	_ = binary.Write(&buf, binary.LittleEndian, uint8(0)) // ssl_type
	_ = binary.Write(&buf, binary.LittleEndian, uint8(0)) // direction write
	_ = binary.Write(&buf, binary.LittleEndian, uint8(2)) // ktls
	_ = binary.Write(&buf, binary.LittleEndian, uint8(1)) // tuple_valid
	_ = binary.Write(&buf, binary.LittleEndian, uint16(8443))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(40494))
	src := ipv4MappedAddr(net.IPv4(10, 244, 2, 7))
	dst := ipv4MappedAddr(net.IPv4(10, 244, 2, 1))
	_, _ = buf.Write(src[:])
	_, _ = buf.Write(dst[:])
	_ = binary.Write(&buf, binary.LittleEndian, uint64(0))
	_ = binary.Write(&buf, binary.LittleEndian, int32(-1))
	_, _ = buf.Write([]byte("OK\n"))

	rec, err := ReadPlaintextFrom(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if rec.TLSSource != TLSSourceKTLS {
		t.Fatalf("unexpected source %q", rec.TLSSource)
	}
	if rec.SrcAddr != "10.244.2.7" || rec.DstAddr != "10.244.2.1" {
		t.Fatalf("unexpected tuple %s:%d -> %s:%d", rec.SrcAddr, rec.SrcPort, rec.DstAddr, rec.DstPort)
	}
	if rec.SrcPort != 8443 || rec.DstPort != 40494 {
		t.Fatalf("unexpected ports %d %d", rec.SrcPort, rec.DstPort)
	}
}

func ipv4MappedAddr(ip net.IP) [16]byte {
	var out [16]byte
	out[10] = 0xff
	out[11] = 0xff
	v4 := ip.To4()
	if v4 != nil {
		out[12] = v4[3]
		out[13] = v4[2]
		out[14] = v4[1]
		out[15] = v4[0]
	}
	return out
}
