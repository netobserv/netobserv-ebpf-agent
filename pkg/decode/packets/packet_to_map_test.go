package packets

import (
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testSrcMAC = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	testDstMAC = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	testTime   = time.Unix(1700000000, 0).UTC()
)

func TestPacketToMap_NilRecord(t *testing.T) {
	out := PacketToMap(nil)
	assert.Equal(t, config.GenericMap{}, out)
}

func TestPacketToMap_TCPIPv4(t *testing.T) {
	payload := []byte("hello")
	stream := mustSerialize(t,
		&layers.Ethernet{
			SrcMAC:       testSrcMAC,
			DstMAC:       testDstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    net.IP{1, 2, 3, 4},
			DstIP:    net.IP{5, 6, 7, 8},
		},
		&layers.TCP{
			SrcPort: 23000,
			DstPort: 443,
			SYN:     true,
		},
		gopacket.Payload(payload),
	)

	out := PacketToMap(model.NewPacketRecord(stream, uint32(len(stream)), testTime))
	parsed := gopacket.NewPacket(stream, layers.LayerTypeEthernet, gopacket.Lazy)

	assert.Equal(t, "00:11:22:33:44:55", out["SrcMac"])
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", out["DstMac"])
	assert.Equal(t, uint16(23000), out["SrcPort"])
	assert.Equal(t, uint16(443), out["DstPort"])
	assert.Equal(t, "1.2.3.4", out["SrcAddr"])
	assert.Equal(t, "5.6.7.8", out["DstAddr"])
	assert.Equal(t, layers.IPProtocolTCP, out["Proto"])
	assert.Equal(t, len(stream), out["Bytes"])
	assert.Equal(t, testTime.Unix(), out["Time"])
	assert.Equal(t, base64.StdEncoding.EncodeToString(parsed.Data()), out["Data"])
}

func TestPacketToMap_UDPIPv4(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	stream := mustSerialize(t,
		&layers.Ethernet{
			SrcMAC:       testSrcMAC,
			DstMAC:       testDstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    net.IP{10, 0, 0, 1},
			DstIP:    net.IP{10, 0, 0, 2},
		},
		&layers.UDP{
			SrcPort: 5353,
			DstPort: 53,
		},
		gopacket.Payload(payload),
	)

	out := PacketToMap(model.NewPacketRecord(stream, uint32(len(stream)), testTime))
	parsed := gopacket.NewPacket(stream, layers.LayerTypeEthernet, gopacket.Lazy)

	assert.Equal(t, uint16(5353), out["SrcPort"])
	assert.Equal(t, uint16(53), out["DstPort"])
	assert.Equal(t, "10.0.0.1", out["SrcAddr"])
	assert.Equal(t, "10.0.0.2", out["DstAddr"])
	assert.Equal(t, layers.IPProtocolUDP, out["Proto"])
	assert.Equal(t, len(stream), out["Bytes"])
	assert.Equal(t, testTime.Unix(), out["Time"])
	assert.Equal(t, base64.StdEncoding.EncodeToString(parsed.Data()), out["Data"])
}

func TestPacketToMap_ICMPv4(t *testing.T) {
	stream := mustSerialize(t,
		&layers.Ethernet{
			SrcMAC:       testSrcMAC,
			DstMAC:       testDstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolICMPv4,
			SrcIP:    net.IP{192, 168, 1, 1},
			DstIP:    net.IP{192, 168, 1, 2},
		},
		&layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		},
	)

	out := PacketToMap(model.NewPacketRecord(stream, uint32(len(stream)), testTime))

	assert.Equal(t, uint8(layers.ICMPv4TypeEchoRequest), out["IcmpType"])
	assert.Equal(t, uint8(0), out["IcmpCode"])
	assert.Equal(t, "192.168.1.1", out["SrcAddr"])
	assert.Equal(t, "192.168.1.2", out["DstAddr"])
	assert.Equal(t, layers.IPProtocolICMPv4, out["Proto"])
	_, hasSrcPort := out["SrcPort"]
	assert.False(t, hasSrcPort)
}

func TestPacketToMap_DNSOverUDP(t *testing.T) {
	dns := &layers.DNS{
		ID:           0x1234,
		QR:           true,
		ResponseCode: layers.DNSResponseCodeNoErr,
		QDCount:      1,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte("example.com"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
	}
	stream := mustSerialize(t,
		&layers.Ethernet{
			SrcMAC:       testSrcMAC,
			DstMAC:       testDstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    net.IP{8, 8, 8, 8},
			DstIP:    net.IP{1, 1, 1, 1},
		},
		&layers.UDP{
			SrcPort: 12345,
			DstPort: 53,
		},
		dns,
	)

	out := PacketToMap(model.NewPacketRecord(stream, uint32(len(stream)), testTime))

	assert.Equal(t, uint16(0x1234), out["DnsId"])
	assert.Equal(t, layers.DNSResponseCodeNoErr.String(), out["DnsFlagsResponseCode"])
	assert.Equal(t, uint16(12345), out["SrcPort"])
	assert.Equal(t, uint16(53), out["DstPort"])
}

func mustSerialize(t *testing.T, layersToSerialize ...gopacket.SerializableLayer) []byte {
	t.Helper()
	for i, layer := range layersToSerialize {
		switch l := layer.(type) {
		case *layers.TCP:
			if ip := ipv4Before(layersToSerialize, i); ip != nil {
				require.NoError(t, l.SetNetworkLayerForChecksum(ip))
			}
		case *layers.UDP:
			if ip := ipv4Before(layersToSerialize, i); ip != nil {
				require.NoError(t, l.SetNetworkLayerForChecksum(ip))
			}
		}
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, layersToSerialize...))
	return buf.Bytes()
}

func ipv4Before(layersToSerialize []gopacket.SerializableLayer, idx int) *layers.IPv4 {
	for j := idx - 1; j >= 0; j-- {
		if ip, ok := layersToSerialize[j].(*layers.IPv4); ok {
			return ip
		}
	}
	return nil
}
