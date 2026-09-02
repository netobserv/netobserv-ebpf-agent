package attach

import (
	"fmt"
	"net"
	"syscall"
	"testing"

	ebpfflows "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestGetPortsFromString(t *testing.T) {
	testCases := []struct {
		portsRange    string
		expectedStart uint16
		expectedEnd   uint16
		expectedError error
	}{
		{
			portsRange:    "80-90",
			expectedStart: 80,
			expectedEnd:   90,
			expectedError: nil,
		},
		{
			portsRange:    "90-80",
			expectedStart: 0,
			expectedEnd:   0,
			expectedError: fmt.Errorf("invalid port range. Start port is greater than end port"),
		},
		{
			portsRange:    "80",
			expectedStart: 0,
			expectedEnd:   0,
			expectedError: fmt.Errorf("invalid ports range. Expected two integers separated by - but found 80"),
		},
		{
			portsRange:    "80000-8080",
			expectedStart: 0,
			expectedEnd:   0,
			expectedError: fmt.Errorf("invalid start port number strconv.ParseUint: parsing \"80000\": value out of range"),
		},
	}

	for _, tc := range testCases {
		start, end, err := getPortsFromString(tc.portsRange, "-")
		if tc.expectedError != nil {
			require.Error(t, err)
			require.Equal(t, tc.expectedError.Error(), err.Error())
		} else {
			require.NoError(t, err)
			require.Equal(t, tc.expectedStart, start)
			require.Equal(t, tc.expectedEnd, end)
		}
	}
}

func TestFilter_getFilterKey(t *testing.T) {
	f := Filter{}
	config := &FilterConfig{
		IPCIDR: "192.168.1.0/24",
	}
	expectedIP := net.ParseIP("192.168.1.0").To4()
	expectedPrefixLen := uint32(24)

	key, err := f.getFilterKey(config)

	assert.Nil(t, err)
	assert.Equal(t, []uint8(expectedIP), key.IpData[:4])
	assert.Equal(t, expectedPrefixLen, key.PrefixLen)
}

func TestFilter_getFilterValue(t *testing.T) {
	f := Filter{}
	config := &FilterConfig{
		Direction:       "Ingress",
		Protocol:        "TCP",
		SourcePort:      intstr.FromInt32(8080),
		DestinationPort: intstr.FromString("8000-9000"),
		Port:            intstr.FromString("3000,4000"),
	}

	value, err := f.getFilterValue(config)

	assert.Nil(t, err)
	assert.Equal(t, ebpfflows.BpfDirectionTINGRESS, value.Direction)
	assert.Equal(t, uint8(syscall.IPPROTO_TCP), value.Protocol)
	assert.Equal(t, uint16(8080), value.SrcPortStart)
	assert.Equal(t, uint16(0), value.SrcPortEnd)
	assert.Equal(t, uint16(8000), value.DstPortStart)
	assert.Equal(t, uint16(9000), value.DstPortEnd)
	assert.Equal(t, uint16(3000), value.Port1)
	assert.Equal(t, uint16(4000), value.Port2)
}

func TestGetSrcPortsRange(t *testing.T) {
	config := &FilterConfig{
		SourcePort: intstr.FromString("8000-9000"),
	}
	start, end := getSrcPortsRange(config)

	assert.Equal(t, uint16(8000), start)
	assert.Equal(t, uint16(9000), end)
}

func TestGetSrcPorts(t *testing.T) {
	config := &FilterConfig{
		SourcePort: intstr.FromString("8000,9000"),
	}
	p1, p2 := getSrcPorts(config)

	assert.Equal(t, uint16(8000), p1)
	assert.Equal(t, uint16(9000), p2)
}

func TestGetDstPortsRange(t *testing.T) {
	config := &FilterConfig{
		DestinationPort: intstr.FromInt32(8080),
	}
	start, end := getDstPortsRange(config)

	assert.Equal(t, uint16(8080), start)
	assert.Equal(t, uint16(0), end)
}

func TestGetDstPorts(t *testing.T) {
	config := &FilterConfig{
		DestinationPort: intstr.FromString("8080,9000"),
	}
	p1, p2 := getDstPorts(config)

	assert.Equal(t, uint16(8080), p1)
	assert.Equal(t, uint16(9000), p2)
}

func TestGetPortsRange(t *testing.T) {
	config := &FilterConfig{
		Port: intstr.FromString("8080-9000"),
	}
	start, end := getPortsRange(config)

	assert.Equal(t, uint16(8080), start)
	assert.Equal(t, uint16(9000), end)
}

func TestGetPorts(t *testing.T) {
	config := &FilterConfig{
		Port: intstr.FromString("7000,8000"),
	}
	p1, p2 := getPorts(config)

	assert.Equal(t, uint16(7000), p1)
	assert.Equal(t, uint16(8000), p2)
}

func TestConvertFilterPortsToInstr(t *testing.T) {

	t.Run("converts int port", func(t *testing.T) {
		port := int32(80)
		result := ConvertFilterPortsToInstr(port, "", "")
		require.Equal(t, intstr.FromInt32(port), result)
	})

	t.Run("converts string range", func(t *testing.T) {
		rangeStr := "80-90"
		result := ConvertFilterPortsToInstr(0, rangeStr, "")
		require.Equal(t, intstr.FromString(rangeStr), result)
	})
	t.Run("converts string ports", func(t *testing.T) {
		portsStr := "80,90"
		result := ConvertFilterPortsToInstr(0, "", portsStr)
		require.Equal(t, intstr.FromString(portsStr), result)
	})
}

func TestBuildFilterKey(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		ipStr     string
		wantKey   ebpfflows.BpfFilterKeyT
		wantError bool
	}{
		{
			name:  "Valid CIDR IPv4",
			cidr:  "192.168.1.0/24",
			ipStr: "",
			wantKey: ebpfflows.BpfFilterKeyT{
				IpData:    [16]byte{192, 168, 1, 0},
				PrefixLen: 24,
			},
			wantError: false,
		},
		{
			name:  "Valid default IPv4 CIDR",
			cidr:  "0.0.0.0/0",
			ipStr: "",
			wantKey: ebpfflows.BpfFilterKeyT{
				IpData:    [16]byte{0},
				PrefixLen: 0,
			},
			wantError: false,
		},
		{
			name:  "Valid CIDR IPv6",
			cidr:  "2001:db8::/48",
			ipStr: "",
			wantKey: ebpfflows.BpfFilterKeyT{
				IpData:    [16]byte{0x20, 0x01, 0x0d, 0xb8},
				PrefixLen: 48,
			},
			wantError: false,
		},
		{
			name:  "Valid default IPv6 CIDR",
			cidr:  "0::0/0",
			ipStr: "",
			wantKey: ebpfflows.BpfFilterKeyT{
				IpData:    [16]byte{0},
				PrefixLen: 0,
			},
			wantError: false,
		},
		{
			name:  "Valid IP string IPv4",
			cidr:  "",
			ipStr: "192.168.1.1",
			wantKey: ebpfflows.BpfFilterKeyT{
				IpData:    [16]byte{192, 168, 1, 1},
				PrefixLen: 32,
			},
			wantError: false,
		},
		{
			name:  "Valid IP string IPv6",
			cidr:  "",
			ipStr: "2001:db8::1",
			wantKey: ebpfflows.BpfFilterKeyT{
				IpData:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
				PrefixLen: 128,
			},
			wantError: false,
		},
		{
			name:      "Invalid CIDR",
			cidr:      "invalidCIDR",
			ipStr:     "",
			wantKey:   ebpfflows.BpfFilterKeyT{},
			wantError: true,
		},
		{
			name:      "Empty input",
			cidr:      "",
			ipStr:     "",
			wantKey:   ebpfflows.BpfFilterKeyT{},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filterObj := Filter{}
			key, err := filterObj.buildFilterKey(tt.cidr, tt.ipStr)

			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantKey, key)
			}
		})
	}
}

func TestBpfKeyToPacketsKey(t *testing.T) {
	key := ebpfflows.BpfFilterKeyT{PrefixLen: 24, IpData: [16]byte{10, 0, 0, 0}}
	pk := bpfKeyToPacketsKey(key)
	assert.Equal(t, key.PrefixLen, pk.PrefixLen)
	assert.Equal(t, key.IpData, pk.IpData)
}

func TestBpfValToPacketsVal(t *testing.T) {
	val := ebpfflows.BpfFilterValueT{
		Protocol:          syscall.IPPROTO_TCP,
		DstPortStart:      80,
		Direction:         ebpfflows.BpfDirectionTINGRESS,
		Action:            ebpfflows.BpfFilterActionTACCEPT,
		TcpFlags:          ebpfflows.BpfTcpFlagsTSYN_FLAG,
		FilterDrops:       1,
		Sample:            5,
		DoPeerCIDR_lookup: 1,
	}
	pk := bpfValToPacketsVal(val)
	assert.Equal(t, val.Protocol, pk.Protocol)
	assert.Equal(t, val.DstPortStart, pk.DstPortStart)
	assert.Equal(t, uint32(val.Direction), pk.Direction)
	assert.Equal(t, uint32(val.Action), pk.Action)
	assert.Equal(t, val.TcpFlags, ebpfflows.BpfTcpFlagsT(pk.TcpFlags))
	assert.Equal(t, val.FilterDrops, pk.FilterDrops)
	assert.Equal(t, val.Sample, pk.Sample)
	assert.Equal(t, val.DoPeerCIDR_lookup, pk.DoPeerCIDR_lookup)
}
