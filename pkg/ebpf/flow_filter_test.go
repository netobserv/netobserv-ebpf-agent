package ebpf

import (
	"fmt"
	"net"
	"syscall"
	"testing"

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

func TestFilter_getFlowFilterKey(t *testing.T) {
	f := Filter{}
	config := &FilterConfig{
		FilterIPCIDR: "192.168.1.0/24",
	}
	expectedIP := net.ParseIP("192.168.1.0").To4()
	expectedPrefixLen := uint32(24)

	key, err := f.getFilterKey(config)

	assert.Nil(t, err)
	assert.Equal(t, []uint8(expectedIP), key.IpData[:4])
	assert.Equal(t, expectedPrefixLen, key.PrefixLen)
}

func TestFilter_getFlowFilterValue(t *testing.T) {
	f := Filter{}
	config := &FilterConfig{
		FilterDirection:       "Ingress",
		FilterProtocol:        "TCP",
		FilterSourcePort:      intstr.FromInt32(8080),
		FilterDestinationPort: intstr.FromString("8000-9000"),
		FilterPort:            intstr.FromString("3000,4000"),
	}

	value, err := f.getFilterValue(config)

	assert.Nil(t, err)
	assert.Equal(t, BpfDirectionTINGRESS, value.Direction)
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
		FilterSourcePort: intstr.FromString("8000-9000"),
	}
	start, end := getSrcPortsRange(config)

	assert.Equal(t, uint16(8000), start)
	assert.Equal(t, uint16(9000), end)
}

func TestGetSrcPorts(t *testing.T) {
	config := &FilterConfig{
		FilterSourcePort: intstr.FromString("8000,9000"),
	}
	p1, p2 := getSrcPorts(config)

	assert.Equal(t, uint16(8000), p1)
	assert.Equal(t, uint16(9000), p2)
}

func TestGetDstPortsRange(t *testing.T) {
	config := &FilterConfig{
		FilterDestinationPort: intstr.FromInt32(8080),
	}
	start, end := getDstPortsRange(config)

	assert.Equal(t, uint16(8080), start)
	assert.Equal(t, uint16(0), end)
}

func TestGetDstPorts(t *testing.T) {
	config := &FilterConfig{
		FilterDestinationPort: intstr.FromString("8080,9000"),
	}
	p1, p2 := getDstPorts(config)

	assert.Equal(t, uint16(8080), p1)
	assert.Equal(t, uint16(9000), p2)
}

func TestGetPortsRange(t *testing.T) {
	config := &FilterConfig{
		FilterPort: intstr.FromString("8080-9000"),
	}
	start, end := getPortsRange(config)

	assert.Equal(t, uint16(8080), start)
	assert.Equal(t, uint16(9000), end)
}

func TestGetPorts(t *testing.T) {
	config := &FilterConfig{
		FilterPort: intstr.FromString("7000,8000"),
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
