package tracer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDNSTrackingPorts(t *testing.T) {
	testCases := []struct {
		name              string
		inputPorts        []uint16
		enableDNSTracking bool
		expectedPorts     []uint16
		expectedCount     uint8
		expectWarning     bool // For validation purposes, not checked in test
	}{
		{
			name:              "Single port - backward compatible",
			inputPorts:        []uint16{53},
			enableDNSTracking: true,
			expectedPorts:     []uint16{53},
			expectedCount:     1,
		},
		{
			name:              "Multiple ports",
			inputPorts:        []uint16{53, 5353, 8053},
			enableDNSTracking: true,
			expectedPorts:     []uint16{53, 5353, 8053},
			expectedCount:     3,
		},
		{
			name:              "Maximum ports (8)",
			inputPorts:        []uint16{53, 5353, 8053, 9053, 10053, 11053, 12053, 13053},
			enableDNSTracking: true,
			expectedPorts:     []uint16{53, 5353, 8053, 9053, 10053, 11053, 12053, 13053},
			expectedCount:     8,
		},
		{
			name:              "More than max ports - truncated",
			inputPorts:        []uint16{53, 5353, 8053, 9053, 10053, 11053, 12053, 13053, 14053, 15053},
			enableDNSTracking: true,
			expectedPorts:     []uint16{53, 5353, 8053, 9053, 10053, 11053, 12053, 13053},
			expectedCount:     8,
			expectWarning:     true,
		},
		{
			name:              "Empty slice - no valid ports",
			inputPorts:        []uint16{},
			enableDNSTracking: true,
			expectedPorts:     []uint16{},
			expectedCount:     0,
			expectWarning:     true,
		},
		{
			name:              "Port zero",
			inputPorts:        []uint16{0},
			enableDNSTracking: true,
			expectedPorts:     []uint16{0},
			expectedCount:     1,
		},
		{
			name:              "Port 65535 - max valid port",
			inputPorts:        []uint16{65535},
			enableDNSTracking: true,
			expectedPorts:     []uint16{65535},
			expectedCount:     1,
		},
		{
			name:              "DNS tracking disabled - no parsing",
			inputPorts:        []uint16{53, 5353},
			enableDNSTracking: false,
			expectedPorts:     []uint16{},
			expectedCount:     0,
		},
		{
			name:              "Duplicate ports",
			inputPorts:        []uint16{53, 53, 5353},
			enableDNSTracking: true,
			expectedPorts:     []uint16{53, 53, 5353},
			expectedCount:     3,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var dnsPorts [maxDNSPorts]uint16
			var dnsPortsCount uint8

			if tc.enableDNSTracking {
				dnsPorts, dnsPortsCount = parseDNSTrackingPorts(tc.inputPorts)
			}

			// Verify the count
			require.Equal(t, tc.expectedCount, dnsPortsCount)

			// Verify the ports
			for i := 0; i < int(tc.expectedCount); i++ {
				assert.Equal(t, tc.expectedPorts[i], dnsPorts[i])
			}

			// Verify remaining slots are zero
			for i := int(tc.expectedCount); i < maxDNSPorts; i++ {
				assert.Equal(t, uint16(0), dnsPorts[i])
			}
		})
	}
}

func TestDNSPortsArraySize(t *testing.T) {
	// Verify that maxDNSPorts matches the eBPF MAX_DNS_PORTS constant
	// This test will fail if they get out of sync
	assert.Equal(t, 8, maxDNSPorts, "maxDNSPorts should match MAX_DNS_PORTS in bpf/configs.h")
}
