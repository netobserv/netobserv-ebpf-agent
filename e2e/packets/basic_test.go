//go:build linux

package packets

import (
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/packets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPacketBPFSymbols is a smoke guard ensuring the packet BPF object is self-contained.
func TestPacketBPFSymbols(t *testing.T) {
	spec, err := packets.LoadPackets()
	require.NoError(t, err)
	require.NotEmpty(t, spec.Programs)
	for name := range spec.Programs {
		assert.Contains(t, name, "packet_parse")
	}
	require.NotNil(t, spec.Maps["packet_record"])
}

// TestBasicPacketCapture is a placeholder for a full Kind-based PCA e2e test.
// Cluster setup with a packet gRPC receiver is tracked separately from this PoC.
func TestBasicPacketCapture(t *testing.T) {
	t.Skip("PCA cluster e2e requires packet collector deployment; see examples/packetcapture-dump/")
}
