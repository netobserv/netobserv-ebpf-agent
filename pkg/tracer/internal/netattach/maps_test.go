package netattach

import (
	"os"
	"testing"

	cilium "github.com/cilium/ebpf"
	ebpfflows "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	ebpfpackets "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/packets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMinimizeOpenSSLMaps(t *testing.T) {
	for name, load := range map[string]func() (*cilium.CollectionSpec, error){"flows": ebpfflows.LoadBpf, "packets": ebpfpackets.LoadPackets} {
		t.Run(name, func(t *testing.T) {
			spec, err := load()
			require.NoError(t, err)
			original := spec.Copy()
			MinimizeOpenSSLMaps(spec)
			for name, before := range original.Maps {
				after := spec.Maps[name]
				switch name {
				case "ssl_data_event_map":
					assert.Equal(t, uint32(os.Getpagesize()), after.MaxEntries)
				case "ssl_read_active_map", "ssl_fd_map":
					assert.Equal(t, uint32(1), after.MaxEntries)
				default:
					assert.Equal(t, before.MaxEntries, after.MaxEntries, "unrelated map %s", name)
				}
				// Resizing must preserve the ABI and map flags expected by existing programs.
				assert.Equal(t, before.KeySize, after.KeySize)
				assert.Equal(t, before.ValueSize, after.ValueSize)
				assert.Equal(t, before.Type, after.Type)
				assert.Equal(t, before.Flags, after.Flags)
			}
		})
	}
}
