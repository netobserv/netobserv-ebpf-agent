package packets

import (
	"fmt"
	"os"
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/packets"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigurePacketMaps(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			spec, err := ebpf.LoadPackets()
			require.NoError(t, err)
			expected := spec.Copy()
			if !enabled {
				expected.Maps[ebpf.PacketsMapSslDataEventMap].MaxEntries = uint32(os.Getpagesize())
				expected.Maps[ebpf.PacketsMapSslReadActiveMap].MaxEntries = 1
				expected.Maps[ebpf.PacketsMapSslFdMap].MaxEntries = 1
			}
			cfg := &tracer.FetcherConfig{Agent: config.Agent{Common: config.Common{EnableOpenSSLTracking: enabled}}}
			configurePacketMaps(spec, cfg)
			// Packet capture, filtering and all map ABI/flags must stay unchanged.
			for name, before := range expected.Maps {
				after := spec.Maps[name]
				assert.Equal(t, before.MaxEntries, after.MaxEntries, name)
				assert.Equal(t, before.KeySize, after.KeySize, name)
				assert.Equal(t, before.ValueSize, after.ValueSize, name)
				assert.Equal(t, before.Type, after.Type, name)
				assert.Equal(t, before.Flags, after.Flags, name)
				assert.Equal(t, before.Pinning, after.Pinning, name)
			}
		})
	}
}
