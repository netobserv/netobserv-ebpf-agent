package packets

import (
	"net"
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/netobserv/gopipes/pkg/node"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
)

type mockPacketFetcher struct{}

func (mockPacketFetcher) Close() error                                        { return nil }
func (mockPacketFetcher) Register(*ifaces.Interface) error                    { return nil }
func (mockPacketFetcher) UnRegister(*ifaces.Interface) error                  { return nil }
func (mockPacketFetcher) AttachTCX(*ifaces.Interface) error                   { return nil }
func (mockPacketFetcher) DetachTCX(*ifaces.Interface) error                   { return nil }
func (mockPacketFetcher) LookupAndDeleteMap(*metrics.Metrics) map[int][]*byte { return nil }
func (mockPacketFetcher) ReadPerf() (ringbuf.Record, error) {
	return ringbuf.Record{}, ringbuf.ErrClosed
}

func TestNew_InvalidExporterConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config.Agent
	}{
		{name: "invalid export", cfg: config.Agent{Common: config.Common{Export: "foo"}}},
		{name: "grpc missing host", cfg: config.Agent{Common: config.Common{Export: "grpc", TargetPort: 1234}}},
		{name: "grpc missing port", cfg: config.Agent{Common: config.Common{Export: "grpc", TargetHost: "flp"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(&tc.cfg)
			assert.Error(t, err)
		})
	}
}

func TestNewAgentWithMockFetcher(t *testing.T) {
	cfg := &config.Agent{Common: config.Common{Export: "grpc", TargetHost: "127.0.0.1", TargetPort: 1}}
	exporter := node.TerminalFunc[[]*model.PacketRecord](func(_ <-chan []*model.PacketRecord) {})

	agent, err := newAgent(cfg, mockPacketFetcher{}, exporter, net.ParseIP("10.0.0.1"))
	require.NoError(t, err)
	require.NotNil(t, agent)
	assert.Equal(t, cfg, agent.cfg)
}
