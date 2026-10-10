package packets

import (
	"os"

	cilium "github.com/cilium/ebpf"
	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/packets"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/internal/netattach"
)

func configurePacketMaps(spec *cilium.CollectionSpec, cfg *tracer.FetcherConfig) {
	netattach.MinimizeMapsIfDisabled(spec, cfg.EnableOpenSSLTracking, 1, ebpf.PacketsMapSslReadActiveMap, ebpf.PacketsMapSslFdMap)
	netattach.MinimizeMapsIfDisabled(spec, cfg.EnableOpenSSLTracking, os.Getpagesize(), ebpf.PacketsMapSslDataEventMap)
}
