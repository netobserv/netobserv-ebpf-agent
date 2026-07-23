package tracer

import (
	"errors"
	"fmt"
	"os"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	agentebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
)

const (
	constEnableGoTLSTracking = "enable_gotls_tracking"
	constEnableKTLSTracking  = "enable_ktls_tracking"
	sockHashMap              = "sock_hash"
)

func tlsPlaintextEnabled(cfg *FlowFetcherConfig) bool {
	return cfg.EnableOpenSSLTracking || cfg.EnableGoTLSTracking || cfg.EnableKTLSTracking
}

func opensslTrackingEnabled(cfg *FlowFetcherConfig) bool {
	return cfg.EnableOpenSSLTracking
}

func setTLSCaptureVariables(spec *cilium.CollectionSpec, cfg *FlowFetcherConfig) error {
	enableOpenSSL := 0
	if opensslTrackingEnabled(cfg) {
		enableOpenSSL = 1
	}
	enableGoTLS := 0
	if cfg.EnableGoTLSTracking {
		enableGoTLS = 1
	}
	enableKTLS := 0
	if cfg.EnableKTLSTracking {
		enableKTLS = 1
	}
	vars := []variablesMapping{
		{agentebpf.BpfVarEnableOpensslTracking, uint8(enableOpenSSL)},
		{constEnableGoTLSTracking, uint8(enableGoTLS)},
		{constEnableKTLSTracking, uint8(enableKTLS)},
	}
	for _, v := range vars {
		if err := setVariable(spec, v.key, v.value); err != nil {
			return fmt.Errorf("setting TLS capture variable %s: %w", v.key, err)
		}
	}
	return nil
}

type tlsBpfPrograms struct {
	ProbeEntrySSLWrite   *cilium.Program `ebpf:"probe_entry_SSL_write"`
	ProbeEntrySSLSetFd   *cilium.Program `ebpf:"probe_entry_SSL_set_fd"`
	ProbeEntrySSLRead    *cilium.Program `ebpf:"probe_entry_SSL_read"`
	ProbeRetSSLRead      *cilium.Program `ebpf:"probe_ret_SSL_read"`
	ProbeEntryGotlsWrite *cilium.Program `ebpf:"probe_entry_gotls_write"`
	ProbeEntryGotlsRead  *cilium.Program `ebpf:"probe_entry_gotls_read"`
	ProbeRetGotlsRead    *cilium.Program `ebpf:"probe_ret_gotls_read"`
	BpfSockops           *cilium.Program `ebpf:"bpf_sockops"`
	BpfKtlsRedir         *cilium.Program `ebpf:"bpf_ktls_redir"`
}

type packetFetcherTLS struct {
	sslReader       *ringbuf.Reader
	opensslAttacher *opensslAttacher
}

func setupPacketFetcherTLS(spec *cilium.CollectionSpec, cfg *FlowFetcherConfig, maps *agentebpf.BpfMaps, progs *tlsBpfPrograms) (*packetFetcherTLS, error) {
	if !tlsPlaintextEnabled(cfg) {
		return nil, nil
	}

	if err := setTLSCaptureVariables(spec, cfg); err != nil {
		return nil, err
	}

	reader, err := ringbuf.NewReader(maps.SslDataEventMap)
	if err != nil {
		return nil, fmt.Errorf("accessing SSL data event ringbuffer: %w", err)
	}

	result := &packetFetcherTLS{sslReader: reader}

	if opensslTrackingEnabled(cfg) {
		if cfg.PlaintextScope == nil || !cfg.PlaintextScope.IsPIDScopeActive() {
			plog.Warn("OpenSSL libssl discovery is not peer-scoped; attaches per-container libssl on this node — set peer_ip/peer_cidr in FLOW_FILTER_RULES to narrow")
		}
		attacher, err := attachOpenSSLUprobes(cfg, progs.ProbeEntrySSLWrite, progs.ProbeEntrySSLRead, progs.ProbeRetSSLRead, progs.ProbeEntrySSLSetFd)
		if err != nil {
			result.Close()
			return nil, fmt.Errorf("attaching OpenSSL uprobes: %w", err)
		}
		result.opensslAttacher = attacher
		plog.Infof("OpenSSL TLS plaintext capture enabled (OPENSSL_PATH=%s)", cfg.OpenSSLPath)
	}

	return result, nil
}

func closePacketFetcherTLS(pf *PacketFetcher) {
	if pf.sslDataEventsReader != nil {
		_ = pf.sslDataEventsReader.Close()
		pf.sslDataEventsReader = nil
	}
	if pf.opensslAttacher != nil {
		pf.opensslAttacher.Close()
		pf.opensslAttacher = nil
	}
}

func closePacketFetcherPrograms(objects *agentebpf.BpfObjects) error {
	if objects == nil {
		return nil
	}
	var errs []error
	closers := []*cilium.Program{
		objects.TcEgressPcaParse,
		objects.TcIngressPcaParse,
		objects.TcxEgressPcaParse,
		objects.TcxIngressPcaParse,
	}
	for _, prog := range closers {
		if prog != nil {
			if err := prog.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if objects.PacketRecord != nil {
		if err := objects.PacketRecord.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (t *packetFetcherTLS) Close() {
	if t == nil {
		return
	}
	if t.sslReader != nil {
		_ = t.sslReader.Close()
	}
	if t.opensslAttacher != nil {
		t.opensslAttacher.Close()
	}
}

func tlsMapSizing(spec *cilium.CollectionSpec, cfg *FlowFetcherConfig) {
	minEntries := uint32(os.Getpagesize())
	if !tlsPlaintextEnabled(cfg) {
		spec.Maps[agentebpf.BpfMapSslDataEventMap].MaxEntries = minEntries
	}
	if !cfg.EnableKTLSTracking {
		spec.Maps[sockHashMap].MaxEntries = 1
	}
}
