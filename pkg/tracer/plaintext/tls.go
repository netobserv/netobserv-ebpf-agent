package plaintext

import (
	"fmt"
	"os"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	ebpfflows "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/internal/netattach"
)

func TLSPlaintextEnabled(enableOpenSSL bool) bool {
	return OpenSSLTrackingEnabled(enableOpenSSL)
}

func OpenSSLTrackingEnabled(enableOpenSSL bool) bool {
	return enableOpenSSL
}

func SetTLSCaptureVariables(spec *cilium.CollectionSpec, enableOpenSSL bool) error {
	v := 0
	if OpenSSLTrackingEnabled(enableOpenSSL) {
		v = 1
	}
	if err := netattach.SetVariable(spec, ebpfflows.BpfVarEnableOpensslTracking, uint8(v)); err != nil {
		return fmt.Errorf("setting TLS capture variable %s: %w", ebpfflows.BpfVarEnableOpensslTracking, err)
	}
	return nil
}

type TLSBpfPrograms struct {
	ProbeEntrySSLWrite *cilium.Program `ebpf:"probe_entry_SSL_write"`
	ProbeEntrySSLSetFd *cilium.Program `ebpf:"probe_entry_SSL_set_fd"`
	ProbeEntrySSLRead  *cilium.Program `ebpf:"probe_entry_SSL_read"`
	ProbeRetSSLRead    *cilium.Program `ebpf:"probe_ret_SSL_read"`
}

type PacketFetcherTLS struct {
	SSLReader       *ringbuf.Reader
	OpensslAttacher *OpenSSLAttacher
}

func SetupPacketFetcherTLS(spec *cilium.CollectionSpec, enableOpenSSL bool, scope *Scope, opensslPath string, maps *ebpfflows.BpfMaps, progs *TLSBpfPrograms) (*PacketFetcherTLS, error) {
	if !TLSPlaintextEnabled(enableOpenSSL) {
		return nil, nil
	}

	if err := SetTLSCaptureVariables(spec, enableOpenSSL); err != nil {
		return nil, err
	}

	reader, err := ringbuf.NewReader(maps.SslDataEventMap)
	if err != nil {
		return nil, fmt.Errorf("accessing SSL data event ringbuffer: %w", err)
	}

	result := &PacketFetcherTLS{SSLReader: reader}

	if OpenSSLTrackingEnabled(enableOpenSSL) {
		if scope == nil || !scope.IsPIDScopeActive() {
			olog.Warn("OpenSSL libssl discovery is not peer-scoped; attaches per-container libssl on this node — set peer_ip/peer_cidr in FLOW_FILTER_RULES to narrow")
		}
		attacher, err := AttachOpenSSLUprobes(scope, opensslPath, progs.ProbeEntrySSLWrite, progs.ProbeEntrySSLRead, progs.ProbeRetSSLRead, progs.ProbeEntrySSLSetFd)
		if err != nil {
			result.Close()
			return nil, fmt.Errorf("attaching OpenSSL uprobes: %w", err)
		}
		result.OpensslAttacher = attacher
		olog.Infof("OpenSSL TLS plaintext capture enabled (OPENSSL_PATH=%s)", opensslPath)
	}

	return result, nil
}

func (t *PacketFetcherTLS) Close() {
	if t == nil {
		return
	}
	if t.SSLReader != nil {
		_ = t.SSLReader.Close()
	}
	if t.OpensslAttacher != nil {
		t.OpensslAttacher.Close()
	}
}

func TLSMapSizing(spec *cilium.CollectionSpec, enableOpenSSL bool) {
	minEntries := uint32(os.Getpagesize())
	if !TLSPlaintextEnabled(enableOpenSSL) {
		spec.Maps[ebpfflows.BpfMapSslDataEventMap].MaxEntries = minEntries
	}
}
