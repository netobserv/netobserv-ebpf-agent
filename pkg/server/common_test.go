package server

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/tlsprofile"
	"github.com/stretchr/testify/assert"
)

func TestDefault_AppliesTLSProfileOverrides(t *testing.T) {
	t.Setenv(tlsprofile.EnvMinVersion, "771")
	t.Setenv(tlsprofile.EnvCipherSuites, "4865,4866")
	t.Setenv(tlsprofile.EnvCurvePreferences, "23,24")

	srv := Default(&http.Server{})

	assert.Equal(t, uint16(tls.VersionTLS12), srv.TLSConfig.MinVersion)
	assert.Equal(t, []uint16{4865, 4866}, srv.TLSConfig.CipherSuites)
	assert.Equal(t, []tls.CurveID{tls.CurveP256, tls.CurveP384}, srv.TLSConfig.CurvePreferences)
}

func TestDefault_NoOverridesKeepsSecureDefaultMinVersion(t *testing.T) {
	srv := Default(&http.Server{})

	assert.Equal(t, uint16(tls.VersionTLS13), srv.TLSConfig.MinVersion)
	assert.Empty(t, srv.TLSConfig.CipherSuites)
	assert.Empty(t, srv.TLSConfig.CurvePreferences)
}

func TestDefault_InvalidOverrideKeepsSecureDefaults(t *testing.T) {
	// One invalid value among an otherwise valid profile must not result in
	// a partially-applied TLS config: the secure defaults should be kept as-is.
	t.Setenv(tlsprofile.EnvMinVersion, "not-a-number")
	t.Setenv(tlsprofile.EnvCipherSuites, "4865,4866")

	srv := Default(&http.Server{})

	assert.Equal(t, uint16(tls.VersionTLS13), srv.TLSConfig.MinVersion)
	assert.Empty(t, srv.TLSConfig.CipherSuites)
	assert.Empty(t, srv.TLSConfig.CurvePreferences)
}
