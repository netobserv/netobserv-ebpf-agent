package prometheus

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartServerAsync(t *testing.T) {
	mockSettings := &metrics.Settings{
		PromConnectionInfo: metrics.PromConnectionInfo{
			Address: "localhost",
			Port:    9091,
		},
		Prefix: "test_prefix_",
	}

	server, err := StartServerAsync(mockSettings, nil)
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { assert.NoError(t, server.Shutdown(context.TODO())) }()

	resp := getMetrics(t, "http://localhost:9091/metrics")
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	// The default registry always exposes the Go collector metrics.
	assert.Contains(t, string(body), "go_goroutines")
}

// TestStartServerAsync_InvalidAuth checks that a metrics server is never started when the
// requested authentication cannot be set up: it must fail rather than silently serve
// metrics unauthenticated.
func TestStartServerAsync_InvalidAuth(t *testing.T) {
	server, err := StartServerAsync(&metrics.Settings{
		PromConnectionInfo: metrics.PromConnectionInfo{
			Address: "localhost",
			Port:    9092,
			Auth:    &metrics.PromAuth{Type: "not-an-auth-type"},
		},
	}, nil)

	require.Error(t, err)
	assert.Nil(t, server)
	assert.Contains(t, err.Error(), "authentication")

	// Nothing is listening on the port.
	_, err = http.Get("http://localhost:9092/metrics")
	assert.Error(t, err)
}

// getMetrics polls the endpoint until the server goroutine has started listening.
func getMetrics(t *testing.T, url string) *http.Response {
	t.Helper()
	var resp *http.Response
	assert.Eventually(t, func() bool {
		r, err := http.Get(url)
		if err != nil {
			return false
		}
		resp = r
		return true
	}, 5*time.Second, 50*time.Millisecond, "metrics server never became reachable")
	require.NotNil(t, resp)
	return resp
}
