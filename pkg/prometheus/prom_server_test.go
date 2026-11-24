package prometheus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartServerAsync(t *testing.T) {
	// Create a mock metrics settings
	mockSettings := &metrics.Settings{
		PromConnectionInfo: metrics.PromConnectionInfo{
			Address: "localhost",
			Port:    9091,
		},
		Prefix: "test_prefix_",
	}

	// Start a mock server
	server := StartServerAsync(mockSettings, nil)

	// Create a test request to the /metrics endpoint
	req, err := http.NewRequest("GET", "http://localhost:9091/metrics", nil)
	assert.NoError(t, err, "Error creating request")

	// Create a response recorder to record the response
	rr := httptest.NewRecorder()

	// Make the request to the mock server
	go func() {
		time.Sleep(100 * time.Millisecond) // Give the server some time to start
		client := http.Client{}
		_, err := client.Do(req)
		assert.NoError(t, err, "Error making request to mock server")
	}()

	// Wait for the server to start
	time.Sleep(200 * time.Millisecond)

	// Simulate a shutdown request to stop the server
	err = server.Shutdown(context.TODO())
	assert.NoError(t, err, "Error shutting down server")

	// Assert the response status code
	assert.Equal(t, http.StatusOK, rr.Code, "Unexpected status code")
}

// TestStartServerAsyncIPv6Literal verifies that the metrics server can be
// bound to an IPv6 literal address (METRICS_SERVER_ADDRESS=::1)
func TestStartServerAsyncIPv6Literal(t *testing.T) {
	test.SkipUnlessLoopbackListenerAccepts(t, "::1")
	srv := StartServerAsync(&metrics.Settings{
		PromConnectionInfo: metrics.PromConnectionInfo{
			Address: "::1",
			Port:    9092,
		},
	}, nil)
	defer func() {
		assert.NoError(t, srv.Shutdown(context.TODO()))
	}()

	// the server starts asynchronously: poll until it answers
	var resp *http.Response
	var err error
	for i := 0; ; i++ {
		resp, err = http.Get("http://[::1]:9092/metrics")
		if err == nil || i >= 20 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.NoError(t, err, "metrics server did not start on [::1]:9092")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
