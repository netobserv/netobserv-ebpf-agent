package prometheus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"

	"github.com/stretchr/testify/assert"
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
