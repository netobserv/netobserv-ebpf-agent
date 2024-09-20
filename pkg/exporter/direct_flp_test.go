package exporter

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDirectFLP_ExportFlows(t *testing.T) {
	// Start DirectFLP exporter stage
	// Create a FLP config with just stdout write
	// Ingest stage must be omitted
	flp, err := StartDirectFLP(`
log-level: debug
pipeline:
  - name: writer
    follows: preset-ingester
parameters:
  - name: writer
    write:
      type: stdout
      stdout:
        format: json
`, 50)
	require.NoError(t, err)
	defer flp.Close()

	// start capture
	capturedOut, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	defer func() {
		os.Stdout = old
	}()

	// Send some flows to the input of the exporter stage
	flows := make(chan []*model.Record, 10)
	go flp.ExportFlows(flows)
	flows <- []*model.Record{
		{AgentIP: net.ParseIP("10.9.8.7")},
	}

	// Read capture
	time.Sleep(10 * time.Millisecond)
	scanner := bufio.NewScanner(capturedOut)
	require.True(t, scanner.Scan())
	capturedRecord := map[string]interface{}{}
	bytes := scanner.Bytes()
	require.NoError(t, json.Unmarshal(bytes, &capturedRecord), string(bytes))

	assert.NotZero(t, capturedRecord["TimeReceived"])
	assert.Equal(t, "10.9.8.7", capturedRecord["AgentIP"])
}
