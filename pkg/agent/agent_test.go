package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlowsAgent_InvalidConfigs(t *testing.T) {
	for _, tc := range []struct {
		d string
		c Config
	}{{
		d: "invalid export type",
		c: Config{Export: "foo"},
	}, {
		d: "GRPC: missing host",
		c: Config{Export: "grpc", TargetPort: 3333},
	}, {
		d: "GRPC: missing port",
		c: Config{Export: "grpc", TargetHost: "flp"},
	}, {
		d: "Kafka: missing brokers",
		c: Config{Export: "kafka"},
	}} {
		t.Run(tc.d, func(t *testing.T) {
			_, err := FlowsAgent(&tc.c)
			assert.Error(t, err)
		})
	}
}
