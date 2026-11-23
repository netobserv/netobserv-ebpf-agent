package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateForPackets(t *testing.T) {
	cfg := &Agent{}
	require.NoError(t, cfg.ValidateForPackets())

	cfg.Flows.EnableDNSTracking = true
	err := cfg.ValidateForPackets()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ENABLE_DNS_TRACKING")
}

func TestValidateForFlows(t *testing.T) {
	cfg := &Agent{}
	require.NoError(t, cfg.ValidateForFlows())

	cfg.Packets.EnablePCA = true
	err := cfg.ValidateForFlows()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ENABLE_PCA")
}
