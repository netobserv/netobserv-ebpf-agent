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

func TestNormalize(t *testing.T) {
	// Based on CacheMaxFlows
	cfg := &Agent{Common: Common{CacheMaxFlows: 100}}
	cfg.Normalize()

	assert.Equal(t, 100, cfg.CacheMaxAdditionalFlows)
	assert.Equal(t, 10, cfg.CacheMaxDNSFlows)
	assert.Equal(t, 50, cfg.CacheMaxNetworkEventFlows)
	assert.Equal(t, 50, cfg.CacheMaxXlatFlows)
	assert.Equal(t, 50, cfg.CacheMaxPktDropsFlows)

	// Too small CacheMaxFlows
	cfg = &Agent{Common: Common{CacheMaxFlows: 1}}
	cfg.Normalize()

	assert.Equal(t, 1, cfg.CacheMaxAdditionalFlows)
	assert.Equal(t, 1, cfg.CacheMaxDNSFlows)
	assert.Equal(t, 1, cfg.CacheMaxNetworkEventFlows)
	assert.Equal(t, 1, cfg.CacheMaxXlatFlows)
	assert.Equal(t, 1, cfg.CacheMaxPktDropsFlows)

	// Not based on CacheMaxFlows
	cfg = &Agent{Common: Common{
		CacheMaxFlows:             100,
		CacheMaxAdditionalFlows:   200,
		CacheMaxDNSFlows:          300,
		CacheMaxNetworkEventFlows: 400,
		CacheMaxXlatFlows:         500,
		CacheMaxPktDropsFlows:     600,
	}}
	cfg.Normalize()

	assert.Equal(t, 200, cfg.CacheMaxAdditionalFlows)
	assert.Equal(t, 300, cfg.CacheMaxDNSFlows)
	assert.Equal(t, 400, cfg.CacheMaxNetworkEventFlows)
	assert.Equal(t, 500, cfg.CacheMaxXlatFlows)
	assert.Equal(t, 600, cfg.CacheMaxPktDropsFlows)
}
