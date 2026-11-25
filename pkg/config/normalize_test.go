package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalize(t *testing.T) {
	// Based on CacheMaxFlows
	cfg := &Agent{Common: Common{CacheMaxFlows: 100}}
	cfg.Normalize(8)

	assert.Equal(t, 20, cfg.CacheMaxDNSFlows)
	assert.Equal(t, 50, cfg.CacheMaxQUICFlows)
	// per-CPU maps: 100 / 8 CPUs
	assert.Equal(t, 12, cfg.CacheMaxNetworkEventFlows)
	assert.Equal(t, 12, cfg.CacheMaxPktDropsFlows)
	assert.Equal(t, 12, cfg.CacheMaxXlatFlows)
	assert.Equal(t, 12, cfg.CacheMaxAdditionalFlows)

	// Single CPU
	cfg = &Agent{Common: Common{CacheMaxFlows: 100}}
	cfg.Normalize(1)

	assert.Equal(t, 100, cfg.CacheMaxNetworkEventFlows)
	assert.Equal(t, 100, cfg.CacheMaxPktDropsFlows)
	assert.Equal(t, 100, cfg.CacheMaxXlatFlows)
	assert.Equal(t, 100, cfg.CacheMaxAdditionalFlows)

	// Invalid CPU count is treated as a single CPU
	cfg = &Agent{Common: Common{CacheMaxFlows: 100}}
	cfg.Normalize(0)

	assert.Equal(t, 100, cfg.CacheMaxNetworkEventFlows)
	assert.Equal(t, 100, cfg.CacheMaxPktDropsFlows)
	assert.Equal(t, 100, cfg.CacheMaxXlatFlows)
	assert.Equal(t, 100, cfg.CacheMaxAdditionalFlows)

	// Too small CacheMaxFlows
	cfg = &Agent{Common: Common{CacheMaxFlows: 1}}
	cfg.Normalize(64)

	assert.Equal(t, 1, cfg.CacheMaxDNSFlows)
	assert.Equal(t, 1, cfg.CacheMaxQUICFlows)
	assert.Equal(t, 1, cfg.CacheMaxNetworkEventFlows)
	assert.Equal(t, 1, cfg.CacheMaxPktDropsFlows)
	assert.Equal(t, 1, cfg.CacheMaxXlatFlows)
	assert.Equal(t, 1, cfg.CacheMaxAdditionalFlows)

	// Not based on CacheMaxFlows
	cfg = &Agent{Common: Common{
		CacheMaxFlows:             100,
		CacheMaxAdditionalFlows:   200,
		CacheMaxDNSFlows:          300,
		CacheMaxNetworkEventFlows: 400,
		CacheMaxXlatFlows:         500,
		CacheMaxPktDropsFlows:     600,
		CacheMaxQUICFlows:         700,
	}}
	cfg.Normalize(8)

	assert.Equal(t, 200, cfg.CacheMaxAdditionalFlows)
	assert.Equal(t, 300, cfg.CacheMaxDNSFlows)
	assert.Equal(t, 400, cfg.CacheMaxNetworkEventFlows)
	assert.Equal(t, 500, cfg.CacheMaxXlatFlows)
	assert.Equal(t, 600, cfg.CacheMaxPktDropsFlows)
	assert.Equal(t, 700, cfg.CacheMaxQUICFlows)
}
