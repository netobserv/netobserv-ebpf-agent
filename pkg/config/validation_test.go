package config

import (
	"testing"

	"github.com/caarlos0/env/v11"
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
	require.NoError(t, env.ParseWithOptions(cfg, env.Options{Environment: map[string]string{}}))
	require.NoError(t, cfg.ValidateForFlows())

	cfg.Packets.EnablePCA = true
	err := cfg.ValidateForFlows()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ENABLE_PCA")
}

func TestEndpointMapMaxEntries(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        uint32
		parseError  bool
		valid       bool
	}{
		{name: "default", want: 1048576, valid: true},
		{name: "custom", value: "4096", want: 4096, valid: true},
		{name: "minimum", value: "1", want: 1, valid: true},
		{name: "zero", value: "0"},
		{name: "negative", value: "-1", parseError: true},
		{name: "overflow", value: "4294967296", parseError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			environ := map[string]string{}
			if tc.value != "" {
				environ["ENDPOINT_MAP_MAX_ENTRIES"] = tc.value
			}
			var cfg Agent
			err := env.ParseWithOptions(&cfg, env.Options{Environment: environ})
			if tc.parseError {
				require.ErrorContains(t, err, "EndpointMapMaxEntries")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, cfg.Flows.EndpointMapMaxEntries)
			if tc.valid {
				require.NoError(t, cfg.ValidateForFlows())
			} else {
				require.ErrorContains(t, cfg.ValidateForFlows(), "ENDPOINT_MAP_MAX_ENTRIES")
			}
		})
	}
}
