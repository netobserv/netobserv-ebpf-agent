package flows

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	require.NoError(t, Validate(&Features{}))

	err := Validate(&Features{EnableDNSTracking: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ENABLE_DNS_TRACKING")
}

func TestValidateListsAllIncompatibleFlags(t *testing.T) {
	f := &Features{
		EnableDNSTracking:             true,
		EnableRTT:                     true,
		EnablePktDrops:                true,
		EnableNetworkEventsMonitoring: true,
		EnablePktTranslationTracking:  true,
		EnableUDNMapping:              true,
		EnableIPsecTracking:           true,
		EnableTLSTracking:             true,
		QUICTrackingMode:              1,
		EnableFlowsRingbufFallback:    true,
	}
	err := Validate(f)
	require.Error(t, err)
	for _, flag := range []string{
		"ENABLE_DNS_TRACKING",
		"ENABLE_RTT",
		"ENABLE_PKT_DROPS",
		"ENABLE_NETWORK_EVENTS_MONITORING",
		"ENABLE_PKT_TRANSLATION",
		"ENABLE_UDN_MAPPING",
		"ENABLE_IPSEC_TRACKING",
		"ENABLE_TLS_TRACKING",
		"QUIC_TRACKING_MODE",
		"ENABLE_FLOWS_RINGBUF_FALLBACK",
	} {
		assert.Contains(t, err.Error(), flag, "missing %s", flag)
	}
	assert.True(t, strings.Contains(err.Error(), "ENABLE_PCA=true"))
}
