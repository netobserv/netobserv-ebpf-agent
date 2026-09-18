package flows

import (
	"fmt"
	"strings"
)

// Validate rejects flow-only options when packet capture mode is selected.
func Validate(f *Features) error {
	var incompatible []string
	if f.EnableDNSTracking {
		incompatible = append(incompatible, "ENABLE_DNS_TRACKING")
	}
	if f.EnableRTT {
		incompatible = append(incompatible, "ENABLE_RTT")
	}
	if f.EnablePktDrops {
		incompatible = append(incompatible, "ENABLE_PKT_DROPS")
	}
	if f.EnableNetworkEventsMonitoring {
		incompatible = append(incompatible, "ENABLE_NETWORK_EVENTS_MONITORING")
	}
	if f.EnablePktTranslationTracking {
		incompatible = append(incompatible, "ENABLE_PKT_TRANSLATION")
	}
	if f.EnableUDNMapping {
		incompatible = append(incompatible, "ENABLE_UDN_MAPPING")
	}
	if f.EnableIPsecTracking {
		incompatible = append(incompatible, "ENABLE_IPSEC_TRACKING")
	}
	if f.EnableTLSTracking {
		incompatible = append(incompatible, "ENABLE_TLS_TRACKING")
	}
	if f.QUICTrackingMode != 0 {
		incompatible = append(incompatible, "QUIC_TRACKING_MODE")
	}
	if f.EnableFlowsRingbufFallback {
		incompatible = append(incompatible, "ENABLE_FLOWS_RINGBUF_FALLBACK")
	}
	if len(incompatible) > 0 {
		return fmt.Errorf(
			"packet capture mode (ENABLE_PCA=true) does not support: %s",
			strings.Join(incompatible, ", "),
		)
	}
	return nil
}
