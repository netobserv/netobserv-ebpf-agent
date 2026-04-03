package networkevents

import (
	"testing"

	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	ovnmodel "github.com/ovn-org/ovn-kubernetes/go-controller/observability-lib/model"
	"github.com/stretchr/testify/assert"
)

func TestMapToStrings(t *testing.T) {
	flow := config.GenericMap{
		"NetworkEvents": []map[string]string{
			ToMap(&ovnmodel.ACLEvent{
				Action:    "allow",
				Actor:     "EgressFirewall",
				Name:      "policy-1",
				Namespace: "ns-1",
				Direction: "Egress",
			}),
			ToMap(&ovnmodel.ACLEvent{
				Action:    "drop",
				Actor:     "NetworkPolicy",
				Name:      "policy-2",
				Namespace: "ns-2",
				Direction: "Ingress",
			}),
		},
	}
	asStrings := MapToStrings(flow)
	assert.Equal(t, []string{
		"Allowed by egress firewall in namespace ns-1",
		"Dropped by network policy policy-2 in namespace ns-2, direction Ingress",
	}, asStrings)
}

func TestMapToStringsUnstructured(t *testing.T) {
	// This test simulates an unstructured flow, as if read from Loki by the web console
	ne1 := map[string]any{}
	ne2 := map[string]any{}
	for k, v := range ToMap(&ovnmodel.ACLEvent{
		Action:    "allow",
		Actor:     "EgressFirewall",
		Name:      "policy-1",
		Namespace: "ns-1",
		Direction: "Egress",
	}) {
		ne1[k] = v
	}
	for k, v := range ToMap(&ovnmodel.ACLEvent{
		Action:    "drop",
		Actor:     "NetworkPolicy",
		Name:      "policy-2",
		Namespace: "ns-2",
		Direction: "Ingress",
	}) {
		ne2[k] = v
	}
	asStrings := MapToStrings(config.GenericMap{"NetworkEvents": []any{ne1, ne2}})
	assert.Equal(t, []string{
		"Allowed by egress firewall in namespace ns-1",
		"Dropped by network policy policy-2 in namespace ns-2, direction Ingress",
	}, asStrings)
}

func TestNetworkEventsCauseConversions(t *testing.T) {
	code, isDrop := ToDropReasonCode(&ovnmodel.ACLEvent{
		Action:    "drop",
		Actor:     "EgressFirewall",
		Name:      "policy-1",
		Namespace: "ns-1",
		Direction: "Egress",
	})
	assert.Equal(t, uint32(0x1000001), code)
	assert.True(t, isDrop)
	assert.Equal(t, "EgressFirewall", DropReasonCodeToString(0x1000001))

	code, isDrop = ToDropReasonCode(&ovnmodel.ACLEvent{
		Action:    "allow",
		Actor:     "AdminNetworkPolicy",
		Name:      "policy-1",
		Namespace: "ns-1",
		Direction: "Ingress",
	})
	assert.Equal(t, uint32(0), code)
	assert.False(t, isDrop)

	code, isDrop = ToDropReasonCode(&ovnmodel.ACLEvent{
		Action:    "drop",
		Actor:     "NetworkPolicy",
		Name:      "policy-1",
		Namespace: "ns-1",
		Direction: "Ingress",
	})
	assert.Equal(t, uint32(0x1000004), code)
	assert.True(t, isDrop)
	assert.Equal(t, "NetworkPolicy", DropReasonCodeToString(0x1000004))

	code, isDrop = ToDropReasonCode(&ovnmodel.ACLEvent{
		Action:    "drop",
		Actor:     "UDNIsolation",
		Name:      "policy-1",
		Namespace: "ns-1",
		Direction: "Ingress",
	})
	assert.Equal(t, uint32(0x1000009), code)
	assert.True(t, isDrop)
	assert.Equal(t, "UDNIsolation", DropReasonCodeToString(0x1000009))

	code, isDrop = ToDropReasonCode(&ovnmodel.ACLEvent{
		Action:    "drop",
		Actor:     "???",
		Name:      "policy-1",
		Namespace: "ns-1",
		Direction: "Ingress",
	})
	assert.Equal(t, uint32(0x1000000), code)
	assert.True(t, isDrop)
	assert.Equal(t, "Unknown", DropReasonCodeToString(0x1000000))
}
