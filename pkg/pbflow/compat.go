//nolint:revive // Names mirror protobuf-generated symbols.
package pbflow

import flowpb "github.com/netobserv/netobserv-ebpf-agent/pkg/pb/flow"

// Deprecated: import github.com/netobserv/netobserv-ebpf-agent/pkg/pb/flow instead.
// Kept for flowlogs-pipeline v1.11.5-community compatibility until FLP is updated.

type (
	CollectorClient              = flowpb.CollectorClient
	CollectorReply               = flowpb.CollectorReply
	CollectorServer              = flowpb.CollectorServer
	DataLink                     = flowpb.DataLink
	Direction                    = flowpb.Direction
	DupMapEntry                  = flowpb.DupMapEntry
	IP                           = flowpb.IP
	IP_Ipv4                      = flowpb.IP_Ipv4
	IP_Ipv6                      = flowpb.IP_Ipv6
	Network                      = flowpb.Network
	NetworkEvent                 = flowpb.NetworkEvent
	Quic                         = flowpb.Quic
	Record                       = flowpb.Record
	Records                      = flowpb.Records
	Transport                    = flowpb.Transport
	UnimplementedCollectorServer = flowpb.UnimplementedCollectorServer
	UnsafeCollectorServer        = flowpb.UnsafeCollectorServer
	Xlat                         = flowpb.Xlat
)

const (
	Direction_INGRESS = flowpb.Direction_INGRESS
	Direction_EGRESS  = flowpb.Direction_EGRESS
)

var (
	Direction_name  = flowpb.Direction_name
	Direction_value = flowpb.Direction_value

	FlowToPB                = flowpb.FlowToPB
	FlowsToPB               = flowpb.FlowsToPB
	NewCollectorClient      = flowpb.NewCollectorClient
	PBToFlow                = flowpb.PBToFlow
	RegisterCollectorServer = flowpb.RegisterCollectorServer
)
