//nolint:revive // Names mirror bpf2go-generated BPF object symbols.
package ebpf

import (
	ciliumebpf "github.com/cilium/ebpf"
	bpfflows "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
)

// Flow BPF types — re-exported from pkg/ebpf/flows for backward compatibility.
// New code should import github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows directly.

type (
	BpfAdditionalMetrics     = bpfflows.BpfAdditionalMetrics
	BpfDirectionT            = bpfflows.BpfDirectionT
	BpfDnsFlowId             = bpfflows.BpfDnsFlowId
	BpfDnsMetrics            = bpfflows.BpfDnsMetrics
	BpfDnsMetricsT           = bpfflows.BpfDnsMetricsT
	BpfDnsNameBuffer         = bpfflows.BpfDnsNameBuffer
	BpfFilterActionT         = bpfflows.BpfFilterActionT
	BpfFilterKeyT            = bpfflows.BpfFilterKeyT
	BpfFilterValueT          = bpfflows.BpfFilterValueT
	BpfFlowId                = bpfflows.BpfFlowId
	BpfFlowIdT               = bpfflows.BpfFlowIdT
	BpfFlowMetrics           = bpfflows.BpfFlowMetrics
	BpfFlowMetricsT          = bpfflows.BpfFlowMetricsT
	BpfFlowRecordT           = bpfflows.BpfFlowRecordT
	BpfGlobalCountersKeyT    = bpfflows.BpfGlobalCountersKeyT
	BpfNetworkEventsMetrics  = bpfflows.BpfNetworkEventsMetrics
	BpfNetworkEventsMetricsT = bpfflows.BpfNetworkEventsMetricsT
	BpfPktDropMetrics        = bpfflows.BpfPktDropMetrics
	BpfPktDropMetricsT       = bpfflows.BpfPktDropMetricsT
	BpfQuicConfigT           = bpfflows.BpfQuicConfigT
	BpfQuicMetrics           = bpfflows.BpfQuicMetrics
	BpfQuicMetricsT          = bpfflows.BpfQuicMetricsT
	BpfSslDataEventT         = bpfflows.BpfSslDataEventT
	BpfTcpFlagsT             = bpfflows.BpfTcpFlagsT
	BpfXlatMetrics           = bpfflows.BpfXlatMetrics
	BpfXlatMetricsT          = bpfflows.BpfXlatMetricsT
	BpfSpecs                 = bpfflows.BpfSpecs
	BpfProgramSpecs          = bpfflows.BpfProgramSpecs
	BpfMapSpecs              = bpfflows.BpfMapSpecs
	BpfVariableSpecs         = bpfflows.BpfVariableSpecs
	BpfObjects               = bpfflows.BpfObjects
	BpfMaps                  = bpfflows.BpfMaps
	BpfVariables             = bpfflows.BpfVariables
	BpfPrograms              = bpfflows.BpfPrograms
)

const (
	BpfDirectionTINGRESS       = bpfflows.BpfDirectionTINGRESS
	BpfDirectionTEGRESS        = bpfflows.BpfDirectionTEGRESS
	BpfDirectionTMAX_DIRECTION = bpfflows.BpfDirectionTMAX_DIRECTION

	BpfFilterActionTACCEPT             = bpfflows.BpfFilterActionTACCEPT
	BpfFilterActionTREJECT             = bpfflows.BpfFilterActionTREJECT
	BpfFilterActionTMAX_FILTER_ACTIONS = bpfflows.BpfFilterActionTMAX_FILTER_ACTIONS

	BpfGlobalCountersKeyTHASHMAP_FAIL_UPDATE_FLOW            = bpfflows.BpfGlobalCountersKeyTHASHMAP_FAIL_UPDATE_FLOW
	BpfGlobalCountersKeyTHASHMAP_FAIL_CREATE_FLOW            = bpfflows.BpfGlobalCountersKeyTHASHMAP_FAIL_CREATE_FLOW
	BpfGlobalCountersKeyTHASHMAP_FAIL_UPDATE_DNS             = bpfflows.BpfGlobalCountersKeyTHASHMAP_FAIL_UPDATE_DNS
	BpfGlobalCountersKeyTFILTER_REJECT                       = bpfflows.BpfGlobalCountersKeyTFILTER_REJECT
	BpfGlobalCountersKeyTFILTER_ACCEPT                       = bpfflows.BpfGlobalCountersKeyTFILTER_ACCEPT
	BpfGlobalCountersKeyTFILTER_NOMATCH                      = bpfflows.BpfGlobalCountersKeyTFILTER_NOMATCH
	BpfGlobalCountersKeyTNETWORK_EVENTS_ERR                  = bpfflows.BpfGlobalCountersKeyTNETWORK_EVENTS_ERR
	BpfGlobalCountersKeyTNETWORK_EVENTS_ERR_GROUPID_MISMATCH = bpfflows.BpfGlobalCountersKeyTNETWORK_EVENTS_ERR_GROUPID_MISMATCH
	BpfGlobalCountersKeyTNETWORK_EVENTS_ERR_UPDATE_MAP_FLOWS = bpfflows.BpfGlobalCountersKeyTNETWORK_EVENTS_ERR_UPDATE_MAP_FLOWS
	BpfGlobalCountersKeyTNETWORK_EVENTS_GOOD                 = bpfflows.BpfGlobalCountersKeyTNETWORK_EVENTS_GOOD
	BpfGlobalCountersKeyTNETWORK_EVENTS_OVERFLOW             = bpfflows.BpfGlobalCountersKeyTNETWORK_EVENTS_OVERFLOW
	BpfGlobalCountersKeyTNETWORK_EVENTS_COOKIE_TOO_BIG       = bpfflows.BpfGlobalCountersKeyTNETWORK_EVENTS_COOKIE_TOO_BIG
	BpfGlobalCountersKeyTOBSERVED_INTF_MISSED                = bpfflows.BpfGlobalCountersKeyTOBSERVED_INTF_MISSED
	BpfGlobalCountersKeyTMAX_COUNTERS                        = bpfflows.BpfGlobalCountersKeyTMAX_COUNTERS

	BpfQuicConfigTQUIC_CONFIG_DISABLED     = bpfflows.BpfQuicConfigTQUIC_CONFIG_DISABLED
	BpfQuicConfigTQUIC_CONFIG_ENABLED      = bpfflows.BpfQuicConfigTQUIC_CONFIG_ENABLED
	BpfQuicConfigTQUIC_CONFIG_ANY_UDP_PORT = bpfflows.BpfQuicConfigTQUIC_CONFIG_ANY_UDP_PORT

	BpfTcpFlagsTFIN_FLAG     = bpfflows.BpfTcpFlagsTFIN_FLAG
	BpfTcpFlagsTSYN_FLAG     = bpfflows.BpfTcpFlagsTSYN_FLAG
	BpfTcpFlagsTRST_FLAG     = bpfflows.BpfTcpFlagsTRST_FLAG
	BpfTcpFlagsTPSH_FLAG     = bpfflows.BpfTcpFlagsTPSH_FLAG
	BpfTcpFlagsTACK_FLAG     = bpfflows.BpfTcpFlagsTACK_FLAG
	BpfTcpFlagsTURG_FLAG     = bpfflows.BpfTcpFlagsTURG_FLAG
	BpfTcpFlagsTECE_FLAG     = bpfflows.BpfTcpFlagsTECE_FLAG
	BpfTcpFlagsTCWR_FLAG     = bpfflows.BpfTcpFlagsTCWR_FLAG
	BpfTcpFlagsTSYN_ACK_FLAG = bpfflows.BpfTcpFlagsTSYN_ACK_FLAG
	BpfTcpFlagsTFIN_ACK_FLAG = bpfflows.BpfTcpFlagsTFIN_ACK_FLAG
	BpfTcpFlagsTRST_ACK_FLAG = bpfflows.BpfTcpFlagsTRST_ACK_FLAG
)

// Flow BPF map, program, and variable names.
const (
	BpfMapAdditionalFlowMetrics        = bpfflows.BpfMapAdditionalFlowMetrics
	BpfMapAggregatedFlows              = bpfflows.BpfMapAggregatedFlows
	BpfMapAggregatedFlowsDns           = bpfflows.BpfMapAggregatedFlowsDns
	BpfMapAggregatedFlowsNetworkEvents = bpfflows.BpfMapAggregatedFlowsNetworkEvents
	BpfMapAggregatedFlowsPktDrop       = bpfflows.BpfMapAggregatedFlowsPktDrop
	BpfMapAggregatedFlowsXlat          = bpfflows.BpfMapAggregatedFlowsXlat
	BpfMapDirectFlows                  = bpfflows.BpfMapDirectFlows
	BpfMapDnsFlows                     = bpfflows.BpfMapDnsFlows
	BpfMapDnsNameMap                   = bpfflows.BpfMapDnsNameMap
	BpfMapIpsecEgressMap               = bpfflows.BpfMapIpsecEgressMap
	BpfMapIpsecIngressMap              = bpfflows.BpfMapIpsecIngressMap
	BpfMapQuicFlows                    = bpfflows.BpfMapQuicFlows
	BpfMapSslDataEventMap              = bpfflows.BpfMapSslDataEventMap

	BpfProgKfreeSkb                = bpfflows.BpfProgKfreeSkb
	BpfProgNetkitPeerFlowParse     = bpfflows.BpfProgNetkitPeerFlowParse
	BpfProgNetkitPrimaryFlowParse  = bpfflows.BpfProgNetkitPrimaryFlowParse
	BpfProgNetworkEventsMonitoring = bpfflows.BpfProgNetworkEventsMonitoring
	BpfProgProbeEntrySSL_write     = bpfflows.BpfProgProbeEntrySSL_write
	BpfProgTcEgressFlowParse       = bpfflows.BpfProgTcEgressFlowParse
	BpfProgTcIngressFlowParse      = bpfflows.BpfProgTcIngressFlowParse
	BpfProgTcpRcvFentry            = bpfflows.BpfProgTcpRcvFentry
	BpfProgTcpRcvKprobe            = bpfflows.BpfProgTcpRcvKprobe
	BpfProgTcxEgressFlowParse      = bpfflows.BpfProgTcxEgressFlowParse
	BpfProgTcxIngressFlowParse     = bpfflows.BpfProgTcxIngressFlowParse
	BpfProgTrackNatManipPkt        = bpfflows.BpfProgTrackNatManipPkt
	BpfProgXfrmInputKprobe         = bpfflows.BpfProgXfrmInputKprobe
	BpfProgXfrmInputKretprobe      = bpfflows.BpfProgXfrmInputKretprobe
	BpfProgXfrmOutputKprobe        = bpfflows.BpfProgXfrmOutputKprobe
	BpfProgXfrmOutputKretprobe     = bpfflows.BpfProgXfrmOutputKretprobe

	BpfVarDnsPort                        = bpfflows.BpfVarDnsPort
	BpfVarEnableDirectflowsRingbuf       = bpfflows.BpfVarEnableDirectflowsRingbuf
	BpfVarEnableDnsTracking              = bpfflows.BpfVarEnableDnsTracking
	BpfVarEnableIpsec                    = bpfflows.BpfVarEnableIpsec
	BpfVarEnableNetworkEventsMonitoring  = bpfflows.BpfVarEnableNetworkEventsMonitoring
	BpfVarEnableOpensslTracking          = bpfflows.BpfVarEnableOpensslTracking
	BpfVarEnablePktTranslationTracking   = bpfflows.BpfVarEnablePktTranslationTracking
	BpfVarEnableQuicTracking             = bpfflows.BpfVarEnableQuicTracking
	BpfVarEnableRtt                      = bpfflows.BpfVarEnableRtt
	BpfVarEnableTlsUsageTracking         = bpfflows.BpfVarEnableTlsUsageTracking
	BpfVarSslDataEvent                   = bpfflows.BpfVarSslDataEvent
	BpfVarNetworkEventsMonitoringGroupid = bpfflows.BpfVarNetworkEventsMonitoringGroupid
)

func LoadBpf() (*ciliumebpf.CollectionSpec, error) {
	return bpfflows.LoadBpf()
}

func LoadBpfObjects(obj interface{}, opts *ciliumebpf.CollectionOptions) error {
	return bpfflows.LoadBpfObjects(obj, opts)
}
