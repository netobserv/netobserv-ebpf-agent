package ebpf

// Shared BPF map and variable names used by both flow and packet objects.

const (
	BpfMapFilterMap      = "filter_map"
	BpfMapGlobalCounters = "global_counters"
	BpfMapPeerFilterMap  = "peer_filter_map"

	BpfVarEnableFiltering      = "enable_filtering"
	BpfVarEnableFlowsFiltering = "enable_filtering" // deprecated alias
	BpfVarFilterKey            = "filter_key"
	BpfVarFilterValue          = "filter_value"
	BpfVarHasFilterSampling    = "has_filter_sampling"
	BpfVarSampling             = "sampling"
	BpfVarTraceMessages        = "trace_messages"
)
