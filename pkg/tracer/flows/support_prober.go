package flows

import (
	"errors"

	"github.com/cilium/ebpf"
	ebpfflows "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
)

// probeBpfLockSupport must be called on an empty map to detect whether LookupLock is supported.
// It calls LookupAndDeleteWithFlags, and not just LookupWithFlags, because they support different kernel versions.
// When supported, LookupLock is used to better ensure consistency in case of unlikely race between userspace lookup and kernel updates.
func probeBpfLockSupport(aggregatedFlowMap *ebpf.Map) ebpf.MapLookupFlags {
	var id ebpfflows.FlowsBpfFlowId
	var baseMetrics ebpfflows.FlowsBpfFlowMetrics
	// That key (0 values) doesn't exist, so we expect to get the error ebpf.ErrKeyNotExist
	// ... unless LookupLock is not supported, in which case we get EINVAL
	err := aggregatedFlowMap.LookupAndDeleteWithFlags(&id, &baseMetrics, ebpf.LookupLock)
	switch {
	case errors.Is(err, ebpf.ErrKeyNotExist):
		// Expected error, lookup is supported
		return ebpf.LookupLock
	case err == nil:
		// Most unlikely case: no error, which means both of 1. map isn't empty (running through bpfman?)
		// and 2. there's a flow with all 5 tuples being 0 => quite unexpected
		// Anyway, let's restore it.
		if uerr := aggregatedFlowMap.Update(&id, &baseMetrics, ebpf.UpdateNoExist); uerr != nil {
			log.WithError(uerr).Debug("could not restore the entry removed while probing BPF_F_LOCK")
		}
		// Still, it worked, meaning that LookupLock is supported
		return ebpf.LookupLock
	default:
		// Another error is considered as LookupLock unsupported
		log.WithError(err).Info("BPF_F_LOCK unsupported for lookup-and-delete; reads won't take the value lock")
		return 0
	}
}
