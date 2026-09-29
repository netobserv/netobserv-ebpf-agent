package flows

import (
	"os"
	"testing"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/internal/netattach"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hasCastToKernCtx() bool {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return false
	}
	var fn *btf.Func
	return spec.TypeByName("bpf_cast_to_kern_ctx", &fn) == nil
}

// The TC programs must read the namespace of the *device* via the bpf_cast_to_kern_ctx kfunc.
// They must NOT use bpf_get_netns_cookie: for sched_cls that helper returns the cookie of skb->sk
// and falls back to init_net when there is no socket, which is always the case on ingress, so pod
// interfaces would be attributed to the host namespace.
func TestNetNSCookieUsesDeviceNamespace(t *testing.T) {
	spec, err := ebpf.LoadFlowsBpf()
	require.NoError(t, err)

	for _, name := range []string{ebpf.FlowsBpfProgTcIngressFlowParse, ebpf.FlowsBpfProgTcEgressFlowParse} {
		prog := spec.Programs[name]
		require.NotNil(t, prog, name)

		castCalls, helperCalls, lookupCalls := 0, 0, 0
		for i := range prog.Instructions {
			ins := &prog.Instructions[i]
			switch {
			case ins.IsKfuncCall() && ins.Reference() == "bpf_cast_to_kern_ctx":
				castCalls++
			case !ins.IsBuiltinCall():
			case asm.BuiltinFunc(ins.Constant) == asm.FnGetNetnsCookie:
				helperCalls++
			case asm.BuiltinFunc(ins.Constant) == asm.FnMapLookupElem:
				lookupCalls++
			}
		}
		// bpf_map_lookup_elem is unconditionally called by flow_monitor. If we stop seeing it,
		// helper detection itself has broken and the bpf_get_netns_cookie check below is a no-op.
		require.Positive(t, lookupCalls, "%s: helper call detection is broken", name)
		assert.Zero(t, helperCalls,
			"%s must not call bpf_get_netns_cookie (returns skb->sk's namespace, not the device's)", name)
		assert.Positive(t, castCalls, "%s should reach the device namespace via bpf_cast_to_kern_ctx", name)
	}
}

// The netns cookie is read with bpf_cast_to_kern_ctx (a weak kfunc) followed by CO-RE reads of
// net_device.nd_net and net.net_cookie. Two things can only be proven by a real verifier load:
//
//   - gate on: the kfunc is actually callable from a sched_cls program and the CO-RE reads relocate
//   - gate off: the poisoned kfunc call is dead-code-eliminated, so kernels lacking it still load
//
// Run with NETOBSERV_PRIVILEGED_TESTS=1 in a privileged container.
func TestNetNSCookieProgramLoads(t *testing.T) {
	if os.Getenv("NETOBSERV_PRIVILEGED_TESTS") != "1" {
		t.Skip("requires BPF privileges; set NETOBSERV_PRIVILEGED_TESTS=1")
	}
	require.NoError(t, rlimit.RemoveMemlock())

	for _, tc := range []struct {
		name    string
		enabled uint8
	}{
		{name: "gate-off", enabled: 0},
		{name: "gate-on", enabled: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.enabled == 1 && !hasCastToKernCtx() {
				t.Skip("kernel has no BTF for bpf_cast_to_kern_ctx; the agent disables the feature here")
			}
			spec, err := ebpf.LoadFlowsBpf()
			require.NoError(t, err)

			// Keep only the TC programs: they are the ones reading the cookie, and the rest
			// need tracing hooks that are not guaranteed on every test host.
			for name := range spec.Programs {
				if name != ebpf.FlowsBpfProgTcIngressFlowParse && name != ebpf.FlowsBpfProgTcEgressFlowParse {
					delete(spec.Programs, name)
				}
			}
			// Several maps are declared PinByName, which would need a bpffs path. Pinning is
			// irrelevant here: we only care that the verifier accepts the programs.
			for name := range spec.Maps {
				spec.Maps[name].Pinning = cilium.PinNone
			}
			require.NoError(t, netattach.SetVariable(spec, ebpf.FlowsBpfVarEnableNetnsCookie, tc.enabled))

			coll, err := cilium.NewCollection(spec)
			require.NoError(t, err, "loading the flow programs with enable_netns_cookie=%d failed", tc.enabled)
			t.Cleanup(coll.Close)

			for _, name := range []string{ebpf.FlowsBpfProgTcIngressFlowParse, ebpf.FlowsBpfProgTcEgressFlowParse} {
				prog := coll.Programs[name]
				if assert.NotNil(t, prog, name) {
					_, err := prog.Info()
					assert.NoError(t, err, name)
				}
			}
		})
	}
}
