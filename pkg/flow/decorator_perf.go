package flow

import (
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
)

func PerfDecorate() func(in <-chan []*ebpf.BpfSockEventT, out chan<- []*ebpf.BpfSockEventT) {
	return func(in <-chan []*ebpf.BpfSockEventT, out chan<- []*ebpf.BpfSockEventT) {
		for flows := range in {
			out <- flows
		}
	}
}
