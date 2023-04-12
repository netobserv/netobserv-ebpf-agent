package flow

import (
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
)

func (c *CapacityLimiter) PerfLimit(in <-chan []*ebpf.BpfSockEventT, out chan<- []*ebpf.BpfSockEventT) {
	go c.logDroppedFlows()
	for i := range in {
		if len(out) < cap(out) || cap(out) == 0 {
			out <- i
		} else {
			c.droppedFlows += len(i)
		}
	}
}
