package flow

import (
	"net"
)

type InterfaceNamer func(ifIndex int) string

// Decorate adds to the flows extra metadata fields that are not directly fetched by eBPF:
// - The interface name (corresponding to the interface index in the flow).
// - The IP address of the agent host.
func Decorate(agentIP net.IP, ifaceNamer InterfaceNamer) func(in <-chan []*Record, out chan<- []*Record) {
	return func(in <-chan []*Record, out chan<- []*Record) {
		for flows := range in {
			for _, flow := range flows {
				flow.Interface = ifaceNamer(int(flow.Id.IfIndex))
				flow.AgentIP = agentIP
			}
			out <- flows
		}
	}
}
