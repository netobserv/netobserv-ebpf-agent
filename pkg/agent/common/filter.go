package common

import (
	"encoding/json"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer"
	"github.com/sirupsen/logrus"
)

var flog = logrus.WithField("component", "agent.common.Filter")

// FlowDirections returns whether ingress and/or egress hooks should be enabled.
func FlowDirections(cfg *config.Agent) (ingress, egress bool) {
	switch cfg.Direction {
	case config.DirectionIngress:
		return true, false
	case config.DirectionEgress:
		return false, true
	case config.DirectionBoth:
		return true, true
	default:
		flog.Warnf("unknown DIRECTION %q. Tracing both ingress and egress traffic", cfg.Direction)
		return true, true
	}
}

// ParseFlowFilterRules parses JSON flow filter rules into tracer filter configs.
func ParseFlowFilterRules(flowFilterRules string) ([]*tracer.FilterConfig, error) {
	filterRules := make([]*tracer.FilterConfig, 0)
	if len(flowFilterRules) == 0 {
		return filterRules, nil
	}

	var flowFilters []*config.FlowFilter
	if err := json.Unmarshal([]byte(flowFilterRules), &flowFilters); err != nil {
		return nil, err
	}

	for _, r := range flowFilters {
		filterRules = append(filterRules, &tracer.FilterConfig{
			Action:          r.Action,
			Direction:       r.Direction,
			IPCIDR:          r.IPCIDR,
			Protocol:        r.Protocol,
			PeerIP:          r.PeerIP,
			PeerCIDR:        r.PeerCIDR,
			DestinationPort: tracer.ConvertFilterPortsToInstr(r.DestinationPort, r.DestinationPortRange, r.DestinationPorts),
			SourcePort:      tracer.ConvertFilterPortsToInstr(r.SourcePort, r.SourcePortRange, r.SourcePorts),
			Port:            tracer.ConvertFilterPortsToInstr(r.Port, r.PortRange, r.Ports),
			TCPFlags:        r.TCPFlags,
			Drops:           r.Drops,
			Sample:          r.Sample,
		})
	}

	return filterRules, nil
}
