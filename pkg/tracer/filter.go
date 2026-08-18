package tracer

import (
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/attach"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// Filter types and helpers — re-exported from pkg/tracer/attach for backward compatibility.

type FilterConfig = attach.FilterConfig
type Filter = attach.Filter

func NewFilter(cfg []*FilterConfig) *Filter {
	return attach.NewFilter(cfg)
}

func ConvertFilterPortsToInstr(intPort int32, rangePorts, ports string) intstr.IntOrString {
	return attach.ConvertFilterPortsToInstr(intPort, rangePorts, ports)
}
