package model

import (
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/stretchr/testify/assert"
)

func TestAccumulate(t *testing.T) {
	baseMetrics := ebpf.BpfFlowMetrics{
		Bytes: 10,
	}
	additionalMetrics := []ebpf.BpfAdditionalMetrics{
		{DnsRecord: ebpf.BpfDnsRecordT{Id: 5}},
		{FlowRtt: 500},
	}
	flowPayload := BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{}}
	flowPayload.AccumulateBase(&baseMetrics)
	for _, a := range additionalMetrics {
		flowPayload.AccumulateAdditional(&a)
	}

	assert.EqualValues(t, 10, flowPayload.Bytes)
	assert.EqualValues(t, 5, flowPayload.AdditionalMetrics.DnsRecord.Id)
	assert.EqualValues(t, 500, flowPayload.AdditionalMetrics.FlowRtt)
}
