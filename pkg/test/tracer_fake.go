package test

import (
	"bytes"
	"encoding/binary"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
)

// TracerFake fakes the kernel-side eBPF map structures for testing
type TracerFake struct {
	interfaces map[ifaces.Interface]struct{}
	mapLookups chan map[ebpf.BpfFlowId][]ebpf.BpfFlowMetrics
	ringBuf    chan ringbuf.Record
}

func NewTracerFake() *TracerFake {
	return &TracerFake{
		interfaces: map[ifaces.Interface]struct{}{},
		mapLookups: make(chan map[ebpf.BpfFlowId][]ebpf.BpfFlowMetrics, 100),
		ringBuf:    make(chan ringbuf.Record, 100),
	}
}

func (m *TracerFake) Close() error {
	return nil
}
func (m *TracerFake) Register(iface ifaces.Interface) error {
	m.interfaces[iface] = struct{}{}
	return nil
}

func (m *TracerFake) LookupAndDeleteMap() map[ebpf.BpfFlowId][]ebpf.BpfFlowMetrics {
	select {
	case r := <-m.mapLookups:
		return r
	default:
		return map[ebpf.BpfFlowId][]ebpf.BpfFlowMetrics{}
	}
}

func (m *TracerFake) ReadRingBuf() (ringbuf.Record, error) {
	return <-m.ringBuf, nil
}

func (m *TracerFake) AppendLookupResults(results map[ebpf.BpfFlowId][]ebpf.BpfFlowMetrics) {
	m.mapLookups <- results
}

//nolint:gocritic // we don't care about efficiency of a large argument in test fakes
func (m *TracerFake) AppendRingBufEvent(flow flow.RawRecord) error {
	encodedRecord := bytes.Buffer{}
	if err := binary.Write(&encodedRecord, binary.LittleEndian, flow); err != nil {
		return err
	}
	m.ringBuf <- ringbuf.Record{RawSample: encodedRecord.Bytes()}
	return nil
}
