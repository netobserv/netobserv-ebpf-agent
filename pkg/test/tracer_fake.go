package test

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer"

	"github.com/cilium/ebpf/ringbuf"
)

// TracerFake fakes the kernel-side eBPF map structures for testing
type TracerFake struct {
	interfaces map[ifaces.InterfaceKey]struct{}
	mapLookups chan map[ebpf.BpfFlowId]model.BpfFlowContent
	ringBuf    chan ringbuf.Record
}

func NewTracerFake() *TracerFake {
	return &TracerFake{
		interfaces: map[ifaces.InterfaceKey]struct{}{},
		mapLookups: make(chan map[ebpf.BpfFlowId]model.BpfFlowContent, 100),
		ringBuf:    make(chan ringbuf.Record, 100),
	}
}

func (m *TracerFake) Close() error {
	return nil
}
func (m *TracerFake) Register(iface *ifaces.Interface) error {
	m.interfaces[iface.InterfaceKey] = struct{}{}
	return nil
}

func (m *TracerFake) UnRegister(iface *ifaces.Interface) error {
	m.interfaces[iface.InterfaceKey] = struct{}{}
	return nil
}

func (m *TracerFake) AttachTCX(_ *ifaces.Interface) *tracer.TracerError {
	return nil
}

func (m *TracerFake) DetachTCX(_ *ifaces.Interface) *tracer.TracerError {
	return nil
}

func (m *TracerFake) LookupAndDeleteMap(_ *metrics.Metrics) map[ebpf.BpfFlowId]model.BpfFlowContent {
	select {
	case r := <-m.mapLookups:
		return r
	default:
		return map[ebpf.BpfFlowId]model.BpfFlowContent{}
	}
}

func (m *TracerFake) DeleteMapsStaleEntries(_ time.Duration) {
}

func (m *TracerFake) ReadRingBuf() (ringbuf.Record, error) {
	return <-m.ringBuf, nil
}

func (m *TracerFake) AppendLookupResults(results map[ebpf.BpfFlowId]model.BpfFlowContent) {
	m.mapLookups <- results
}

//nolint:gocritic // we don't care about efficiency of a large argument in test fakes
func (m *TracerFake) AppendRingBufEvent(flow model.RawRecord) error {
	encodedRecord := bytes.Buffer{}
	if err := binary.Write(&encodedRecord, binary.LittleEndian, flow); err != nil {
		return err
	}
	m.ringBuf <- ringbuf.Record{RawSample: encodedRecord.Bytes()}
	return nil
}
