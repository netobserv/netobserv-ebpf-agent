package test

import (
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
)

type ExporterFake struct {
	messages chan []*model.Record
}

func NewExporterFake() *ExporterFake {
	return &ExporterFake{
		messages: make(chan []*model.Record, 100),
	}
}

func (ef *ExporterFake) Export(in <-chan *model.FlowBatch) {
	for batch := range in {
		if len(batch.Records) > 0 {
			ef.messages <- batch.Records
		}
		batch.Release()
	}
}

func (ef *ExporterFake) Get(t *testing.T, timeout time.Duration) []*model.Record {
	t.Helper()
	select {
	case <-time.After(timeout):
		t.Fatalf("timeout %s while waiting for a message to be exported", timeout)
		return nil
	case m := <-ef.messages:
		return m
	}
}
