package agent

import (
	"context"
	"testing"
	"time"

	"github.com/gavv/monotime"
	test2 "github.com/mariomac/guara/pkg/test"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const timeout = 2 * time.Second

func TestFlowsAgent_InvalidConfigs(t *testing.T) {
	for _, tc := range []struct {
		d string
		c Config
	}{{
		d: "invalid export type",
		c: Config{Export: "foo"},
	}, {
		d: "GRPC: missing host",
		c: Config{Export: "grpc", TargetPort: 3333},
	}, {
		d: "GRPC: missing port",
		c: Config{Export: "grpc", TargetHost: "flp"},
	}, {
		d: "Kafka: missing brokers",
		c: Config{Export: "kafka"},
	}} {
		t.Run(tc.d, func(t *testing.T) {
			_, err := FlowsAgent(&tc.c)
			assert.Error(t, err)
		})
	}
}

var (
	key1 = flow.RecordKey{
		Transport: flow.Transport{SrcPort: 123, DstPort: 456},
		IFIndex:   3,
	}
	key1Dupe = flow.RecordKey{
		Transport: flow.Transport{SrcPort: 123, DstPort: 456},
		IFIndex:   4,
	}

	key2 = flow.RecordKey{
		Transport: flow.Transport{SrcPort: 333, DstPort: 532},
		IFIndex:   3,
	}
)

func TestFlowsAgent_Deduplication(t *testing.T) {
	export := testAgent(t, &Config{
		CacheActiveTimeout: 10 * time.Millisecond,
		CacheMaxFlows:      100,
		DeduperJustMark:    false,
		Deduper:            DeduperFirstCome,
	})

	exported := export.Get(t, timeout)
	assert.Len(t, exported, 2)

	receivedKeys := map[flow.RecordKey]struct{}{}

	var key1Flows []*flow.Record
	for _, f := range exported {
		require.NotContains(t, receivedKeys, f.RecordKey)
		receivedKeys[f.RecordKey] = struct{}{}
		switch f.RecordKey {
		case key1:
			assert.EqualValues(t, 4, f.Packets)
			assert.EqualValues(t, 66, f.Bytes)
			assert.False(t, f.Duplicate)
			assert.Equal(t, "foo", f.Interface)
			key1Flows = append(key1Flows, f)
		case key1Dupe:
			assert.EqualValues(t, 4, f.Packets)
			assert.EqualValues(t, 66, f.Bytes)
			assert.False(t, f.Duplicate)
			assert.Equal(t, "bar", f.Interface)
			key1Flows = append(key1Flows, f)
		case key2:
			assert.EqualValues(t, 7, f.Packets)
			assert.EqualValues(t, 33, f.Bytes)
			assert.False(t, f.Duplicate)
		}
	}
	assert.Lenf(t, key1Flows, 1, "only one flow should have been forwarded: %#v", key1Flows)
}

func TestFlowsAgent_DeduplicationJustMark(t *testing.T) {
	export := testAgent(t, &Config{
		CacheActiveTimeout: 10 * time.Millisecond,
		CacheMaxFlows:      100,
		DeduperJustMark:    true,
		Deduper:            DeduperFirstCome,
	})

	exported := export.Get(t, timeout)
	receivedKeys := map[flow.RecordKey]struct{}{}

	assert.Len(t, exported, 3)
	duplicates := 0
	for _, f := range exported {
		require.NotContains(t, receivedKeys, f.RecordKey)
		receivedKeys[f.RecordKey] = struct{}{}
		switch f.RecordKey {
		case key1:
			assert.EqualValues(t, 4, f.Packets)
			assert.EqualValues(t, 66, f.Bytes)
			if f.Duplicate {
				duplicates++
			}
			assert.Equal(t, "foo", f.Interface)
		case key1Dupe:
			assert.EqualValues(t, 4, f.Packets)
			assert.EqualValues(t, 66, f.Bytes)
			if f.Duplicate {
				duplicates++
			}
			assert.Equal(t, "bar", f.Interface)
		case key2:
			assert.EqualValues(t, 7, f.Packets)
			assert.EqualValues(t, 33, f.Bytes)
			assert.False(t, f.Duplicate)
		}
	}
	assert.Equalf(t, 1, duplicates, "exported flows should have only one duplicate: %#v", exported)
}

func TestFlowsAgent_Deduplication_None(t *testing.T) {
	export := testAgent(t, &Config{
		CacheActiveTimeout: 10 * time.Millisecond,
		CacheMaxFlows:      100,
		Deduper:            DeduperNone,
	})

	exported := export.Get(t, timeout)
	assert.Len(t, exported, 3)
	receivedKeys := map[flow.RecordKey]struct{}{}

	var key1Flows []*flow.Record
	for _, f := range exported {
		require.NotContains(t, receivedKeys, f.RecordKey)
		receivedKeys[f.RecordKey] = struct{}{}
		switch f.RecordKey {
		case key1:
			assert.EqualValues(t, 4, f.Packets)
			assert.EqualValues(t, 66, f.Bytes)
			assert.False(t, f.Duplicate)
			assert.Equal(t, "foo", f.Interface)
			key1Flows = append(key1Flows, f)
		case key1Dupe:
			assert.EqualValues(t, 4, f.Packets)
			assert.EqualValues(t, 66, f.Bytes)
			assert.False(t, f.Duplicate)
			assert.Equal(t, "bar", f.Interface)
			key1Flows = append(key1Flows, f)
		case key2:
			assert.EqualValues(t, 7, f.Packets)
			assert.EqualValues(t, 33, f.Bytes)
			assert.False(t, f.Duplicate)
		}
	}
	assert.Lenf(t, key1Flows, 2, "both key1 flows should have been forwarded: %#v", key1Flows)
}

func testAgent(t *testing.T, cfg *Config) *test.ExporterFake {
	ebpf := test.NewTracerFake()
	export := test.NewExporterFake()
	agent, err := flowsAgent(cfg,
		test.SliceInformerFake{
			{Name: "foo", Index: 3},
			{Name: "bar", Index: 4},
		}, ebpf, export.Export)
	require.NoError(t, err)

	go func() {
		require.NoError(t, agent.Run(context.Background()))
	}()
	test2.Eventually(t, timeout, func(t require.TestingT) {
		require.Equal(t, StatusStarted, agent.status)
	})

	now := uint64(monotime.Now())
	key1Metrics := []flow.RecordMetrics{
		{Packets: 3, Bytes: 44, StartMonoTimeNs: now + 1000, EndMonoTimeNs: now + 1_000_000_000},
		{Packets: 1, Bytes: 22, StartMonoTimeNs: now, EndMonoTimeNs: now + 3000},
	}
	key2Metrics := []flow.RecordMetrics{
		{Packets: 7, Bytes: 33, StartMonoTimeNs: now, EndMonoTimeNs: now + 2_000_000_000},
	}

	ebpf.AppendLookupResults(map[flow.RecordKey][]flow.RecordMetrics{
		key1:     key1Metrics,
		key1Dupe: key1Metrics,
		key2:     key2Metrics,
	})
	return export
}
