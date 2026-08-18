# Flow capture architecture

Flow mode (`ENABLE_PCA=false`) is the default agent operation. It aggregates per-connection statistics in the kernel and exports flow records to flowlogs-pipeline or compatible collectors.

See also: [top-level architecture](../architecture.md) · [flow filtering](../flow_filtering.md) · [eBPF implementation](../ebpf_implementation.md)

## BPF object

Flow programs are compiled from [`bpf/flows/flows.c`](../../bpf/flows/flows.c). Go bindings are generated into [`pkg/ebpf/flows`](../../pkg/ebpf/flows) via bpf2go.

The flow object includes TC/TCX/netkit `*_flow_parse` programs and optional feature hooks (DNS, RTT, packet drops, network events, IPsec, TLS, QUIC, OpenSSL, etc.). It does **not** include packet-capture (`*_packet_parse`) programs.

## Kernel space

```mermaid
flowchart TD
    A[TC/X Hooks] -->|Accumulate packet data| M1(Global map: aggregated_flows)
    D{If DNS} -->|Req: store req info| MD(Global map: dns_flows)
    D -->|Resp: compute latency| MD
    A -->D
    D -->|Store DNS info| M2(PerCPU map: additional_flow_metrics)
    B[Drops Hook: kfree_skb] -->|Accumulate drop data| M2(PerCPU map: additional_flow_metrics)
    C[RTT Hook: tcp_rcv_established] -->|Extract & store sRTT| M2(PerCPU map: additional_flow_metrics)
    E[Events Hook: psample_sample_packet] -->|Accumulate net events| M2(PerCPU map: additional_flow_metrics)
    A -->F{If busy map / error}
    F -->|Single-packet flow| RB(RingBuffer: direct_flows)
    M1 --> |Polling|U[User space]
    M2 --> |Polling|U
    RB --> |Push|U
    style A fill:#FBB
    style B fill:#FBB
    style C fill:#FBB
    style E fill:#FBB
```

Key maps are documented in [ebpf_implementation.md](../ebpf_implementation.md).

## User space

```mermaid
flowchart TD
    E(tracer/flows.Fetcher) --> |"pushes via<br/>RingBuffer"| RB(flow.RingBufTracer)
    style E fill:#7CA

    E --> |"polls<br/>HashMap"| M(flow.MapTracer)
    RB --> |chan *model.Record| ACC(flow.Accounter)
    RB -.-> |flushes| M
    ACC --> |"chan []*model.Record"| CL(flow.CapacityLimiter)
    M --> |"chan []*model.Record"| CL

    CL --> |"chan []*model.Record"| EX("exporter.GRPC<br/>or Kafka<br/>or direct-flp")
```

## Userspace packages

| Package | Role |
|---------|------|
| `pkg/tracer/flows` | Load flow BPF object, attach TC/TCX hooks, read maps and ringbuf |
| `pkg/tracer/attach` | Shared interface registration and filter map programming |
| `pkg/flow` | Flow aggregation, accounting, export batching |
| `pkg/agent/common` | Shared agent wiring: interface listener, TLS/SASL, flow filter parsing, status |
| `pkg/agent/flows` | Flow agent: pipeline composition and exporters |
| `pkg/decode/flows` | Flow protobuf decode and direct-flp `GenericMap` conversion |
| `pkg/exporter/flows` | gRPC, Kafka, IPFIX, and direct-flp export |

## Optional features

These are compiled into the flow BPF object and enabled via environment variables. They are **rejected at startup** when `ENABLE_PCA=true`:

| Feature | Env var |
|---------|---------|
| DNS tracking | `ENABLE_DNS_TRACKING` |
| RTT | `ENABLE_RTT` |
| Packet drops | `ENABLE_PKT_DROPS` |
| Network events | `ENABLE_NETWORK_EVENTS_MONITORING` |
| NAT / address translation | `ENABLE_PKT_TRANSLATION` |
| UDN mapping | `ENABLE_UDN_MAPPING` |
| IPsec | `ENABLE_IPSEC_TRACKING` |
| OpenSSL (flow metadata) | `ENABLE_OPENSSL_TRACKING` |
| TLS | `ENABLE_TLS_TRACKING` |
| QUIC | `QUIC_TRACKING_MODE` |
| Ringbuf fallback | `ENABLE_FLOWS_RINGBUF_FALLBACK` |

## Filtering

Flow and packet modes share filter rule syntax (`FLOW_FILTER_RULES`), implemented in [`bpf/common/filter.h`](../../bpf/common/filter.h). See [flow_filtering.md](../flow_filtering.md).
