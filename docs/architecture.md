# NetObserv eBPF agent architecture

The eBPF agent is built as an a Extract-Transform-Load pipeline on top of the [Gopipes library](https://github.com/netobserv/gopipes).

The following graph provides a birds' eye view on how the different components are connected and which data they share.

For more info on each component, please check their corresponding Go docs.

<!-- When editing, you can use an online editor for a live preview, e.g. https://mermaid.live/ -->

### Kernel space

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
    F -->|Single-packet flow| RB(RingBuffer)
    M1 --> |Polling|U[User space]
    M2 --> |Polling|U
    RB --> |Push|U
    style A fill:#FBB
    style B fill:#FBB
    style C fill:#FBB
    style E fill:#FBB
```

### User space
```mermaid
flowchart TD
    E(ebpf.FlowFetcher) --> |"pushes via<br/>RingBuffer"| RB(flow.RingBufTracer)
    style E fill:#7CA

    E --> |"polls<br/>HashMap"| M(flow.MapTracer)
    RB --> |chan *model.Record| ACC(flow.Accounter)
    RB -.-> |flushes| M
    ACC --> |"chan []*model.Record"| CL(flow.CapacityLimiter)
    M --> |"chan []*model.Record"| CL

    CL --> |"chan []*model.Record"| EX("export.GRPCProto<br/>or<br/>export.KafkaProto<br/>or<br/>export.DirectFLP")
```
