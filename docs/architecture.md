# NetObserv eBPF agent architecture

The eBPF agent is built as an a Extract-Transform-Load pipeline on top of the [Gopipes library](https://github.com/netobserv/gopipes).

The following graph provides a birds' eye view on how the different components are connected and which data they share.

For more info on each component, please check their corresponding Go docs.

```mermaid
flowchart TD
    E(ebpf.FlowFetcher) --> |"pushes via<br/>RingBuffer"| RB(flow.RingBufTracer)
    style E fill:#990

    E --> |"polls<br/>PerCPUHashMap"| M(flow.MapTracer)
    RB --> |chan *model.Record| ACC(flow.Accounter)
    RB -.-> |flushes| M
    ACC --> |"chan []*model.Record"| DD(flow.Deduper)
    M --> |"chan []*model.Record"| DD

    subgraph Optional
        DD
    end

    DD --> |"chan []*model.Record"| CL(flow.CapacityLimiter)

    CL --> |"chan []*model.Record"| DC(flow.Decorator)
    
    DC --> |"chan []*model.Record"| EX("export.GRPCProto<br/>or<br/>export.KafkaProto")
```
