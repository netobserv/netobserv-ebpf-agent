# AI Agents Best Practices for NetObserv eBPF Agent

Best practices for AI coding agents on NetObserv eBPF Agent.

> **Note**: Symlinked as [CLAUDE.md](CLAUDE.md) for Claude Code auto-loading.

## Project Context

**NetObserv eBPF Agent** - Network flow capture and aggregation using eBPF technology on Linux hosts (Kernel 5.8+)

**Components:**
- **eBPF C code** (`bpf/` directory): Runs in kernel space to capture packet data via TC/TCX hooks
- **Go userspace agent** (`pkg/` directory): Aggregates and exports network flows
- **Managed by**: [Network Observability Operator](https://github.com/netobserv/network-observability-operator)

**Key Directories:**
- `bpf/`: eBPF C code (flows.c, types.h, configs.h, feature-specific headers)
- `pkg/config/`: Configuration via environment variables
- `pkg/flow/`: Flow aggregation, accounting, and flow tracers (map/ringbuf readers)
- `pkg/tracer/`: eBPF program loader, TC/TCX hook attachment, flow filtering
- `pkg/exporter/`: GRPC, Kafka, direct-flp exporters
- `pkg/ebpf/`: Generated eBPF Go bindings (bpf_*_bpfel.go/o)
- `proto/`: Protocol buffer definitions
- `docs/`: Architecture, config reference, eBPF implementation details

## Critical Constraints

### 🚨 eBPF Compatibility (Kernel 5.8+)
eBPF verifier requirements:
- **Bounded loops only**: Verifier must prove loop termination
- **Stack limit**: 512 bytes maximum
- **No unbounded recursion**
- Changes to `bpf/*.c` or `bpf/*.h` require `make docker-generate` or `make generate`

### 🚨 Configuration via Environment Variables Only
- No config files from agent's perspective
- Source of truth: `pkg/config/config.go`
- All options documented in [docs/config.md](./docs/config.md)
- Agent does NOT access Kubernetes API directly

### 🚨 Licenses
- eBPF code (`bpf/`): GPL v2 (see `bpf/LICENSE`)
- Go code: Apache v2

## Effective Prompting

**Good Example:**
```text
Update bpf/flows.c to add packet drop reason tracking. Store drop reason in
additional_flow_metrics PerCPU map. Update pkg/tracer/tracer.go to read and
merge drop reasons. Add DROPS_TRACKING env var in pkg/config/config.go
(default: false). Run make docker-generate and add unit tests.
```

**Bad Example:**
```text
Add drop tracking to eBPF
```

**Key Principles:**
1. Specify exact file paths (`bpf/flows.c`, not "eBPF code")
2. Reference existing patterns (maps, config, exporters)
3. Mention regeneration steps (`make docker-generate` for eBPF changes)
4. Check dependencies before adding new packages

## Common Task Templates

### Add eBPF Feature
```text
Add PacketDrop tracking to monitor dropped packets:

1. eBPF Implementation:
   - Define data structure in bpf/types.h (e.g., pkt_drop_t with state, drop_cause)
   - Update bpf/flows.c to hook into kfree_skb tracepoint
   - Store drop metadata in flow_record_t or additional_flow_metrics PerCPU map
   - Access kernel debug filesystem (/sys/kernel/debug) for tracepoint data

2. Userspace Integration:
   - Update pkg/tracer/tracer.go to read drop data from eBPF maps
   - Update pkg/flow/ tracers (tracer_map.go, tracer_ringbuf.go) to handle drop events
   - Add drop fields to proto/flow.proto (PktDropBytes, PktDropPackets, PktDropLatestState, etc.)
   - Run make gen-protobuf to regenerate pkg/pbflow/

3. Build and Test:
   - Run make docker-generate to regenerate eBPF binaries
   - Test on actual kernel with privileged mode enabled (requires /sys/kernel/debug mount)
   - Document in docs/architecture.md if adding new map

Note: PacketDrop feature requires privileged mode for kernel debug filesystem access.
Other privileged-mode features: NetworkEvents, UDNMapping (debug fs), SR-IOV (secondary interfaces).
For features NOT requiring privileged mode (e.g., DNSTracking, FlowRTT), skip privileged testing.
```

### Add Configuration Parameter
```text
Add cache timeout configuration:
1. Update pkg/config/config.go:
   - Add field to Agent struct with env: tag
   - Set default value
2. Update docs/config.md with new parameter documentation
3. Use config in pkg/flow/ or pkg/tracer/ as needed
4. Add validation if required (e.g., positive duration)
5. Run make build
```

### Add Flow Field
```text
Add new flow field for packet metadata:
1. Update proto/flow.proto with new field
2. Run make prereqs (ensures protoc is installed)
3. Run make gen-protobuf to regenerate pkg/pbflow/
4. Update bpf/types.h with field in flow_record_t if captured in eBPF
5. Update bpf/flows.c to populate field
6. Run make docker-generate for eBPF changes
7. Update pkg/flow/ to handle new field in aggregation
8. Update pkg/exporter/ if export format changes
```

### Debug Packet Capture Issues
```text
Flows not captured for specific interface:
Check pkg/tracer/tracer.go:
- Verify TC/TCX hook attachment in AttachTCX() or Register()
- Check interface filtering logic in pkg/agent/interfaces_listener.go
- Review eBPF map access errors in bpf/flows.c
Suggest fixes with proper error handling patterns.
```

### Modify Flow Aggregation
```text
Change flow aggregation logic in pkg/flow/account.go:
- Review existing Accounter struct
- Check cache eviction policy (maxEntries, evictTimeout)
- Review flow accumulation logic
- Add unit tests for new aggregation rules
```

### Add Exporter Configuration
```text
Add request timeout to GRPC exporter:
1. Update pkg/config/config.go with timeout-related env vars
2. Update pkg/exporter/grpc_proto.go to use timeout config
3. Add timeout handling logic
4. Update docs/config.md
5. Add integration tests in e2e/
```

## Repository-Specific Context

### Export Modes
Export modes (check `EXPORT` env var):
- **GRPC**: Export to flowlogs-pipeline via gRPC (default)
- **Kafka**: Export to Kafka topics
- **direct-flp**: Embed flowlogs-pipeline in agent process (configured via `FLP_CONFIG`)
- **IPFIX collectors**: Export to flowlogs-pipeline (via GRPC/Kafka/direct-flp), then configure IPFIX export within flowlogs-pipeline

### Performance
- **Sampling**: `SAMPLING` env var (agent default: 0 = disabled, commonly deployed: 50 = 1:50 packets). Lower = more flows/resources
- **Caching**: `CACHE_MAX_FLOWS` (default: 5000), `CACHE_ACTIVE_TIMEOUT` (default: 5s)
- **Memory**: Watch for eBPF map sizes and userspace cache
- **Metrics**: Prometheus metrics exposed on `METRICS_SERVER_PORT` (default: 9090)

### eBPF Maps
- **aggregated_flows**: `BPF_MAP_TYPE_HASH` (global, not per-CPU) - main flow aggregation
- **additional_flow_metrics**: `BPF_MAP_TYPE_PERCPU_HASH` - RTT, IPsec metrics
- **aggregated_flows_dns**, **aggregated_flows_pkt_drop**, **aggregated_flows_network_events**, **aggregated_flows_xlat**: PerCPU maps for DNS, drops, network events, and address translation
- **dns_flows**: Global map for DNS request/response matching
- See [docs/ebpf_implementation.md](./docs/ebpf_implementation.md) for details on per-CPU vs regular maps

### Deployment Requirements

**Default mode (granular capabilities):**
Agent requires Linux capabilities:
- `BPF`: Use eBPF programs and maps
- `PERFMON`: Access perf monitoring
- `NET_ADMIN`: Attach/detach TC programs, TCX hooks

**Privileged mode (when required):**
Certain features require privileged mode for kernel debug filesystem access or secondary interface monitoring:
- **PacketDrop**: Packet drop flows logging (requires /sys/kernel/debug)
- **NetworkEvents**: Network policy correlation (requires /sys/kernel/debug)
- **UDNMapping**: User Defined Networks mapping (requires /sys/kernel/debug)
- **SR-IOV support**: Secondary interface monitoring

**Compatibility notes:**
- Some older Kubernetes distributions (Kind, K3s, Rancher Desktop) don't recognize `BPF` and `PERFMON` capabilities
- In these cases, privileged mode is required even for basic features
- See README.md for tested distribution compatibility matrix

**Deployment:** When using Network Observability Operator, configure via FlowCollector CR. For standalone deployment, see deployment examples in [deployments/](./deployments/).

### Flow Filtering
- Configured via `FLOW_FILTER_RULES` env var (JSON format)
- See [docs/flow_filtering.md](./docs/flow_filtering.md) for rule syntax and examples

## Code Review Checklist

```text
Review for:
1. eBPF verifier compliance (bounded loops, stack limit)
2. Kernel 5.8+ compatibility (no newer eBPF features)
3. Error handling (wrap with context)
4. Unit test coverage (go test)
5. Configuration in pkg/config/config.go AND docs/config.md
6. License headers (GPL v2 for bpf/, Apache v2 for Go)
7. Performance impact (eBPF overhead, memory usage)
8. Security (input validation, no buffer overflows in eBPF)
```

## Testing

### Unit Tests
```text
Generate tests for flow aggregation in pkg/flow/account.go:
- Cache eviction on max entries
- Cache eviction on timeout
- Flow accumulation
- Edge cases (nil, empty)
Use standard Go testing patterns.
```

### E2E Tests
```text
Test on Kind cluster:
1. make tests-e2e (installs prereqs, builds image, runs tests)
   - Builds localhost/ebpf-agent:test image
   - Runs e2e test suite with Kind cluster
2. Verify: packet capture, flow aggregation, export to flowlogs-pipeline
Note: tests-e2e target handles image build and Kind cluster setup automatically
```

## Quick Reference

**Essential Commands:**
```bash
make build                      # Run prereqs, fmt, lint, test, vendors, compile
make fmt                        # Format Go and C code
make lint                       # Lint Go and C code
make test                       # Run unit tests
make compile                    # Compile the agent binary
make docker-generate            # Regenerate eBPF binaries (after bpf/ changes)
make generate                   # Regenerate eBPF + protobuf (requires local tools)
make tests-e2e                  # E2E tests on Kind cluster
make image-build image-push     # Build and push image
```

**Key Files:**
- Config: [pkg/config/config.go](pkg/config/config.go)
- eBPF main: [bpf/flows.c](bpf/flows.c), [bpf/types.h](bpf/types.h), [bpf/maps_definition.h](bpf/maps_definition.h)
- Flow aggregation: [pkg/flow/account.go](pkg/flow/account.go)
- eBPF loader: [pkg/tracer/tracer.go](pkg/tracer/tracer.go)
- Flow tracers: [pkg/flow/tracer_map.go](pkg/flow/tracer_map.go), [pkg/flow/tracer_ringbuf.go](pkg/flow/tracer_ringbuf.go)
- Exporters: [pkg/exporter/](pkg/exporter/)
- Docs: [docs/architecture.md](docs/architecture.md), [docs/config.md](docs/config.md)

## AI Workflow Example

```text
1. Research: "Explain RTT tracking implementation in bpf/rtt_tracker.h"
2. Plan: "Add TCP retransmit tracking - suggest eBPF hook and data structure"
3. Implement: "Implement with proper map storage and userspace reading"
4. Review: "Review for eBPF verifier compliance and edge cases"
5. Regenerate: "Run make docker-generate to update binaries"
6. Test: "Provide e2e test scenarios for retransmit tracking"
```

## Contribution Checklist

Before commit:
1. AI code review
2. `make build`
3. `make docker-generate` (if eBPF code changed)
4. Update docs/config.md (if config changed)
5. Add unit tests for new Go logic
6. Run e2e tests for eBPF changes: `make tests-e2e`
7. Conventional commit messages

## Resources

- [README.md](README.md) - Build, configure, run, troubleshoot
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [docs/architecture.md](docs/architecture.md) - System architecture and data flow
- [docs/config.md](docs/config.md) - All environment variable options
- [docs/ebpf_implementation.md](docs/ebpf_implementation.md) - eBPF maps, per-CPU HashMap, flow collisions
- [docs/flow_filtering.md](docs/flow_filtering.md) - Flow filter rules configuration
- [docs/profiling.md](docs/profiling.md) - Performance profiling
- [docs/rtt_calculations.md](docs/rtt_calculations.md) - RTT tracking implementation
- [examples/direct-flp/README.md](examples/direct-flp/README.md) - Direct-flp usage examples
- [e2e/README.md](e2e/README.md) - End-to-end testing guide

**Remember**: AI agents need clear context. Always review generated code, test thoroughly on actual kernel environment, and follow project conventions.
