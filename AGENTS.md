# AI Agents Best Practices for NetObserv eBPF Agent

Best practices for AI coding agents on NetObserv eBPF Agent.

> **Note**: Symlinked as [CLAUDE.md](CLAUDE.md) for Claude Code auto-loading.

## Project Context

**NetObserv eBPF Agent** - Linux kernel-level network flow collection agent using eBPF technology

**Architecture:**
- **eBPF Programs**: C code running in kernel space (`bpf/` directory) for packet capture and flow tracking
- **Agent Core**: Go application managing eBPF programs, flow aggregation, and export
- **Exporters**: Multiple export modes (gRPC, Kafka, IPFIX, direct-flp) for sending flow data
- **Kubernetes Integration**: Deployed as DaemonSet, enriched with K8s metadata
- **Data Flow**: Packet capture → eBPF maps → User-space aggregation → Export to collectors

**Key Features:**
- Network flow tracking (ingress/egress)
- RTT (Round-Trip Time) calculation
- DNS latency tracking
- Packet drop detection
- Packet capture (PCA) capabilities
- Flow deduplication
- Flow filtering and sampling

**Key Directories:**
- `bpf/`: eBPF C code for kernel-space packet processing
  - `flows.c`: Main flow tracking logic
  - `packet_capture.c`: Packet capture implementation
  - `tc_*.c`: Traffic control hooks
- `pkg/`: Go application code
  - `agent/`: Main agent logic and configuration
  - `ebpf/`: eBPF program loader and manager (Go bindings)
  - `flow/`: Flow accounting and deduplication
  - `exporter/`: Export implementations (gRPC, Kafka, IPFIX, direct-flp)
  - `ifaces/`: Interface detection and management
  - `tracer/`: Flow tracer orchestration
  - `decode/`: Packet decoding logic
  - `metrics/`: Prometheus metrics
- `proto/`: Protocol buffer definitions for gRPC
- `examples/`: Example deployments and usage patterns
- `e2e/`: End-to-end tests
- `deployments/`: Kubernetes deployment manifests

## Critical Constraints

### 🚨 eBPF Kernel Compatibility
This agent uses eBPF and requires Kernel 5.8+:
- eBPF programs must be compatible with various kernel versions
- Use CO-RE (Compile Once - Run Everywhere) patterns
- Test on different kernel versions when changing eBPF code
- Be aware of eBPF verifier constraints (instruction limits, map sizes)

### 🚨 eBPF Code Generation
When modifying C code in `bpf/`:
1. Update the eBPF C source files
2. Regenerate Go bindings: `make docker-generate` or `make generate`
3. The generated files in `pkg/ebpf/bpf_*` must be committed
4. Never manually edit generated `pkg/ebpf/bpf_*` files

### 🚨 Protocol Buffer Changes
When updating `.proto` files:
1. Modify `proto/flow.proto` or `proto/packet.proto`
2. Regenerate Go code: `make gen-protobuf`
3. Ensure backward compatibility with existing collectors
4. Test with flowlogs-pipeline integration

### 🚨 Performance-Critical Code
This agent runs on every node and processes high packet volumes:
- eBPF code must be optimized (verifier limits, minimal instructions)
- Avoid unnecessary allocations in hot paths
- Use efficient map lookups and aggregation
- Profile performance impact of changes (`PROFILE_PORT`)
- Test with realistic traffic volumes

### 🚨 Privileged Execution
The agent requires specific Linux capabilities:
- `BPF`: Required for eBPF programs and maps
- `PERFMON`: Required for perf monitoring features
- `NET_ADMIN`: Required for TC attachment
- Must run as root user (`runAsUser: 0`)
- Security considerations for all code changes

### 🚨 Multi-Export Mode Support
Changes must support all export modes:
- `grpc`: gRPC + Protocol Buffers
- `kafka`: Apache Kafka
- `ipfix+tcp` / `ipfix+udp`: IPFIX protocol
- `direct-flp`: Embedded flowlogs-pipeline
- Test changes across export modes

### 🚨 Configuration via Environment Variables
All configuration is done through environment variables:
- Add new config in `pkg/agent/config.go`
- Document in `docs/config.md`
- Provide sensible defaults
- Support backward compatibility

## Effective Prompting

**Good Example:**
```
Update pkg/flow/deduper.go to improve the firstCome deduplication algorithm
by tracking flow hashes instead of full flow keys. Update the corresponding
test in pkg/flow/deduper_test.go. Ensure DEDUPER_FC_EXPIRY configuration
is respected.
```

**Bad Example:**
```
Make deduplication better
```

**Key Principles:**
1. Specify whether changes are in eBPF (C) or userspace (Go)
2. Distinguish between kernel-space (`bpf/`) and user-space (`pkg/`) code
3. Reference existing patterns in similar components
4. Mention testing requirements (unit tests, e2e tests)
5. Consider performance implications
6. Note which export modes are affected

## Common Task Templates

### Modify eBPF Flow Tracking
```
Add TCP flag tracking to bpf/flows.c:
1. Update flow_id struct to include TCP flags field
2. Extract TCP flags in handle_packet function
3. Regenerate Go bindings: make docker-generate
4. Update pkg/decode/decoder.go to parse new field
5. Update proto/flow.proto if needed for export
6. Add e2e test to verify TCP flags are captured
7. Test with tcpdump/real traffic
```

### Add New Configuration Option
```
Add FLOW_SAMPLING_RATE configuration to enable dynamic sampling:
1. Add new field to pkg/agent/config.go Config struct
2. Add environment variable parsing with default value
3. Document in docs/config.md
4. Update pkg/tracer/tracer.go to use the new setting
5. Add unit test for config parsing
6. Update deployment examples in deployments/
```

### Improve Flow Aggregation
```
Optimize flow accounting in pkg/flow/account.go:
1. Profile current performance with pprof (PROFILE_PORT)
2. Identify hot paths in cache lookup/update
3. Reduce allocations in accounter methods
4. Update pkg/flow/account_test.go with benchmarks
5. Test with high flow volumes (e2e/basic/)
6. Verify CACHE_MAX_FLOWS and CACHE_ACTIVE_TIMEOUT work correctly
```

### Add New Export Mode Feature
```
Add compression support for gRPC exporter:
1. Update pkg/exporter/grpc/grpc_proto.go to support compression
2. Add GRPC_COMPRESSION environment variable in pkg/agent/config.go
3. Update proto service definitions if needed
4. Test with flowlogs-pipeline receiver
5. Document configuration in docs/config.md
6. Add e2e test for compressed flows
```

### Fix Interface Detection Issue
```
Fix interface filtering bug in pkg/ifaces/watcher.go:
1. Reproduce the issue with specific INTERFACES/EXCLUDE_INTERFACES config
2. Debug with LOG_LEVEL=debug
3. Fix regex matching logic
4. Add test cases in pkg/ifaces/watcher_test.go
5. Test with various interface name patterns
6. Verify INTERFACE_IPS mode still works
```

### Add New eBPF Feature
```
Add VLAN tag tracking to eBPF programs:
1. Update bpf/flows.c to extract VLAN tags from packets
2. Add VLAN field to flow_id struct in bpf/flow.h
3. Regenerate eBPF bindings: make docker-generate
4. Update pkg/decode/decoder.go to handle VLAN field
5. Add to proto/flow.proto for export
6. Update pkg/flow/deduper.go if VLAN affects deduplication
7. Add e2e test with VLAN-tagged traffic
```

## Code Review Checklist

```
eBPF C Code (bpf/):
1. eBPF verifier compatibility (instruction count, complexity)
2. Proper bounds checking for array/map access
3. Efficient map lookups (minimize redundant lookups)
4. Correct memory access patterns
5. CO-RE relocations for portability
6. License headers (GPL v2 for eBPF code)
7. Regenerated Go bindings committed

Go Code (pkg/):
1. Error handling (wrap errors with context)
2. Logging with appropriate levels (LOG_LEVEL)
3. Unit test coverage
4. Performance considerations (allocations, hot paths)
5. Configuration via environment variables
6. Backward compatibility (config, exports)
7. Thread safety (goroutine synchronization)
8. Resource cleanup (defer close, context cancellation)
9. License headers (Apache v2)

General:
1. Documentation updates (README.md, docs/)
2. Configuration documented (docs/config.md)
3. Deployment manifests updated if needed
4. E2E tests for significant changes
5. All export modes tested
6. Performance impact measured
7. Kernel version compatibility
```

## Testing

### Unit Tests
```
Run Go unit tests:
make test

Test specific package:
go test -v ./pkg/flow/...

Run with coverage:
make test-coverage

Test with race detector:
go test -race ./pkg/...
```

### eBPF Code Generation
```
Regenerate eBPF bindings after C changes:

With Docker (recommended):
make docker-generate

Without Docker (requires kernel-devel, llvm, clang):
dnf install -y kernel-devel make llvm clang glibc-devel.i686
make generate

Verify generated files:
git diff pkg/ebpf/
```

### End-to-End Tests
```
Run e2e tests:
cd e2e
make run-tests

Test specific scenario:
cd e2e/basic
./run-test.sh

Test with Kafka:
cd e2e/kafka
./run-test.sh

See e2e/README.md for detailed instructions
```

### Local Development Testing
```
Build and run locally:
1. Build agent: make build
2. Export TARGET_HOST=localhost
3. Export TARGET_PORT=2055
4. Run with direct-flp mode for stdout output:
   export FLP_CONFIG='{"pipeline":[{"name":"writer","follows":"preset-ingester"}],"parameters":[{"name":"writer","write":{"type":"stdout"}}]}'
   export EXPORT=direct-flp
   sudo -E bin/netobserv-ebpf-agent

Test on KinD cluster:
make create-and-deploy-kind-cluster
export KUBECONFIG=$(pwd)/scripts/kubeconfig
kubectl logs -n default -l app=netobserv-ebpf-agent -f
```

### Performance Testing
```
Profile agent performance:
1. Set PROFILE_PORT=6060 environment variable
2. Run agent
3. Access pprof: go tool pprof http://localhost:6060/debug/pprof/profile
4. Analyze CPU, memory, goroutines

Load testing:
cd examples/performance
# Follow README for packet counter and load generation
```

## Repository-Specific Context

### eBPF Architecture
- **TC Hooks**: Traffic control for packet capture (attach/detach to qdisc)
- **TCX Hooks**: Modern TC-eXpress hooks for newer kernels
- **Ring Buffer**: Perf ring buffer for kernel-to-userspace communication
- **Maps**: eBPF maps for flow aggregation, configuration
- **CO-RE**: Compile Once - Run Everywhere for kernel portability

### Flow Processing Pipeline
```
Packet arrives → eBPF hook (TC/TCX)
  ↓
Extract flow key (5-tuple + interface)
  ↓
Lookup/update in eBPF map (aggregation)
  ↓
Eviction → Ring buffer → Userspace
  ↓
Flow accounting (pkg/flow/account.go)
  ↓
Deduplication (pkg/flow/deduper.go)
  ↓
Enrichment (K8s metadata)
  ↓
Export (gRPC/Kafka/IPFIX/direct-flp)
```

### Configuration Management
Environment variable → `pkg/agent/config.go` → Component-specific config
- Central config struct in `pkg/agent/config.go`
- Validation and defaults in config parsing
- Documentation in `docs/config.md`

### Export Modes
1. **gRPC**: `pkg/exporter/grpc/` - Protocol buffer based, recommended
2. **Kafka**: `pkg/exporter/kafka/` - Apache Kafka producer
3. **IPFIX**: `pkg/exporter/ipfix/` - IPFIX protocol (not actively maintained)
4. **direct-flp**: `pkg/exporter/direct_flp/` - Embedded flowlogs-pipeline

### Kubernetes Integration
- Deployed as DaemonSet (one pod per node)
- Metadata enrichment from K8s API
- Service account with RBAC for API access
- ConfigMap for configuration
- Privileged or capability-based security context

### Build System
- **Makefile**: Primary build interface
- **eBPF Generation**: `make docker-generate` (Docker) or `make generate` (local)
- **Protocol Buffers**: `make gen-protobuf`
- **Container Images**: `make image-build`, `make image-push`
- **Multi-arch**: `MULTIARCH_TARGETS=amd64,arm64 make images`

### Licensing
- eBPF code (`bpf/`): GPL v2 (kernel requirement)
- Everything else: Apache v2

## Quick Reference

**Essential Commands:**
```bash
make build                        # Build agent binary
make test                         # Run unit tests
make lint                         # Lint code (Go + C)
make fmt                          # Format code (Go + C)
make docker-generate              # Regenerate eBPF bindings (Docker)
make generate                     # Regenerate eBPF bindings (local)
make gen-protobuf                 # Regenerate protobuf code
make image-build                  # Build container image
make image-push                   # Push container image
make images                       # Build + push multi-arch images
make vendors                      # Update Go dependencies
make prereqs                      # Install build prerequisites
make create-and-deploy-kind-cluster  # Deploy to KinD
make destroy-kind-cluster         # Delete KinD cluster
```

**Quick Development Builds:**
```bash
# Build specific architecture
GOARCH=arm64 make build

# Build and push custom image
IMAGE_ORG=myuser VERSION=dev make images

# Use custom registry
IMAGE=docker.io/myuser/agent:tag make images
```

**Key Files:**
- Main Entry: [cmd/netobserv-ebpf-agent.go](cmd/netobserv-ebpf-agent.go)
- Agent Core: [pkg/agent/agent.go](pkg/agent/agent.go)
- Configuration: [pkg/agent/config.go](pkg/agent/config.go)
- eBPF Loader: [pkg/ebpf/tracer.go](pkg/ebpf/tracer.go)
- Flow Tracer: [pkg/tracer/tracer.go](pkg/tracer/tracer.go)
- Flow Accounting: [pkg/flow/account.go](pkg/flow/account.go)
- Deduplication: [pkg/flow/deduper.go](pkg/flow/deduper.go)
- Interface Watcher: [pkg/ifaces/watcher.go](pkg/ifaces/watcher.go)
- Main eBPF Flow Code: [bpf/flows.c](bpf/flows.c)
- eBPF Headers: [bpf/flow.h](bpf/flow.h)
- Flow Proto: [proto/flow.proto](proto/flow.proto)
- Config Docs: [docs/config.md](docs/config.md)

**Version Requirements:**
- Kernel: 5.8+ with eBPF enabled
- Go: Check [Makefile](Makefile) `GO_VERSION` variable (currently 1.25.3)
- Clang/LLVM: For eBPF compilation
- Docker/Podman: For containerization

## AI Workflow Example

```
1. Research: "Explain how RTT calculation works in the eBPF code"
2. Plan: "Add packet retransmission tracking - suggest implementation"
3. Implement: "Add TCP retransmit counter to bpf/flows.c and update bindings"
4. Review: "Check for eBPF verifier compatibility and performance impact"
5. Test: "Add unit tests and e2e test with retransmission scenarios"
6. Verify: "Test on different kernel versions and with real traffic"
```

## Contribution Checklist

Before commit:
1. Run `make lint test` (all tests pass)
2. Format code: `make fmt`
3. Regenerate eBPF if C code changed: `make docker-generate`
4. Regenerate protobuf if .proto changed: `make gen-protobuf`
5. Update documentation (docs/config.md, README.md)
6. Test with real traffic or e2e tests
7. Verify all export modes work
8. Run `make vendors` to update dependencies
9. Conventional commit messages

## Common Pitfalls

**eBPF Code:**
- Exceeding eBPF verifier instruction limits
- Unbounded loops (must be bounded for verifier)
- Missing bounds checks on array/map access
- Not regenerating Go bindings after C changes
- Forgetting GPL v2 license header
- Using kernel functions not available in older kernels

**Go Code:**
- Not handling all export modes
- Missing environment variable validation
- Hardcoding values instead of using configuration
- Not closing file descriptors or network connections
- Race conditions in concurrent code
- Breaking backward compatibility in exports
- Not updating documentation

**General:**
- Forgetting to commit generated files (pkg/ebpf/bpf_*)
- Testing only one export mode
- Not testing with realistic traffic volumes
- Missing capability requirements in deployment manifests
- Not considering performance impact
- Assuming specific kernel version features

## Resources

- [README.md](README.md) - Setup, build, deployment
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [Configuration Docs](docs/config.md) - Environment variables
- [RTT Documentation](docs/rtt_calculations.md) - RTT feature details
- [Flow Filtering](docs/flow_filtering.md) - Filter configuration
- [E2E Tests](e2e/README.md) - End-to-end testing guide
- [NetObserv Operator](https://github.com/netobserv/network-observability-operator) - Deploys this agent
- [Flowlogs Pipeline](https://github.com/netobserv/flowlogs-pipeline) - Flow collector and processor
- [eBPF Documentation](https://ebpf.io/) - eBPF concepts and guides
- [Cilium eBPF Library](https://github.com/cilium/ebpf) - Go eBPF library used

**Remember**: AI agents need clear context. This is a performance-sensitive,
kernel-level network monitoring tool. Always consider eBPF constraints, test
thoroughly across kernel versions and export modes, and prioritize performance.
Review generated code carefully, especially eBPF changes that affect kernel execution.
