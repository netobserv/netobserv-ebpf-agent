# Packet capture (PCA)

Operational guide for running the agent in packet capture mode. For kernel/userspace architecture and package layout, see [packets/architecture.md](./packets/architecture.md).

## Mode selection

Set `ENABLE_PCA=true` at startup. The agent loads the packet BPF object ([`bpf/packets/packets.c`](../bpf/packets/packets.c)) instead of the flow object. See [architecture.md](./architecture.md) for how the two modes compare.

## Deployment

Packet capture is typically deployed as a DaemonSet or dedicated agent instance with `ENABLE_PCA=true`. The [network-observability-cli](https://github.com/netobserv/network-observability-cli) triggers on-demand captures against agents running in PCA mode.

Required capabilities match flow mode (`BPF`, `PERFMON`, `NET_ADMIN`) unless the host distribution requires privileged mode.

## Configuration

| Variable | Description |
|----------|-------------|
| `ENABLE_PCA` | Enable packet capture mode (`true` / `false`) |
| `EXPORT` | `grpc` (default) or `direct-flp` |
| `TARGET_HOST` / `TARGET_PORT` | Packet collector endpoint for gRPC export |
| `FLOW_FILTER_RULES` | JSON filter rules (shared syntax with flow mode) |
| `SAMPLING` | Packet sampling rate (same semantics as flow mode) |
| `CACHE_MAX_FLOWS` / `CACHE_ACTIVE_TIMEOUT` | Batch size and flush interval for packet records |

Flow-only options are rejected at startup in PCA mode. See the incompatible-options list in [packets/architecture.md](./packets/architecture.md).

Full env var reference: [config.md](./config.md).

## Examples

See [examples/packetcapture-dump/](../examples/packetcapture-dump/) for a minimal gRPC client that receives `PacketRecord` messages.

### OpenSSL connection identity

OpenSSL events carry a local-first socket tuple captured in the kernel during the TLS call, exported as `TupleSource: "kernel"`. This requires a successful `SSL_set_fd` observed by the agent. `SSL_free` and BIO replacement invalidate the binding. Connections opened before probe attachment or using unsupported BIO setup can still produce plaintext, but have no verified tuple.

The agent does not guess another connection from `/proc` or read a queued event's SSL pointer/descriptor from userspace: both can have been reused before the event is processed. Consumers must not treat filter-derived endpoints as verified connection identity. `Direction` remains the `read`/`write` TLS operation; read tuples must be reversed for network-oriented output.
