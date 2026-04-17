# direct-flp with Prometheus (local lab)

This example runs the NetObserv eBPF agent on the host with **`EXPORT=direct-flp`**, embeds [flowlogs-pipeline](https://github.com/netobserv/flowlogs-pipeline) using **`FLP_CONFIG`** from [`flp-prometheus.yaml`](./flp-prometheus.yaml), and starts a **Prometheus** container that scrapes the embedded pipeline’s `/metrics` endpoint.

Optional features are turned on in the runner script for demonstration: **RTT** (`ENABLE_RTT`), **DNS tracking** (`ENABLE_DNS_TRACKING`), **packet drop tracking** (`ENABLE_PKT_DROPS`), **IPsec flow metadata** (`ENABLE_IPSEC_TRACKING`), and **TLS metadata per flow** (`ENABLE_TLS_TRACKING`). See [docs/config.md](../../../docs/config.md) and [pkg/config/config.go](../../../pkg/config/config.go) for all agent environment variables.

IPsec and TLS hooks add eBPF work and only populate fields when matching traffic exists on the traced interfaces; they are enabled here so the corresponding `netobserv_*` series appear in Prometheus when you exercise those protocols. This is **TLS metadata from the agent’s eBPF TLS tracker** (`ENABLE_TLS_TRACKING`), not Kafka or gRPC TLS. Userspace OpenSSL correlation uses `ENABLE_OPENSSL_TRACKING` separately and is not turned on in this script.

## Quick start

From the repository root:

```bash
make compile
./examples/direct-flp/prometheus-local/run-example.sh
```

- **Prometheus UI:** http://127.0.0.1:9091  
- **Embedded FLP metrics:** http://127.0.0.1:9102/metrics  
- **Agent operational metrics:** http://127.0.0.1:9090/metrics (default `METRICS_SERVER_PORT`)

Stop Prometheus: `docker compose -f examples/direct-flp/prometheus-local/docker-compose.yaml down`

## Why two ports (9090 and 9102)

The agent exposes its own Prometheus listener on **`METRICS_SERVER_PORT`** (default **9090**). The embedded flowlogs-pipeline also starts a global metrics HTTP server; if its port is left unset it defaults to **9090** as well and would conflict. [`flp-prometheus.yaml`](./flp-prometheus.yaml) sets **`metricsSettings.port: 9102`** so flow encode metrics are served separately.

## Flow metrics exposed by FLP (`flp-prometheus.yaml`)

All names use the encode prefix **`netobserv_`** (see `prom.prefix` in the file).

| Prometheus metric | Type | When populated | Main labels |
|-------------------|------|----------------|-------------|
| `netobserv_flow_bytes` | gauge | `Bytes` present on the flow | `SrcAddr`, `DstAddr`, `SrcPort`, `DstPort`, `Proto` |
| `netobserv_flow_packets` | gauge | `Packets` present | same as above |
| `netobserv_dns_latency_ms` | gauge | DNS tracking enabled, `DnsLatencyMs` present | `SrcAddr`, `DstAddr`, `DstPort`, `DnsFlagsResponseCode` |
| `netobserv_tcp_flow_rtt_ns` | gauge | RTT enabled, `TimeFlowRttNs` present | `SrcAddr`, `DstAddr`, `DstPort`, `Proto` |
| `netobserv_pkt_drop_packets` | gauge | Packet drop tracking enabled, `PktDropPackets` present | `SrcAddr`, `DstAddr`, `PktDropLatestDropCause` |
| `netobserv_ipsec_flow_bytes` | gauge | IPsec tracking enabled; `IPSecStatus` and `Bytes` present | `SrcAddr`, `DstAddr`, `DstPort`, `Proto`, `IPSecStatus`, `IPSecRetCode` |
| `netobserv_tls_flow_bytes` | gauge | TLS tracking enabled; `TLSVersion` and `Bytes` present | `SrcAddr`, `DstAddr`, `DstPort`, `Proto`, `TLSVersion`, `TLSCipherSuite` |

These are **gauges** reflecting the last value for each label set (with FLP `expiryTime: 5m` cleaning stale series). They are not counters; use aggregations such as `max_over_time` or `topk` rather than `rate()` unless you understand the semantics.

**Cardinality:** labels include IP addresses and ports. This is appropriate for a **local lab** only, not for a large production Prometheus.

**Packet drops:** the agent needs access to kernel tracepoints (typically **`/sys/kernel/debug`** mounted and sufficient privileges). See the main [README.md](../../../README.md) and [docs/config.md](../../../docs/config.md).

## Prometheus rules (`netobserv-rules.yml`)

[`prometheus.yml`](./prometheus.yml) loads [`netobserv-rules.yml`](./netobserv-rules.yml) via `rule_files`.

### Recording rules (precomputed series)

| Recorded metric | Expression (summary) |
|-----------------|----------------------|
| `netobserv:pkt_drop_packets:sum_by_cause` | `sum by (PktDropLatestDropCause) (netobserv_pkt_drop_packets)` |
| `netobserv:tcp_flow_rtt:milliseconds` | `netobserv_tcp_flow_rtt_ns / 1e6` |
| `netobserv:dns_latency_ms:max_over_5m` | `max_over_time(netobserv_dns_latency_ms[5m])` |
| `netobserv:flow_bytes:top10` | `topk(10, netobserv_flow_bytes)` |
| `netobserv:flow_bytes:deriv_2m` | `deriv(netobserv_flow_bytes[2m])` (noisy; exploratory) |
| `netobserv:ipsec_flow_bytes:sum_by_status` | `sum by (IPSecStatus) (netobserv_ipsec_flow_bytes)` |
| `netobserv:tls_flow_bytes:count_by_version` | `count by (TLSVersion) (netobserv_tls_flow_bytes)` |

In the Prometheus UI (**Graph**), you can query these names directly instead of typing the full expression.

### Example alert

| Alert | Condition | Meaning |
|-------|-----------|---------|
| `NetobservNoFlowMetrics` | `absent(netobserv_flow_bytes)` for 3m | No `netobserv_flow_bytes` series (scrape failure, agent stopped, or no flows exported yet). Check the agent, http://127.0.0.1:9102/metrics on the host, and Docker `host.docker.internal` reachability. |

View rule evaluation status under **Status → Rules** and firing alerts under **Alerts**.

## Ad hoc PromQL (raw FLP metrics)

```promql
{__name__=~"netobserv_.*"}
```

```promql
topk(10, netobserv_flow_bytes)
```

```promql
netobserv_tcp_flow_rtt_ns / 1e6
```

```promql
sum by (PktDropLatestDropCause) (netobserv_pkt_drop_packets)
```

```promql
netobserv_ipsec_flow_bytes
```

```promql
topk(5, netobserv_tls_flow_bytes)
```

## Files in this directory

| File | Role |
|------|------|
| [`flp-prometheus.yaml`](./flp-prometheus.yaml) | `FLP_CONFIG`: `metricsSettings` + `encode/prom` pipeline after `preset-ingester` |
| [`prometheus.yml`](./prometheus.yml) | Prometheus scrape config + `rule_files` |
| [`netobserv-rules.yml`](./netobserv-rules.yml) | Recording rules and example alert |
| [`docker-compose.yaml`](./docker-compose.yaml) | Prometheus service and config mounts |
| [`run-example.sh`](./run-example.sh) | Starts Compose, exports env vars, runs the agent with `sudo -E` |

## Prometheus without Docker

Point a local `prometheus.yml` at `127.0.0.1:9102` instead of `host.docker.internal:9102`, and use the same `rule_files` entry with a path to [`netobserv-rules.yml`](./netobserv-rules.yml) on your machine.
