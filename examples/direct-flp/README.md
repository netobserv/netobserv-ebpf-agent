## Simple example using direct-flp + stdout

```bash
export FLP_CONFIG=$(cat ./examples/direct-flp/simple-stdout.json)
export EXPORT="direct-flp"
sudo -E bin/netobserv-ebpf-agent
```

## Example using direct-flp + IPFIX (requires an IPFIX collector)

```bash
export FLP_CONFIG=$(cat ./examples/direct-flp/ipfix.json)
export EXPORT="direct-flp"
sudo -E bin/netobserv-ebpf-agent
```

## Local direct-flp with RTT, DNS, packet drops, and Prometheus (Docker)

The directory [prometheus-local](./prometheus-local/) runs the agent with `EXPORT=direct-flp`, enables RTT, DNS, packet-drop, IPsec, and TLS tracking in the agent, embeds flowlogs-pipeline with a `encode/prom` stage on **port 9102**, and starts a dedicated Prometheus (UI on **9091**) that scrapes those metrics from the host. Full documentation (FLP metric names, Prometheus recording rules, example alert, PromQL, ports, and files) is in [prometheus-local/README.md](./prometheus-local/README.md).

```bash
make compile
./examples/direct-flp/prometheus-local/run-example.sh
```

Packet drop tracking needs tracepoint access to `/sys/kernel/debug` (typically mount it read-write and run with sufficient privileges). See [docs/config.md](../../docs/config.md) and the main [README.md](../../README.md) for capability and troubleshooting notes.

To start a collector, you can start another (standalone) instance of flowlogs-pipeline, configured with an IPFIX ingester and logging on stdout.

Example for [FLP repo](https://github.com/netobserv/flowlogs-pipeline):

```bash
./flowlogs-pipeline --config=contrib/local/ipfix-collector-stdout.yaml
```
