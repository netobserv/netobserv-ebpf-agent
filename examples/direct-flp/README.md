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

To start a collector, you can start another (standalone) instance of flowlogs-pipeline, configured with an IPFIX ingester and logging on stdout.

Example for [FLP repo](https://github.com/netobserv/flowlogs-pipeline):

```bash
./flowlogs-pipeline --config=contrib/local/ipfix-collector-stdout.yaml
```
