## Simple example filtering on a single IP

```bash
export ENABLE_FLOW_FILTER="true"
export FLOW_FILTER_RULES=$(cat ./examples/filters/single-ip.json)
sudo -E bin/netobserv-ebpf-agent
```
