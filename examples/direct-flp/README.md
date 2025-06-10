## Simple example using direct-flp + stdout

```bash
export FLP_CONFIG=$(cat ./examples/direct-flp/simple-stdout.json)
export EXPORT="direct-flp"
sudo -E bin/netobserv-ebpf-agent
```
