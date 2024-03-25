# flowlogs-dump (like tcpdump)

## How to run 

From the root directory of the project: 

Build the agent (the flowlogs client that uses ebpf) using:
```bash
make build
```
Build the flowlogs-dump-collector (the server that receives logs from the agent and dumps to screen) using:
```bash
go build -mod vendor -o bin/flowlogs-dump-collector examples/flowlogs-dump/server/flowlogs-dump-collector.go  
```
Start the agent using:
```bash
sudo TARGET_HOST=127.0.0.1 TARGET_PORT=9999 ./bin/netobserv-ebpf-agent
```

Start the flowlogs-dump-collector using: (in a secondary shell)
```bash
./bin/flowlogs-dump-collector -listen_port=9999
```

You should see output such as:
```bash
starting flowlogs-dump-collector on port 9999
13:31:38.857689 eth0 IP 192.168.50.88:5353 > 224.0.0.251:5353: proto:2048 dir:0 bytes:384 packets:2 ends: 13:31:38.859561
13:31:38.858447 eth0 IP 0.0.0.0:0 > 0.0.0.0:0: proto:34525 dir:0 bytes:424 packets:2 ends: 13:31:38.860284
13:31:37.409071 eth0 IP 192.168.50.16:2221 > 192.168.50.88:59239: proto:2048 dir:1 bytes:371806 packets:403 ends: 13:31:42.342690
13:31:37.408148 eth0 IP 192.168.50.88:59239 > 192.168.50.16:2221: proto:2048 dir:0 bytes:16926 packets:277 ends: 13:31:42.390777
...
```



