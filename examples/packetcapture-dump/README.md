# Packet Capture TCP Client

## How to run 

From the root directory of the project: 

Build the agent (the flowlogs client that uses ebpf) using:
```bash
make build
```
Build the packetcapture-dump-collector (the client that receives full packets from the agent and writes to a pcap file) using:
```bash
go build -mod vendor -o bin/packetcapture-client examples/packetcapture-dump/client/packetcapture-client.go  
```
Start the packetcapture-client using: (in a secondary shell)
```bash
./bin/packetcapture-client -outfile=capture.pcap
```

Start the agent using:
```bash
sudo TARGET_HOST=localhost TARGET_PORT=9990 ENABLE_PCA="true" FLOW_FILTER_RULES='[{"ip_cidr":"0.0.0.0/0","protocol":"TCP","action":"Accept"}]' ./bin/netobserv-ebpf-agent

```

You should see output such as:
```bash
Starting Packet Capture Client.
By default, the read packets are printed on stdout.
To write to a pcap file use flag '-outfile=[filename]'
This creates a file [filename] and writes packets to it.
To view captured packets 'tcpdump -r [filename]'.
writting into capture.pcap
03-22-2024 10:48:44.941828 : Received Packet of length  136
03-22-2024 10:48:44.942901 : Received Packet of length  106
03-22-2024 10:48:44.943597 : Received Packet of length  110
03-22-2024 10:48:44.944182 : Received Packet of length  70
03-22-2024 10:48:44.944447 : Received Packet of length  70
03-22-2024 10:48:44.944644 : Received Packet of length  138
...
```

To open pcap file:
```bash
tcpdump -r capture.pcap
```



