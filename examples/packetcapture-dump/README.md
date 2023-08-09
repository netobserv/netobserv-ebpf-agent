# packetcapture-client

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
Start the agent using:
```bash
sudo PCA_SERVER_PORT=9990 ENABLE_PCA=true PCA_FILTER=tcp,22 ./bin/netobserv-ebpf-agent
```

Start the packetcapture-client using: (in a secondary shell)
```bash
./bin/packetcapture-client -outfile=capture.pcap
```

You should see output such as:
```bash
Starting Packet Capture Client.
By default, the read packets are printed on stdout.
To write to a pcap file use flag '-outfile=[filename]'
This creates a file [filename] and writes packets to it.
To view captured packets 'tcpdump -r [filename]'.

07-24-2023 07:58:59.264323 : Received Packet of length  24
07-24-2023 07:59:04.268965 : Received Packet of length  410
07-24-2023 07:59:04.269048 : Received Packet of length  644
07-24-2023 07:59:04.269087 : Received Packet of length  224
07-24-2023 07:59:04.269125 : Received Packet of length  82
07-24-2023 07:59:04.269173 : Received Packet of length  148
...
```

To open pcap file:
```bash
tcpdump -r capture.pcap
```



