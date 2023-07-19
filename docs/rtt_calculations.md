# RTT calculations done by ebpf-agent

This agent has the capablity to perform Round-Trip-Time calculations for packet flows. Currently the agent will capture and report RTT for tcp handshake only
but can be extended to any other protocol.

The design of the system is like this,
1. For every SYN packet that gets detected at Egress, the agent will capture standard 4-tuple information and packet sequence id and put it into a `flow_sequences` ebpf map as key and the value of which will be set to timestamp the packet was detected.

1. Now for every ACK packet that gets detected at Ingress, the agent will check if the 4-tuple information (reversed for incoming flow) and sequence id (sequence id of ACK - 1) is present in the `flow_sequences` hashmap, if so it will calculate the handshake RTT as,
`rtt = ack-timestampack - syn-timestamp(from map)`

1. This approach is very simple but can be extended to perform continous RTT tracking for a TCP flow or perform RTT tracking for any other protocol like, ICMP etc.

This rtt in flow logs is reported as, actual RTT for the flow logs which is present and can be calculated (handshake packets), zero for flows where it is not calculated yet (any protocols other than TCP) or is not present (non handshake tcp packets).

## Concerns

### Packet Retransmissions:

In case of packet retransmissions the behavior of tracker is as follows,

1. If SYN packet is retransmitted only the last SYN packet is taken into account which is correct behavior.

1. If ACK packet is retransmitted the last ACK will be considered (the ACK which finally got received by receiver),
in that case while the behavior of our program is as expected, because receiver will only see one and the last ACK but
the RTT reported by the receiver will be much higher than the actual number.
For now, this is an erroneous case and can be fixed later by doing either continous or multiple RTT monitoring per flow.