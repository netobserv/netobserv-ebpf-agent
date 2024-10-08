# eBPF Rule Based Filtering

## Introduction 

Rule-base filtering is a method to control the flow of packets cached in the eBPF flows table based on certain configuration

## Filter rule configuration

 The filter rule consists of two parts mandatory and optional parameters.
 
### Mandatory parameters

- `FILTER_IP_CIDR` - IP address and CIDR mask for the flow filter rule, supports IPv4 and IPv6 address format.
  If wanted to match against any IP, user can use `0.0.0.0/0` or `::/0` for IPv4 and IPv6 respectively.
- `FILTER_ACTION` - Action to be taken for the flow filter rule. Possible values are `Accept` and `Reject`.
  - For the matching rule with `Accept` action this flow will be allowed to be cached in eBPF table, with updated global metric `FilterAcceptCounter`.
  - For the matching rule with `Reject` action this flow will not be cached in eBPF table, with updated global metric `FilterRejectCounter`.
  - If the rule is not matched, based on the configured action if its `Accept` the flow will not be cached in eBPF table, 
   if the action is `Reject` then the flow will be cached in the eBPF table and a global metric `FilterNoMatchCounter` will be updated.

### Optional parameters

- `FILTER_DIRECTION` - Direction of the flow filter rule. Possible values are `Ingress` and `Egress`.
- `FILTER_PROTOCOL` - Protocol of the flow filter rule. Possible values are `TCP`, `UDP`, `SCTP`, `ICMP`, `ICMPv6`.
- `FILTER_SOURCE_PORT` - Single Source port of the flow filter rule.
- `FILTER_SOURCE_PORT_RANGE` - Source port range of the flow filter rule. using "80-100" format.
- `FILTER_SOURCE_PORTS` - Source port two values of the flow filter rule. using "80,100" format.
- `FILTER_DESTINATION_PORT` - Single Destination port of the flow filter rule.
- `FILTER_DESTINATION_PORT_RANGE` - Destination port range of the flow filter rule. using "80-100" format.
- `FILTER_DESTINATION_PORTS` - Destination port two values of the flow filter rule. using "80,100" format.
- `FILTER_PORT` - Single L4 port of the flow filter rule can be either source or destination port.
- `FILTER_PORT_RANGE` - L4 port range of the flow filter rule. using "80–100" format can be either a source or destination ports range.
- `FILTER_PORTS` - Two ports values of the flow filter rule. using "80,100" format can be either two ports for src or two ports for destination.
- `FILTER_ICMP_TYPE` - ICMP type of the flow filter rule.
- `FILTER_ICMP_CODE` - ICMP code of the flow filter rule.
- `FILTER_PEER_IP` - Specific Peer IP address of the flow filter rule.
- `FILTER_TCP_FLAGS` - Filter based on TCP flags Possible values are SYN, SYN-ACK, ACK, FIN, RST, PSH, URG, ECE, CWR, FIN-ACK, RST_ACK
- `FILTER_DROPS` - Filter flows when packets drop feature is enabled to filter only flows with drop cause not 0.

Note: 
- for L4 ports configuration, you can use either single port config options or the range but not both.
- use either specific src and/or dst ports or the generic port config that works for both directions.

## How does Flow Filtering work

### Filter and CIDR Matching

The flow filter examines incoming or outgoing packets and attempts to match the source IP address or the destination IP address
of each packet against a CIDR range specified in the `FILTER_IP_CIDR` parameter. 
If the packet's source or destination IP address falls within the specified CIDR range, the filter takes action based on the configured rules. 
This action could involve allowing the packet to be cached in an eBPF flow table or blocking it.

### Matching Specific Endpoints with `FILTER_PEER_IP`

The `FILTER_PEER_IP` parameter specifies the IP address of a specific endpoint.
Depending on whether the traffic is ingress (incoming) or egress (outgoing), this IP address is used to further refine
the filtering process:
- In ingress traffic filtering, the `FILTER_PEER_IP` is used to match against the destination IP address of the packet. 
After the initial CIDR matching, the filter then narrows down the scope to packets destined for a specific endpoint
specified by `FLOW_FILTER_PEER_IP`.
- In egress traffic filtering, the `FILTER_PEER_IP` is used to match against the source IP address of the packet.
After the initial CIDR matching, the filter narrows down the scope to packets originating from a specific endpoint
specified by `FILTER_PEER_IP`.

### How to fine-tune the flow filter rule configuration?

We have many configuration options available for the flow filter rule configuration, but we can use them in combination to achieve the desired
flow filter rule configuration. Let's use some examples to understand how to fine-tune the flow filter rule configuration.

#### Use-case 1:

Filter k8s service traffic to specific POD IP endpoint.
For example, if we wanted to filter in incoming k8s service traffic coming from source `172.210.150.100` for `SCTP` protocol, 
on specific dport range 80–100, and targeting specific POD IP endpoint at `10.10.10.10` we can use the following configuration:

```shell
    FILTER_IP_CIDR=172.210.150.1/24
    FILTER_ACTION=Accept
    FILTER_PROTOCOL=SCTP
    FILTER_DIRECTION=Ingress
    FILTER_DESTINATION_PORT_RANGE=80-100
    FILTER_PEER_IP=10.10.10.10
```
 
#### Use-case 2:

Users wanted to see flows after EgressIP feature is configured with EgressIP `192.168.127.12` for `TCP` protocol with sport `100`
to any cluster's outside addresses (destinations is unknown or don't care), so they can use the following configuration:

```shell
    FILTER_IP_CIDR=0.0.0.0/0
    FILTER_ACTION=Accept
    FILTER_PROTOCOL=TCP
    FILTER_DIRECTION=Egress
    FILTER_SOURCE_PORT=100
    FILTER_PEER_IP=192.168.127.12
```

#### Use-case 3:

OpenShift ovn kubernetes CNI uses `169.254.169.1-4` as masquerade addresses when handle host service traffic
I am not interested in capturing any those packets, so I can use the following configuration:

```shell
    FILTER_IP_CIDR=169.254.169.1/24
    FILTER_ACTION=Reject
    FILTER_DIRECTION=Ingress
```

#### Use-case 4:

We have a case where ping traffic is going between PODA `1.1.1.10` to PODB in different node `1.2.1.10` for that we can use the following configuration:

```shell
    FILTER_IP_CIDR=1.1.1.10/32
    FILTER_ACTION=Accept
    FILTER_DIRECTION=Ingress
    FILTER_PROTOCOL=ICMP
    FILTER_PEER_IP=1.2.1.10
    FILTER_ICMP_TYPE=8
```

#### Use-case 5:

We wanted to filter in `curl` request and response for TCP flow going from PODA `1.1.1.10` to PODB in different node `1.2.1.10` using port `80`
for that we can use the following configuration:

```shell
    FILTER_IP_CIDR=1.1.1.10/32
    FILTER_ACTION=Accept
    FILTER_PROTOCOL=TCP
    FILTER_PORT=80
    FILTER_PEER_IP=1.2.1.10
```
