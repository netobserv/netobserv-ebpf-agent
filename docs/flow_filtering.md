# eBPF Rule Based Filtering

## Introduction 

Rules-base filtering is a method to control the flow of packets cached in the eBPF flows table based on certain configuration.

## Filter rule configuration

Filtering must be enabled with the environment variable `ENABLE_FLOW_FILTER` set to `true`, and `FLOW_FILTER_RULES` containing a list of rules in JSON format. For instance, you can create a `filters.json` file such as:

```json
[
    {
        "ip_cidr":"0.0.0.0/0",
        "action": "Accept"
    }
]
```

And set environment variables:

```bash
export ENABLE_FLOW_FILTER="true"
export FLOW_FILTER_RULES=$(cat filters.json)
```
 
### Mandatory parameter

- `ip_cidr` - IP address and CIDR mask for the flow filter rule, supports IPv4 and IPv6 address format.
  If wanted to match against any IP, user can use `0.0.0.0/0` or `::/0` for IPv4 and IPv6 respectively.

### Optional parameters

- `action` - Action to be taken for the flow filter rule. Possible values are `Accept` (default) and `Reject`.
  - For the matching rule with `Accept` action this flow will be allowed to be cached in eBPF table, with updated global metric `FilterAcceptCounter`.
  - For the matching rule with `Reject` action this flow will not be cached in eBPF table, with updated global metric `FilterRejectCounter`.
- `direction` - Direction of the flow filter rule. Possible values are `Ingress` and `Egress`.
- `protocol` - Protocol of the flow filter rule. Possible values are `TCP`, `UDP`, `SCTP`, `ICMP`, `ICMPv6`.
- `source_port` - Single Source port of the flow filter rule.
- `source_port_range` - Source port range of the flow filter rule. using "80-100" format.
- `source_ports` - Source port two values of the flow filter rule. using "80,100" format.
- `destination_port` - Single Destination port of the flow filter rule.
- `destination_port_range` - Destination port range of the flow filter rule. using "80-100" format.
- `destination_ports` - Destination port two values of the flow filter rule. using "80,100" format.
- `port` - Single L4 port of the flow filter rule can be either source or destination port.
- `port_range` - L4 port range of the flow filter rule. using "80–100" format can be either a source or destination ports range.
- `ports` - Two ports values of the flow filter rule. using "80,100" format can be either two ports for src or two ports for destination.
- `icmp_type` - ICMP type of the flow filter rule.
- `icmp_code` - ICMP code of the flow filter rule.
- `peer_ip` - Specific Peer IP address of the flow filter rule. Do not use with `peer_cidr` (this parameters is internally translated into a `peer_cidr`).
- `peer_cidr` - Specific Peer IP CIDR of the flow filter rule.
- `tcp_flags` - Filter based on TCP flags Possible values are SYN, SYN-ACK, ACK, FIN, RST, PSH, URG, ECE, CWR, FIN-ACK, RST_ACK
- `drops` - Filter flows when packets drop feature is enabled to filter only flows with drop cause not 0.

Note: 
- for L4 ports configuration, you can use either single port config options or the range but not both.
- use either specific src and/or dst ports or the generic port config that works for both directions.
- you cannot have two rules with the same combination of `ip_cidr` and `peer_cidr`/`peer_ip`.

## How does Flow Filtering work

### Filter and CIDR Matching

The flow filter examines incoming or outgoing packets and attempts to match the source IP address or the destination IP address
of each packet against a CIDR range specified in the `ip_cidr` parameter. 
If the packet's source or destination IP address falls within the specified CIDR range, the filter takes action based on the configured rules. 
This action could involve allowing the packet to be cached in an eBPF flow table or blocking it.

If an IP matches several rules, **only the one with the longest CIDR prefix is evaluated**. For instance, having a first rule on `10.0.10.0/24` and a second rule on `10.0.0.0/8`, a packet to `10.0.10.15` will be skipped or kept based on the first rule alone, without evaluating the second rule.

### Matching Specific Endpoints with `peer_ip` or `peer_cidr`

The `peer_ip` parameter specifies the IP address of a specific endpoint, while `peer_cidr` specifies subnet for range of endpoints. `peer_ip` is just syntactic sugar for writing a /32 `peer_cidr`.

The `peer_cidr` or `peer_ip` settings are used when you want to filter on both ends of the connection, in combination with `ip_cidr`. Note that "peer" does not necessarily mean "remote" here, it means "the other end" contextually to `ip_cidr`.


### How to fine-tune the flow filter rule configuration?

We have many configuration options available for the flow filter rule configuration, but we can use them in combination to achieve the desired
flow filter rule configuration. Let's use some examples to understand how to fine-tune the flow filter rule configuration.

#### Use-case 1:

Filter k8s service traffic to specific POD IP endpoint.
For example, if we wanted to filter in incoming k8s service traffic coming from source `172.210.150.100` for `SCTP` protocol, 
on specific dport range 80–100, and targeting specific POD IP endpoint at `10.10.10.10` we can use the following configuration:

```json
{
    "ip_cidr": "172.210.150.1/24",
    "action": "Accept",
    "protocol": "SCTP",
    "direction": "Ingress",
    "destination_port_range": "80-100",
    "peer_ip": "10.10.10.10"
}
```
 
#### Use-case 2:

Users wanted to see flows after EgressIP feature is configured with EgressIP `192.168.127.12` for `TCP` protocol with sport `100`
to any cluster's outside addresses (destinations is unknown or don't care), so they can use the following configuration:

```json
{
    "ip_cidr": "0.0.0.0/0",
    "action": "Accept",
    "protocol": "TCP",
    "direction": "Egress",
    "source_port": 100,
    "peer_ip": "192.168.127.12"
}
```

#### Use-case 3:

OpenShift ovn kubernetes CNI uses `169.254.169.1-4` as masquerade addresses when handle host service traffic
I am not interested in capturing any those packets, so I can use the following configuration:

```json
{
    "ip_cidr": "169.254.169.1/24",
    "action": "Reject",
    "direction": "Ingress"
}
```

#### Use-case 4:

We have a case where ping traffic is going between PODA `1.1.1.10` to PODB in different node `1.2.1.10` for that we can use the following configuration:

```json
{
    "ip_cidr": "1.1.1.10/32",
    "action": "Accept",
    "direction": "Ingress",
    "protocol": "ICMP",
    "peer_ip": "1.2.1.10",
    "icmp_type": 8
}
```

#### Use-case 5:

We wanted to filter in `curl` request and response for TCP flow going from PODA `1.1.1.10` to PODB in different node `1.2.1.10` using port `80`
for that we can use the following configuration:

```json
{
    "ip_cidr": "1.1.1.10/32",
    "action": "Accept",
    "protocol": "TCP",
    "port": "80",
    "peer_cidr": "1.2.1.10/32"
}
```
