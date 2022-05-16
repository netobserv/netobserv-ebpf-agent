#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include "flow.h"

#define DISCARD 1
#define SUBMIT 0

// according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
#define INGRESS 0
#define EGRESS 1

// TODO: for performance reasons, replace the ring buffer by a hashmap and
// aggregate the flows here instead of the Go Accounter
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} flows SEC(".maps");

// Constant definitions, to be overridden by the invoker
volatile const u32 sampling = 0;

// sets flow fields from IPv4 header information
static inline int fill_iphdr(struct iphdr *ip, void *data_end, struct flow *flow) {
    if ((void *)ip + sizeof(*ip) > data_end) {
        return DISCARD;
    }

    flow->network.v4ip.src_ip = __bpf_ntohl(ip->saddr);
    flow->network.v4ip.dst_ip = __bpf_ntohl(ip->daddr);
    flow->transport.protocol = ip->protocol;

    switch (ip->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            flow->transport.src_port = __bpf_ntohs(tcp->source);
            flow->transport.dst_port = __bpf_ntohs(tcp->dest);
        }
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) <= data_end) {
            flow->transport.src_port = __bpf_ntohs(udp->source);
            flow->transport.dst_port = __bpf_ntohs(udp->dest);
        }
    } break;
    default:
        break;
    }
    return SUBMIT;
}

// sets flow fields from IPv6 header information
static inline int fill_ip6hdr(struct ipv6hdr *ip, void *data_end, struct flow *flow) {
    if ((void *)ip + sizeof(*ip) > data_end) {
        return DISCARD;
    }

    flow->network.v6ip.src_ip6 = ip->saddr;
    flow->network.v6ip.dst_ip6 = ip->daddr;
    flow->transport.protocol = ip->nexthdr;

    switch (ip->nexthdr) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            flow->transport.src_port = __bpf_ntohs(tcp->source);
            flow->transport.dst_port = __bpf_ntohs(tcp->dest);
        }
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) <= data_end) {
            flow->transport.src_port = __bpf_ntohs(udp->source);
            flow->transport.dst_port = __bpf_ntohs(udp->dest);
        }
    } break;
    default:
        break;
    }
    return SUBMIT;
}
// sets flow fields from Ethernet header information
static inline int fill_ethhdr(struct ethhdr *eth, void *data_end, struct flow *flow) {
    if ((void *)eth + sizeof(*eth) > data_end) {
        return DISCARD;
    }
    __builtin_memcpy(flow->data_link.dst_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(flow->data_link.src_mac, eth->h_source, ETH_ALEN);
    flow->protocol = __bpf_ntohs(eth->h_proto);
    // TODO: ETH_P_IPV6
    if (flow->protocol == ETH_P_IP) {
        struct iphdr *ip = (void *)eth + sizeof(*eth);
        return fill_iphdr(ip, data_end, flow);
    } else if (flow->protocol == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);
        return fill_ip6hdr(ip6, data_end, flow);
    }
    return SUBMIT;
}

// parses flow information for a given direction (ingress/egress)
static inline int flow_parse(struct __sk_buff *skb, u8 direction) {

    // If sampling is defined, will only parse 1 out of "sampling" flows
    if (sampling != 0 && (bpf_get_prandom_u32() % sampling) != 0) {
        return TC_ACT_OK;
    }

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct flow *flow = bpf_ringbuf_reserve(&flows, sizeof(struct flow), 0);
    if (!flow) {
        return TC_ACT_OK;
    }

    struct ethhdr *eth = data;
    if (fill_ethhdr(eth, data_end, flow) == DISCARD) {
        bpf_ringbuf_discard(flow, 0);
    } else {
        flow->direction = direction;
        flow->bytes = skb->len;
        bpf_ringbuf_submit(flow, 0);
    }
    return TC_ACT_OK;
}

SEC("tc/ingress_flow_parse")
static inline int ingress_flow_parse(struct __sk_buff *skb) {
    return flow_parse(skb, INGRESS);
}

SEC("tc/egress_flow_parse")
static inline int egress_flow_parse(struct __sk_buff *skb) {
    return flow_parse(skb, EGRESS);
}

char __license[] SEC("license") = "GPL";
