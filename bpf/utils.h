#ifndef __UTILS_H__
#define __UTILS_H__

#include <bpf_core_read.h>
#include "types.h"
#include "maps_definition.h"
#include "flows_filter.h"

static u64 do_sampling = 0;

// Update global counter for hashmap update errors
static inline void increase_counter(u32 key) {
    u32 *error_counter_p = NULL;
    u32 initVal = 1;
    error_counter_p = bpf_map_lookup_elem(&global_counters, &key);
    if (!error_counter_p) {
        bpf_map_update_elem(&global_counters, &key, &initVal, BPF_ANY);
    } else {
        __sync_fetch_and_add(error_counter_p, 1);
    }
}

// sets the TCP header flags for connection information
static inline void set_flags(struct tcphdr *th, u16 *flags) {
    //If both ACK and SYN are set, then it is server -> client communication during 3-way handshake.
    if (th->ack && th->syn) {
        *flags |= SYN_ACK_FLAG;
    } else if (th->ack && th->fin) {
        // If both ACK and FIN are set, then it is graceful termination from server.
        *flags |= FIN_ACK_FLAG;
    } else if (th->ack && th->rst) {
        // If both ACK and RST are set, then it is abrupt connection termination.
        *flags |= RST_ACK_FLAG;
    } else if (th->fin) {
        *flags |= FIN_FLAG;
    } else if (th->syn) {
        *flags |= SYN_FLAG;
    } else if (th->ack) {
        *flags |= ACK_FLAG;
    } else if (th->rst) {
        *flags |= RST_FLAG;
    } else if (th->psh) {
        *flags |= PSH_FLAG;
    } else if (th->urg) {
        *flags |= URG_FLAG;
    } else if (th->ece) {
        *flags |= ECE_FLAG;
    } else if (th->cwr) {
        *flags |= CWR_FLAG;
    }
}

// Extract L4 info for the supported protocols
static inline void fill_l4info(void *l4_hdr_start, void *data_end, u8 protocol, pkt_info *pkt) {
    flow_id *id = pkt->id;
    id->transport_protocol = protocol;
    switch (protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = l4_hdr_start;
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            id->src_port = bpf_ntohs(tcp->source);
            id->dst_port = bpf_ntohs(tcp->dest);
            set_flags(tcp, &pkt->flags);
            pkt->l4_hdr = (void *)tcp;
        }
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp = l4_hdr_start;
        if ((void *)udp + sizeof(*udp) <= data_end) {
            id->src_port = bpf_ntohs(udp->source);
            id->dst_port = bpf_ntohs(udp->dest);
            pkt->l4_hdr = (void *)udp;
        }
    } break;
    case IPPROTO_SCTP: {
        struct sctphdr *sctph = l4_hdr_start;
        if ((void *)sctph + sizeof(*sctph) <= data_end) {
            id->src_port = bpf_ntohs(sctph->source);
            id->dst_port = bpf_ntohs(sctph->dest);
            pkt->l4_hdr = (void *)sctph;
        }
    } break;
    case IPPROTO_ICMP: {
        struct icmphdr *icmph = l4_hdr_start;
        if ((void *)icmph + sizeof(*icmph) <= data_end) {
            id->icmp_type = icmph->type;
            id->icmp_code = icmph->code;
            pkt->l4_hdr = (void *)icmph;
        }
    } break;
    case IPPROTO_ICMPV6: {
        struct icmp6hdr *icmp6h = l4_hdr_start;
        if ((void *)icmp6h + sizeof(*icmp6h) <= data_end) {
            id->icmp_type = icmp6h->icmp6_type;
            id->icmp_code = icmp6h->icmp6_code;
            pkt->l4_hdr = (void *)icmp6h;
        }
    } break;
    default:
        break;
    }
}

static inline u8 ipv4_get_dscp(const struct iphdr *iph) {
    return (iph->tos >> DSCP_SHIFT) & DSCP_MASK;
}

static inline u8 ipv6_get_dscp(const struct ipv6hdr *ipv6h) {
    return ((bpf_ntohs(*(const __be16 *)ipv6h) >> 4) >> DSCP_SHIFT) & DSCP_MASK;
}

// sets flow fields from IPv4 header information
static inline int fill_iphdr(struct iphdr *ip, void *data_end, pkt_info *pkt) {
    void *l4_hdr_start;

    l4_hdr_start = (void *)ip + sizeof(*ip);
    if (l4_hdr_start > data_end) {
        return DISCARD;
    }
    flow_id *id = pkt->id;
    /* Save the IP Address to id directly. copy once. */
    __builtin_memcpy(id->src_ip, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(id->dst_ip, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(id->src_ip + sizeof(ip4in6), &ip->saddr, sizeof(ip->saddr));
    __builtin_memcpy(id->dst_ip + sizeof(ip4in6), &ip->daddr, sizeof(ip->daddr));
    pkt->dscp = ipv4_get_dscp(ip);
    /* fill l4 header which will be added to id in flow_monitor function.*/
    fill_l4info(l4_hdr_start, data_end, ip->protocol, pkt);
    return SUBMIT;
}

// sets flow fields from IPv6 header information
static inline int fill_ip6hdr(struct ipv6hdr *ip, void *data_end, pkt_info *pkt) {
    void *l4_hdr_start;

    l4_hdr_start = (void *)ip + sizeof(*ip);
    if (l4_hdr_start > data_end) {
        return DISCARD;
    }
    flow_id *id = pkt->id;
    /* Save the IP Address to id directly. copy once. */
    __builtin_memcpy(id->src_ip, ip->saddr.in6_u.u6_addr8, IP_MAX_LEN);
    __builtin_memcpy(id->dst_ip, ip->daddr.in6_u.u6_addr8, IP_MAX_LEN);
    pkt->dscp = ipv6_get_dscp(ip);
    /* fill l4 header which will be added to id in flow_monitor function.*/
    fill_l4info(l4_hdr_start, data_end, ip->nexthdr, pkt);
    return SUBMIT;
}

// sets flow fields from Ethernet header information
static inline int fill_ethhdr(struct ethhdr *eth, void *data_end, pkt_info *pkt,
                              u16 *eth_protocol) {
    if ((void *)eth + sizeof(*eth) > data_end) {
        return DISCARD;
    }
    *eth_protocol = bpf_ntohs(eth->h_proto);

    if (*eth_protocol == ETH_P_IP) {
        struct iphdr *ip = (void *)eth + sizeof(*eth);
        return fill_iphdr(ip, data_end, pkt);
    } else if (*eth_protocol == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);
        return fill_ip6hdr(ip6, data_end, pkt);
    }
    // Only IP-based flows are managed
    return DISCARD;
}

static inline bool is_filter_enabled() {
    if (enable_flows_filtering || enable_pca) {
        return true;
    }
    return false;
}

/*
 * check if flow filter is enabled and if we need to continue processing the packet or not
 */
static __always_inline bool check_and_do_flow_filtering(flow_id *id, u16 flags, u32 drop_reason,
                                                        u16 eth_protocol, u32 *sampling,
                                                        u8 direction) {
    // check if this packet need to be filtered if filtering feature is enabled
    if (is_filter_enabled()) {
        filter_action action = ACCEPT;
        if (is_flow_filtered(id, &action, flags, drop_reason, eth_protocol, sampling, direction) !=
                0 &&
            action != MAX_FILTER_ACTIONS) {
            // we have matching rules follow through the actions to decide if we should accept or reject the flow
            // and update global counter for both cases
            bool skip = false;
            u32 key = 0;

            switch (action) {
            case REJECT:
                key = FILTER_REJECT;
                skip = true;
                break;
            case ACCEPT:
                key = FILTER_ACCEPT;
                break;
            // should never come here
            case MAX_FILTER_ACTIONS:
                return true;
            }

            // update global counter for flows dropped by filter
            increase_counter(key);
            if (skip) {
                return true;
            }
        } else {
            // we have no matching rules so we update global counter for flows that are not matched by any rule
            increase_counter(FILTER_NOMATCH);
            // we have accept rule but no match so we can't let mismatched flows in the hashmap table or
            // we have no match at all and the action is the default value MAX_FILTER_ACTIONS.
            if (action == ACCEPT || action == MAX_FILTER_ACTIONS) {
                return true;
            } else {
                // we have reject rule and no match so we can add the flows to the hashmap table.
            }
        }
    }
    return false;
}

static inline void core_fill_in_l2(struct sk_buff *skb, u16 *eth_protocol, u16 *family) {
    struct ethhdr eth;

    __builtin_memset(&eth, 0, sizeof(eth));

    u8 *skb_head = BPF_CORE_READ(skb, head);
    u16 skb_mac_header = BPF_CORE_READ(skb, mac_header);

    bpf_probe_read_kernel(&eth, sizeof(eth), (struct ethhdr *)(skb_head + skb_mac_header));
    *eth_protocol = bpf_ntohs(eth.h_proto);
    if (*eth_protocol == ETH_P_IP) {
        *family = AF_INET;
    } else if (*eth_protocol == ETH_P_IPV6) {
        *family = AF_INET6;
    }
}

static inline void core_fill_in_l3(struct sk_buff *skb, flow_id *id, u16 family, u8 *protocol,
                                   u8 *dscp) {
    u16 skb_network_header = BPF_CORE_READ(skb, network_header);
    u8 *skb_head = BPF_CORE_READ(skb, head);

    switch (family) {
    case AF_INET: {
        struct iphdr ip;
        __builtin_memset(&ip, 0, sizeof(ip));
        bpf_probe_read_kernel(&ip, sizeof(ip), (struct iphdr *)(skb_head + skb_network_header));
        __builtin_memcpy(id->src_ip, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(id->dst_ip, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(id->src_ip + sizeof(ip4in6), &ip.saddr, sizeof(ip.saddr));
        __builtin_memcpy(id->dst_ip + sizeof(ip4in6), &ip.daddr, sizeof(ip.daddr));
        *dscp = ipv4_get_dscp(&ip);
        *protocol = ip.protocol;
        break;
    }
    case AF_INET6: {
        struct ipv6hdr ip;
        __builtin_memset(&ip, 0, sizeof(ip));
        bpf_probe_read_kernel(&ip, sizeof(ip), (struct ipv6hdr *)(skb_head + skb_network_header));
        __builtin_memcpy(id->src_ip, ip.saddr.in6_u.u6_addr8, IP_MAX_LEN);
        __builtin_memcpy(id->dst_ip, ip.daddr.in6_u.u6_addr8, IP_MAX_LEN);
        *dscp = ipv6_get_dscp(&ip);
        *protocol = ip.nexthdr;
        break;
    }
    default:
        return;
    }
}

static inline void core_fill_in_tcp(struct sk_buff *skb, flow_id *id, u16 *flags) {
    u16 skb_transport_header = BPF_CORE_READ(skb, transport_header);
    u8 *skb_head = BPF_CORE_READ(skb, head);
    struct tcphdr tcp;
    u16 sport, dport;

    __builtin_memset(&tcp, 0, sizeof(tcp));

    bpf_probe_read_kernel(&tcp, sizeof(tcp), (struct tcphdr *)(skb_head + skb_transport_header));
    sport = bpf_ntohs(tcp.source);
    dport = bpf_ntohs(tcp.dest);
    id->src_port = sport;
    id->dst_port = dport;
    set_flags(&tcp, flags);
    id->transport_protocol = IPPROTO_TCP;
}

static inline void core_fill_in_udp(struct sk_buff *skb, flow_id *id) {
    u16 skb_transport_header = BPF_CORE_READ(skb, transport_header);
    u8 *skb_head = BPF_CORE_READ(skb, head);
    struct udphdr udp;
    u16 sport, dport;

    __builtin_memset(&udp, 0, sizeof(udp));

    bpf_probe_read_kernel(&udp, sizeof(udp), (struct udphdr *)(skb_head + skb_transport_header));
    sport = bpf_ntohs(udp.source);
    dport = bpf_ntohs(udp.dest);
    id->src_port = sport;
    id->dst_port = dport;
    id->transport_protocol = IPPROTO_UDP;
}

static inline void core_fill_in_sctp(struct sk_buff *skb, flow_id *id) {
    u16 skb_transport_header = BPF_CORE_READ(skb, transport_header);
    u8 *skb_head = BPF_CORE_READ(skb, head);
    struct sctphdr sctp;
    u16 sport, dport;

    __builtin_memset(&sctp, 0, sizeof(sctp));

    bpf_probe_read_kernel(&sctp, sizeof(sctp), (struct sctphdr *)(skb_head + skb_transport_header));
    sport = bpf_ntohs(sctp.source);
    dport = bpf_ntohs(sctp.dest);
    id->src_port = sport;
    id->dst_port = dport;
    id->transport_protocol = IPPROTO_SCTP;
}

static inline void core_fill_in_icmpv4(struct sk_buff *skb, flow_id *id) {
    u16 skb_transport_header = BPF_CORE_READ(skb, transport_header);
    u8 *skb_head = BPF_CORE_READ(skb, head);
    struct icmphdr icmph;
    __builtin_memset(&icmph, 0, sizeof(icmph));

    bpf_probe_read_kernel(&icmph, sizeof(icmph),
                          (struct icmphdr *)(skb_head + skb_transport_header));
    id->icmp_type = icmph.type;
    id->icmp_code = icmph.code;
    id->transport_protocol = IPPROTO_ICMP;
}

static inline void core_fill_in_icmpv6(struct sk_buff *skb, flow_id *id) {
    u16 skb_transport_header = BPF_CORE_READ(skb, transport_header);
    u8 *skb_head = BPF_CORE_READ(skb, head);
    struct icmp6hdr icmph;
    __builtin_memset(&icmph, 0, sizeof(icmph));

    bpf_probe_read_kernel(&icmph, sizeof(icmph),
                          (struct icmp6hdr *)(skb_head + skb_transport_header));
    id->icmp_type = icmph.icmp6_type;
    id->icmp_code = icmph.icmp6_code;
    id->transport_protocol = IPPROTO_ICMPV6;
}

static inline void fill_in_others_protocol(flow_id *id, u8 protocol) {
    id->transport_protocol = protocol;
}

static inline bool is_transport_protocol(u8 protocol) {
    switch (protocol) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
    case IPPROTO_SCTP:
        return true;
    }
    return false;
}

#endif // __UTILS_H__
