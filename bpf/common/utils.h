#ifndef __COMMON_UTILS_H__
#define __COMMON_UTILS_H__

#include <bpf_core_read.h>
#include "types.h"

#define ENOENT 2
#define EEXIST 17
#define EINVAL 22

#define AF_INET 2
#define AF_INET6 10
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_ARP 0x0806
#define IPPROTO_ICMPV6 58
#define DSCP_SHIFT 2
#define DSCP_MASK 0x3F

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_UNSPEC -1

#define DISCARD 1
#define SUBMIT 0

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_ntohs(x) (x)
#define bpf_htons(x) (x)
#define bpf_ntohl(x) (x)
#define bpf_htonl(x) (x)
#else
#error "Endianness detection needs to be set up for your compiler?!"
#endif

static u8 do_sampling = 0;
const static u8 ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

static inline u8 ipv4_get_dscp(const struct iphdr *iph) {
    return (iph->tos >> DSCP_SHIFT) & DSCP_MASK;
}

static inline u8 ipv6_get_dscp(const struct ipv6hdr *ipv6h) {
    return ((bpf_ntohs(*(const __be16 *)ipv6h) >> 4) >> DSCP_SHIFT) & DSCP_MASK;
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

static inline void core_fill_in_l3(struct sk_buff *skb, flow_id *id, u16 family, u8 *protocol, u8 *dscp) {
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

    bpf_probe_read_kernel(&icmph, sizeof(icmph), (struct icmphdr *)(skb_head + skb_transport_header));
    id->icmp_type = icmph.type;
    id->icmp_code = icmph.code;
    id->transport_protocol = IPPROTO_ICMP;
}

static inline void core_fill_in_icmpv6(struct sk_buff *skb, flow_id *id) {
    u16 skb_transport_header = BPF_CORE_READ(skb, transport_header);
    u8 *skb_head = BPF_CORE_READ(skb, head);
    struct icmp6hdr icmph;
    __builtin_memset(&icmph, 0, sizeof(icmph));

    bpf_probe_read_kernel(&icmph, sizeof(icmph), (struct icmp6hdr *)(skb_head + skb_transport_header));
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

static inline bool is_ipv4(u8 *ip) {
    for (int i = 0; i < IP_MAX_LEN; i++) {
        if (ip[i] == 255) {
            return true;
        }
    }
    return false;
}

static inline u16 add_len_u16(u16 old, u64 add) {
    if (add > 65535) {
        return 65535;
    }
    u16 n = old + (u16)add;
    return n < add ? 65535 : n;
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
static inline int fill_ethhdr(struct ethhdr *eth, void *data_end, pkt_info *pkt, u16 *eth_protocol) {
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

#endif // __COMMON_UTILS_H__
