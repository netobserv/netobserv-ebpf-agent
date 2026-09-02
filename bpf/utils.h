#ifndef __UTILS_H__
#define __UTILS_H__

#include <bpf_core_read.h>
#include "types.h"
#include "maps_definition.h"
#include "common/filter.h"
#include "common/packet_utils.h"

static u8 do_sampling = 0;

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

#endif // __UTILS_H__
