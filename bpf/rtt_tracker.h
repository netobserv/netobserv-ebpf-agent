/*
    A simple RTT tracker implemented using eBPF fentry hook to read RTT from TCP socket.
 */

#ifndef __RTT_TRACKER_H__
#define __RTT_TRACKER_H__

#include <bpf_core_read.h>
#include <bpf_tracing.h>
#include "utils.h"
#include "maps_definition.h"

static inline void rtt_fill_in_l2(struct sk_buff *skb, flow_id *id) {
    struct ethhdr eth;

    __builtin_memset(&eth, 0, sizeof(eth));

    u8 *skb_head = BPF_CORE_READ(skb, head);
    u16 skb_mac_header = BPF_CORE_READ(skb, mac_header);

    bpf_probe_read(&eth, sizeof(eth), (struct ethhdr *)(skb_head + skb_mac_header));
    __builtin_memcpy(id->dst_mac, eth.h_dest, ETH_ALEN);
    __builtin_memcpy(id->src_mac, eth.h_source, ETH_ALEN);
    id->eth_protocol = bpf_ntohs(eth.h_proto);
}

static inline void rtt_fill_in_l3(struct sk_buff *skb, flow_id *id, u16 family, u8 *dscp) {
    u16 skb_network_header = BPF_CORE_READ(skb, network_header);
    u8 *skb_head = BPF_CORE_READ(skb, head);

    switch (family) {
    case AF_INET: {
        struct iphdr ip;
        __builtin_memset(&ip, 0, sizeof(ip));
        bpf_probe_read(&ip, sizeof(ip), (struct iphdr *)(skb_head + skb_network_header));
        __builtin_memcpy(id->src_ip, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(id->dst_ip, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(id->src_ip + sizeof(ip4in6), &ip.saddr, sizeof(ip.saddr));
        __builtin_memcpy(id->dst_ip + sizeof(ip4in6), &ip.daddr, sizeof(ip.daddr));
        *dscp = ipv4_get_dscp(&ip);
        break;
    }
    case AF_INET6: {
        struct ipv6hdr ip;
        __builtin_memset(&ip, 0, sizeof(ip));
        bpf_probe_read(&ip, sizeof(ip), (struct ipv6hdr *)(skb_head + skb_network_header));
        __builtin_memcpy(id->src_ip, ip.saddr.in6_u.u6_addr8, IP_MAX_LEN);
        __builtin_memcpy(id->dst_ip, ip.daddr.in6_u.u6_addr8, IP_MAX_LEN);
        *dscp = ipv6_get_dscp(&ip);
        break;
    }
    default:
        return;
    }
}

static inline void rtt_fill_in_tcp(struct sk_buff *skb, flow_id *id, u16 *flags) {
    u16 skb_transport_header = BPF_CORE_READ(skb, transport_header);
    u8 *skb_head = BPF_CORE_READ(skb, head);
    struct tcphdr tcp;
    u16 sport, dport;

    __builtin_memset(&tcp, 0, sizeof(tcp));

    bpf_probe_read(&tcp, sizeof(tcp), (struct tcphdr *)(skb_head + skb_transport_header));
    sport = bpf_ntohs(tcp.source);
    dport = bpf_ntohs(tcp.dest);
    id->src_port = sport;
    id->dst_port = dport;
    set_flags(&tcp, flags);
    id->transport_protocol = IPPROTO_TCP;
}

static inline int rtt_lookup_and_update_flow(flow_id *id, u16 flags, u64 rtt) {
    flow_metrics *aggregate_flow = bpf_map_lookup_elem(&aggregated_flows, id);
    if (aggregate_flow != NULL) {
        aggregate_flow->end_mono_time_ts = bpf_ktime_get_ns();
        aggregate_flow->flags |= flags;
        if (aggregate_flow->flow_rtt < rtt) {
            aggregate_flow->flow_rtt = rtt;
        }
        long ret = bpf_map_update_elem(&aggregated_flows, id, aggregate_flow, BPF_ANY);
        if (trace_messages && ret != 0) {
            bpf_printk("error rtt updating flow %d\n", ret);
        }
        return 0;
    }
    return -1;
}

static inline int calculate_flow_rtt_tcp(struct sock *sk, struct sk_buff *skb) {
    struct tcp_sock *ts;
    u16 family, flags = 0;
    u64 rtt = 0, len;
    int ret = 0;
    flow_id id;
    u8 dscp = 0;

    if (!enable_rtt) {
        return 0;
    }
    __builtin_memset(&id, 0, sizeof(id));

    id.if_index = BPF_CORE_READ(skb, skb_iif);
    // filter out TCP sockets with unknown or loopback interface
    if (id.if_index == 0 || id.if_index == 1) {
        return 0;
    }
    len = BPF_CORE_READ(skb, len);

    // read L2 info
    rtt_fill_in_l2(skb, &id);

    family = BPF_CORE_READ(sk, __sk_common.skc_family);

    // read L3 info
    rtt_fill_in_l3(skb, &id, family, &dscp);

    // read TCP info
    rtt_fill_in_tcp(skb, &id, &flags);

    // read TCP socket rtt and store it in nanoseconds
    ts = (struct tcp_sock *)(sk);
    rtt = BPF_CORE_READ(ts, srtt_us) >> 3;
    rtt *= 1000u;

    // check if this packet need to be filtered if filtering feature is enabled
    bool skip = check_and_do_flow_filtering(&id);
    if (skip) {
        return 0;
    }

    // update flow with rtt info
    id.direction = INGRESS;
    ret = rtt_lookup_and_update_flow(&id, flags, rtt);
    if (ret == 0) {
        return 0;
    }

    u64 current_ts = bpf_ktime_get_ns();
    flow_metrics new_flow = {
        .packets = 1,
        .bytes = len,
        .start_mono_time_ts = current_ts,
        .end_mono_time_ts = current_ts,
        .flags = flags,
        .flow_rtt = rtt,
        .dscp = dscp,
    };
    ret = bpf_map_update_elem(&aggregated_flows, &id, &new_flow, BPF_ANY);
    if (trace_messages && ret != 0) {
        bpf_printk("error rtt track creating flow %d\n", ret);
    }

    return 0;
}

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv_fentry, struct sock *sk, struct sk_buff *skb) {
    if (sk == NULL || skb == NULL || do_sampling == 0) {
        return 0;
    }
    return calculate_flow_rtt_tcp(sk, skb);
}

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_kprobe, struct sock *sk, struct sk_buff *skb) {
    if (sk == NULL || skb == NULL || do_sampling == 0) {
        return 0;
    }
    return calculate_flow_rtt_tcp(sk, skb);
}

#endif /* __RTT_TRACKER_H__ */
