/*
    A simple RTT tracker implemented using eBPF fentry hook to read RTT from TCP socket.
 */

#ifndef __RTT_TRACKER_H__
#define __RTT_TRACKER_H__

#include <bpf_tracing.h>
#include "utils.h"
#include "maps_definition.h"

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
    u8 dscp = 0, protocol = 0;
    struct tcp_sock *ts;
    u16 family = 0, flags = 0;
    u64 rtt = 0, len;
    int ret = 0;
    flow_id id;

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
    core_fill_in_l2(skb, &id, &family);

    // read L3 info
    core_fill_in_l3(skb, &id, family, &protocol, &dscp);

    if (protocol != IPPROTO_TCP) {
        return 0;
    }

    // read TCP info
    core_fill_in_tcp(skb, &id, &flags);

    // read TCP socket rtt and store it in nanoseconds
    ts = (struct tcp_sock *)(sk);
    rtt = BPF_CORE_READ(ts, srtt_us) >> 3;
    rtt *= 1000u;

    // check if this packet need to be filtered if filtering feature is enabled
    bool skip = check_and_do_flow_filtering(&id, flags, 0);
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
