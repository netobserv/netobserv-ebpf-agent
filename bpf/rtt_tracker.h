/*
    A simple RTT tracker implemented using eBPF fentry hook to read RTT from TCP socket.
 */

#ifndef __RTT_TRACKER_H__
#define __RTT_TRACKER_H__

#include <bpf_tracing.h>
#include "utils.h"
#include "maps_definition.h"

static inline int rtt_lookup_and_update_flow(flow_id *id, u64 rtt) {
    additional_metrics *extra_metrics = bpf_map_lookup_elem(&additional_flow_metrics, id);
    if (extra_metrics != NULL) {
        if (extra_metrics->flow_rtt < rtt) {
            extra_metrics->flow_rtt = rtt;
        }
        return 0;
    }
    return -1;
}

static inline int calculate_flow_rtt_tcp(struct sock *sk, struct sk_buff *skb) {
    u8 dscp = 0, protocol = 0;
    struct tcp_sock *ts;
    u16 family = 0, flags = 0, eth_protocol = 0;
    u64 rtt = 0;
    int ret = 0;
    flow_id id;

    if (!enable_rtt) {
        return 0;
    }
    __builtin_memset(&id, 0, sizeof(id));

    u32 if_index = BPF_CORE_READ(skb, skb_iif);
    // filter out TCP sockets with unknown or loopback interface
    if (if_index == 0 || if_index == 1) {
        return 0;
    }

    // read L2 info
    core_fill_in_l2(skb, &eth_protocol, &family);

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
    bool skip = check_and_do_flow_filtering(&id, flags, 0, eth_protocol);
    if (skip) {
        return 0;
    }

    // update flow with rtt info
    ret = rtt_lookup_and_update_flow(&id, rtt);
    if (ret == 0) {
        return 0;
    }

    additional_metrics new_flow = {
        .flow_rtt = rtt,
    };
    ret = bpf_map_update_elem(&additional_flow_metrics, &id, &new_flow, BPF_NOEXIST);
    if (ret != 0) {
        if (trace_messages && ret != -EEXIST) {
            bpf_printk("error rtt track creating flow %d\n", ret);
        }
        if (ret == -EEXIST) {
            ret = rtt_lookup_and_update_flow(&id, rtt);
            if (trace_messages && ret != 0) {
                bpf_printk("error rtt track updating an existing flow %d\n", ret);
            }
        }
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
