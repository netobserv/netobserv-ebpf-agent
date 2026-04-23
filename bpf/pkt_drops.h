/*
    Packet Drops using trace points.
*/

#ifndef __PKT_DROPS_H__
#define __PKT_DROPS_H__

#include "utils.h"

static inline long pkt_drop_lookup_and_update_flow(flow_id *id, u8 state, u16 flags,
                                                   enum skb_drop_reason reason, u64 len) {
    pkt_drop_metrics *extra_metrics = bpf_map_lookup_elem(&aggregated_flows_pkt_drop, id);
    if (extra_metrics != NULL) {
        extra_metrics->end_mono_time_ts = bpf_ktime_get_ns();
        extra_metrics->packets += 1;
        extra_metrics->bytes += len;
        extra_metrics->latest_state = state;
        extra_metrics->latest_flags = flags;
        extra_metrics->latest_drop_cause = reason;
        return 0;
    }
    return -1;
}

static inline int trace_pkt_drop(void *ctx, u8 state, struct sk_buff *skb,
                                 enum skb_drop_reason reason) {
    flow_id id;
    __builtin_memset(&id, 0, sizeof(id));
    u16 eth_protocol = 0;

    u8 protocol = 0, dscp = 0;
    u16 family = 0, flags = 0;

    u32 if_index = BPF_CORE_READ(skb, skb_iif);
    // filter out TCP sockets with unknown or loopback interface
    if (if_index == 0 || if_index == 1) {
        return 0;
    }
    // read L2 info
    core_fill_in_l2(skb, &eth_protocol, &family);

    // read L3 info
    core_fill_in_l3(skb, &id, family, &protocol, &dscp);

    // read L4 info
    switch (protocol) {
    case IPPROTO_TCP:
        core_fill_in_tcp(skb, &id, &flags);
        break;
    case IPPROTO_UDP:
        core_fill_in_udp(skb, &id);
        break;
    case IPPROTO_SCTP:
        core_fill_in_sctp(skb, &id);
        break;
    case IPPROTO_ICMP:
        core_fill_in_icmpv4(skb, &id);
        break;
    case IPPROTO_ICMPV6:
        core_fill_in_icmpv6(skb, &id);
        break;
    default:
        return 0;
    }

    // check if this packet need to be filtered if filtering feature is enabled
    bool skip = check_and_do_flow_filtering(&id, flags, reason, eth_protocol, NULL, 0);
    if (skip) {
        return 0;
    }
    u64 len = BPF_CORE_READ(skb, len);
    long ret = pkt_drop_lookup_and_update_flow(&id, state, flags, reason, len);
    if (ret == 0) {
        return 0;
    }
    // there is no matching flows so lets create new one and add the drops
    u64 current_time = bpf_ktime_get_ns();
    pkt_drop_metrics new_flow;
    __builtin_memset(&new_flow, 0, sizeof(new_flow));
    new_flow.start_mono_time_ts = current_time;
    new_flow.end_mono_time_ts = current_time;
    new_flow.eth_protocol = eth_protocol;
    new_flow.packets = 1;
    new_flow.bytes = len;
    new_flow.latest_state = state;
    new_flow.latest_flags = flags;
    new_flow.latest_drop_cause = reason;
    ret = bpf_map_update_elem(&aggregated_flows_pkt_drop, &id, &new_flow, BPF_NOEXIST);
    if (ret != 0) {
        if (trace_messages && ret != -EEXIST) {
            bpf_printk("error packet drop creating new flow %d\n", ret);
        }
        if (ret == -EEXIST) {
            ret = pkt_drop_lookup_and_update_flow(&id, state, flags, reason, len);
            if (ret != 0 && trace_messages) {
                bpf_printk("error packet drop updating an existing flow %d\n", ret);
            }
        }
    }

    return ret;
}

SEC("tracepoint/skb/kfree_skb")
int kfree_skb(struct trace_event_raw_kfree_skb *args) {
    if (do_sampling == 0) {
        return 0;
    }

    struct sk_buff *skb = (struct sk_buff *)BPF_CORE_READ(args, skbaddr);
    struct sock *sk = (struct sock *)BPF_CORE_READ(skb, sk);
    enum skb_drop_reason reason = args->reason;

    // SKB_NOT_DROPPED_YET,
    // SKB_CONSUMED,
    // SKB_DROP_REASON_NOT_SPECIFIED,
    if (reason > SKB_DROP_REASON_NOT_SPECIFIED) {
        u8 state = 0;
        if (sk) {
            // pull in details from the packet headers and the sock struct
            bpf_probe_read_kernel(&state, sizeof(u8), (u8 *)&sk->__sk_common.skc_state);
        }
        return trace_pkt_drop(args, state, skb, reason);
    }
    return 0;
}

#endif //__PKT_DROPS_H__
