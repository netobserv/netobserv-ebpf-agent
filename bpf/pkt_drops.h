/*
    Packet Drops using trace points.
*/

#ifndef __PKT_DROPS_H__
#define __PKT_DROPS_H__

#include "utils.h"

static inline int trace_pkt_drop(void *ctx, struct sock *sk,
                                 struct sk_buff *skb,
                                 enum skb_drop_reason reason) {
    if (sk == NULL)
        return 0;

    flow_id id;
    __builtin_memset(&id, 0, sizeof(id));

    u8 state = 0, protocol = 0;
    u16 family = 0,flags = 0;

    // pull in details from the packet headers and the sock struct
    bpf_probe_read(&state, sizeof(u8), (u8 *)&sk->__sk_common.skc_state);

    id.if_index = skb->skb_iif;

    // read L2 info
    set_key_with_l2_info(skb, &id, &family);

    // read L3 info
    set_key_with_l3_info(skb, family, &id, &protocol);

    // read L4 info
    switch (protocol) {
        case IPPROTO_TCP:
            set_key_with_tcp_info(skb, &id, protocol, &flags);
            break;
        case IPPROTO_UDP:
            set_key_with_udp_info(skb, &id, protocol);
            break;
        case IPPROTO_SCTP:
            set_key_with_sctp_info(skb, &id, protocol);
            break;
        case IPPROTO_ICMP:
            set_key_with_icmpv4_info(skb, &id, protocol);
            break;
        case IPPROTO_ICMPV6:
            set_key_with_icmpv6_info(skb, &id, protocol);
            break;
        default:
            return 0;
    }

    long ret = 0;
    for (direction_t dir = INGRESS; dir < MAX_DIRECTION; dir++) {
        id.direction = dir;
        ret = pkt_drop_lookup_and_update_flow(skb, &id, state, flags, reason);
        if (ret == 0) {
            return 0;
        }
    }
    // there is no matching flows so lets create new one and add the drops
    u64 current_time = bpf_ktime_get_ns();
    id.direction = INGRESS;
    flow_metrics new_flow = {
        .start_mono_time_ts = current_time,
        .end_mono_time_ts = current_time,
        .flags = flags,
        .pkt_drops.packets = 1,
        .pkt_drops.bytes = skb->len,
        .pkt_drops.latest_state = state,
        .pkt_drops.latest_flags = flags,
        .pkt_drops.latest_drop_cause = reason,
    };
    ret = bpf_map_update_elem(&aggregated_flows, &id, &new_flow, BPF_ANY);
    if (trace_messages && ret != 0) {
        bpf_printk("error packet drop creating new flow %d\n", ret);
    }

    return ret;
}

SEC("tracepoint/skb/kfree_skb")
int kfree_skb(struct trace_event_raw_kfree_skb *args) {
    struct sk_buff skb;
    __builtin_memset(&skb, 0, sizeof(skb));

    bpf_probe_read(&skb, sizeof(struct sk_buff), args->skbaddr);
    struct sock *sk = skb.sk;
    enum skb_drop_reason reason = args->reason;

    // SKB_NOT_DROPPED_YET,
    // SKB_CONSUMED,
    // SKB_DROP_REASON_NOT_SPECIFIED,
    if (reason > SKB_DROP_REASON_NOT_SPECIFIED) {
        return trace_pkt_drop(args, sk, &skb, reason);
    }
    return 0;
}

#endif //__PKT_DROPS_H__
