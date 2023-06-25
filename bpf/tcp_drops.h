/*
    TCPDrops using trace points.
*/

#ifndef __TCP_DROPS_H__
#define __TCP_DROPS_H__

#include "utils.h"

static inline int trace_tcp_drop(void *ctx, struct sock *sk,
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

    // We only support TCP drops for any other protocol just return w/o doing anything
    if (protocol != IPPROTO_TCP) {
        return 0;
    }

    // read L4 info
    set_key_with_tcp_info(skb, &id, protocol, &flags);

    long ret = 0;
    for (direction_t dir = INGRESS; dir < MAX_DIRECTION; dir++) {
        id.direction = dir;
        ret = tcp_drop_lookup_and_update_flow(skb, &id, state, flags, reason);
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
        .tcp_drops.packets = 1,
        .tcp_drops.bytes = skb->len,
        .tcp_drops.latest_state = state,
        .tcp_drops.latest_flags = flags,
        .tcp_drops.latest_drop_cause = reason,
    };
    ret = bpf_map_update_elem(&aggregated_flows, &id, &new_flow, BPF_ANY);
    if (trace_messages && ret != 0) {
        bpf_printk("error tcp drop creating new flow %d\n", ret);
    }

    return ret;
}

#endif //__TCP_DROPS_H__
