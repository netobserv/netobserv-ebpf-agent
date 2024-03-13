/*
 * OVS monitoring trace point eBPF hook.
 */

#ifndef __OVS_MONITORING_H__
#define __OVS_MONITORING_H__
#include "utils.h"

struct sw_flow_key {
    u64 key [2];
};

static inline int trace_ovs_dp(struct sk_buff *skb, struct sw_flow_key *key) {
    flow_id id;
    __builtin_memset(&id, 0, sizeof(id));

    u8 protocol = 0;
    u16 family = 0,flags = 0;

    id.if_index = skb->skb_iif;
    // filter out TCP sockets with unknown or loopback interface
    if (id.if_index == 0 || id.if_index == 1) {
        return 0;
    }
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
        flow_metrics *aggregate_flow = bpf_map_lookup_elem(&aggregated_flows, &id);
        if (aggregate_flow != NULL) {
            aggregate_flow->ovs_dp_keys[0] = BPF_CORE_READ(key, key[0]);
            aggregate_flow->ovs_dp_keys[1] = BPF_CORE_READ(key, key[1]);
            ret = bpf_map_update_elem(&aggregated_flows, &id, aggregate_flow, BPF_ANY);
            if (ret == 0) {
                return 0;
            }
        }
    }
    // there is no matching flows so lets create new one and add the ovs datapath keys
    u64 current_time = bpf_ktime_get_ns();
    id.direction = INGRESS;
    flow_metrics new_flow = {
        .start_mono_time_ts = current_time,
        .end_mono_time_ts = current_time,
        .flags = flags,
        .ovs_dp_keys[0] = key->key[0],
        .ovs_dp_keys[1] = key->key[1],
    };
    ret = bpf_map_update_elem(&aggregated_flows, &id, &new_flow, BPF_ANY);
    if (trace_messages && ret != 0) {
        bpf_printk("error ovs datapath creating new flow %d\n", ret);
    }

    return ret;
}

SEC("tracepoint/openvswitch/ovs_dp_monitor")
int ovs_dp_monitor(struct sk_buff *skb, struct sw_flow_key *key) {
    return trace_ovs_dp(skb, key);
}

#endif /* __OVS_MONITORING_H__ */
