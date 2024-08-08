/*
 * Network events monitoring kprobe eBPF hook.
 */

#ifndef __NETWORK_EVENTS_MONITORING_H__
#define __NETWORK_EVENTS_MONITORING_H__

#include "utils.h"

struct rh_psample_metadata {
    u32 trunc_size;
    int in_ifindex;
    int out_ifindex;
    u16 out_tc;
    u64 out_tc_occ; /* bytes */
    u64 latency;    /* nanoseconds */
    u8 out_tc_valid : 1, out_tc_occ_valid : 1, latency_valid : 1, rate_as_probability : 1,
        unused : 4;
    const u8 *user_cookie;
    u32 user_cookie_len;
};

static inline int trace_network_events(struct sk_buff *skb, struct rh_psample_metadata *md) {
    u8 dscp = 0, protocol = 0, md_len = 0;
    u16 family = 0, flags = 0;
    u8 *user_cookie = NULL;
    u64 len = 0;
    flow_id id;

    __builtin_memset(&id, 0, sizeof(id));

    md_len = BPF_CORE_READ(md, user_cookie_len);
    user_cookie = (u8 *)BPF_CORE_READ(md, user_cookie);
    if (md_len == 0 || md_len > MAX_EVENT_MD || user_cookie == NULL) {
        return 0;
    }

    id.if_index = BPF_CORE_READ(skb, skb_iif);
    // filter out sockets with unknown or loopback interface
    if (id.if_index == 0 || id.if_index == 1) {
        return 0;
    }
    len = BPF_CORE_READ(skb, len);
    if (len == 0) {
        return 0;
    }

    // read L2 info
    core_fill_in_l2(skb, &id, &family);

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

    long ret = 0;

    for (direction dir = INGRESS; dir < MAX_DIRECTION; dir++) {
        id.direction = dir;
        flow_metrics *aggregate_flow = bpf_map_lookup_elem(&aggregated_flows, &id);
        if (aggregate_flow != NULL) {
            u8 idx = aggregate_flow->network_events_idx;
            // Needed to check length here again to keep JIT verifier happy
            if (idx < MAX_NETWORK_EVENTS && md_len < MAX_EVENT_MD) {
                aggregate_flow->end_mono_time_ts = bpf_ktime_get_ns();
                bpf_probe_read(aggregate_flow->network_events[idx], md_len, user_cookie);
                aggregate_flow->network_events_idx = (idx + 1) % MAX_NETWORK_EVENTS;
                ret = bpf_map_update_elem(&aggregated_flows, &id, aggregate_flow, BPF_ANY);
                if (ret == 0) {
                    return 0;
                }
            }
        }
    }
    // there is no matching flows so lets create new one and add the network event metadata
    u64 current_time = bpf_ktime_get_ns();
    id.direction = INGRESS;
    flow_metrics new_flow = {
        .packets = 1,
        .bytes = len,
        .start_mono_time_ts = current_time,
        .end_mono_time_ts = current_time,
        .flags = flags,
        .network_events_idx = 0,
    };
    bpf_probe_read(new_flow.network_events[0], md_len, user_cookie);
    new_flow.network_events_idx++;
    ret = bpf_map_update_elem(&aggregated_flows, &id, &new_flow, BPF_ANY);
    if (trace_messages && ret != 0) {
        bpf_printk("error network events creating new flow %d\n", ret);
    }
    return ret;
}

// for older kernel will use `rh_psample_sample_packet` to avoid kapis issues
SEC("kprobe/rh_psample_sample_packet")
int BPF_KPROBE(rh_network_events_monitoring, struct psample_group *group, struct sk_buff *skb,
               u32 sample_rate, struct rh_psample_metadata *md) {
    if (enable_network_events_monitoring == 0 || do_sampling == 0) {
        return 0;
    }
    if (skb == NULL || md == NULL || group == NULL) {
        return 0;
    }
    // filter out none matching samples with different groupid
    int group_id = BPF_CORE_READ(group, group_num);
    if (group_id != network_events_monitoring_groupid) {
        return 0;
    }

    return trace_network_events(skb, md);
}
/*
SEC("kprobe/psample_sample_packet")
int BPF_KPROBE(network_events_monitoring, struct psample_group *group, struct sk_buff *skb, u32 sample_rate,
               struct psample_metadata *md) {
    if (enable_network_events_monitoring == 0 || do_sampling == 0) {
        return 0;
    }
    if (skb == NULL || md == NULL || group == NULL) {
        return 0;
    }
    // filter out none matching samples with different groupid
    int group_id = BPF_CORE_READ(group, group_num);
    if (group_id != network_events_monitoring_groupid) {
        return 0;
    }

    return trace_network_events(skb, md);
}
*/
#endif /* __NETWORK_EVENTS_MONITORING_H__ */
