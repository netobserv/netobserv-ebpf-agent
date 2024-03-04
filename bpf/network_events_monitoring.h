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

static inline bool md_already_exists(u8 network_events[MAX_NETWORK_EVENTS][MAX_EVENT_MD], u8 *md) {
    for (u8 i = 0; i < MAX_NETWORK_EVENTS; i++) {
        if (__builtin_memcmp(network_events[i], md, MAX_EVENT_MD) == 0) {
            return true;
        }
    }
    return false;
}

static inline int trace_network_events(struct sk_buff *skb, struct rh_psample_metadata *md) {
    u8 dscp = 0, protocol = 0, md_len = 0;
    u16 family = 0, flags = 0;
    u8 *user_cookie = NULL;
    u8 cookie[MAX_EVENT_MD];
    long ret = 0;
    u64 len = 0;
    flow_id id;

    __builtin_memset(&id, 0, sizeof(id));
    __builtin_memset(cookie, 0, sizeof(cookie));

    md_len = BPF_CORE_READ(md, user_cookie_len);
    user_cookie = (u8 *)BPF_CORE_READ(md, user_cookie);
    if (md_len == 0 || md_len > MAX_EVENT_MD || user_cookie == NULL) {
        return -1;
    }

    bpf_probe_read(cookie, md_len, user_cookie);

    id.if_index = BPF_CORE_READ(md, in_ifindex);

    len = BPF_CORE_READ(skb, len);

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
        fill_in_others_protocol(&id, protocol);
    }

    for (direction dir = INGRESS; dir < MAX_DIRECTION; dir++) {
        id.direction = dir;
        flow_metrics *aggregate_flow = bpf_map_lookup_elem(&aggregated_flows, &id);
        if (aggregate_flow != NULL) {
            u8 idx = aggregate_flow->network_events_idx;
            aggregate_flow->end_mono_time_ts = bpf_ktime_get_ns();
            // Needed to check length here again to keep JIT verifier happy
            if (idx < MAX_NETWORK_EVENTS && md_len <= MAX_EVENT_MD) {
                if (!md_already_exists(aggregate_flow->network_events, (u8 *)cookie)) {
                    __builtin_memcpy(aggregate_flow->network_events[idx], cookie, MAX_EVENT_MD);
                    aggregate_flow->network_events_idx = (idx + 1) % MAX_NETWORK_EVENTS;
                }
                ret = bpf_map_update_elem(&aggregated_flows, &id, aggregate_flow, BPF_ANY);
                if (ret == 0) {
                    return 0;
                }
            } else {
                return -1;
            }
        }
    }

    if (ret != 0) {
        if (trace_messages) {
            bpf_printk("error network events updating existing flow %d\n", ret);
        }
        return ret;
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

static inline void update_network_events_statistics(u32 *key, u32 *value) {
    u32 *error_counter_p = NULL;
    error_counter_p = bpf_map_lookup_elem(&global_counters, key);
    if (!error_counter_p) {
        bpf_map_update_elem(&global_counters, key, value, BPF_ANY);
        return;
    }
    __sync_fetch_and_add(error_counter_p, 1);
}

// for older kernel will use `rh_psample_sample_packet` to avoid kapis issues
SEC("kprobe/rh_psample_sample_packet")
int BPF_KPROBE(rh_network_events_monitoring, struct psample_group *group, struct sk_buff *skb,
               u32 sample_rate, struct rh_psample_metadata *md) {
    u32 initVal = 1, key = NETWORK_EVENTS_ERR_KEY;
    if (enable_network_events_monitoring == 0 || do_sampling == 0) {
        return 0;
    }
    if (skb == NULL || md == NULL || group == NULL) {
        update_network_events_statistics(&key, &initVal);
        return 0;
    }
    // filter out none matching samples with different groupid
    int group_id = BPF_CORE_READ(group, group_num);
    if (group_id != network_events_monitoring_groupid) {
        key = NETWORK_EVENTS_ERR_GROUPID_MISMATCH;
        update_network_events_statistics(&key, &initVal);
        return 0;
    }
    long ret = 0;
    if ((ret = trace_network_events(skb, md)) != 0) {
        key = NETWORK_EVENTS_ERR_UPDATE_MAP_FLOWS;
        update_network_events_statistics(&key, &initVal);
        return 0;
    }
    key = NETWORK_EVENTS_GOOD;
    update_network_events_statistics(&key, &initVal);
    return 0;
}
/*
SEC("kprobe/psample_sample_packet")
int BPF_KPROBE(network_events_monitoring, struct psample_group *group, struct sk_buff *skb, u32 sample_rate,
               struct psample_metadata *md) {
    u32 initVal = 1, key = NETWORK_EVENTS_ERR_KEY;
    if (enable_network_events_monitoring == 0 || do_sampling == 0) {
        return 0;
    }
    if (skb == NULL || md == NULL || group == NULL) {
        update_network_events_statistics(&key, &initVal);
        return 0;
    }
    // filter out none matching samples with different groupid
    int group_id = BPF_CORE_READ(group, group_num);
    if (group_id != network_events_monitoring_groupid) {
        key = NETWORK_EVENTS_ERR_GROUPID_MISMATCH;
        update_network_events_statistics(&key, &initVal);
        return 0;
    }

    long ret = 0;
    if ((ret = trace_network_events(skb, md)) != 0) {
        key = NETWORK_EVENTS_ERR_UPDATE_MAP_FLOWS;
        update_network_events_statistics(&key, &initVal);
        return 0;
    }
    key = NETWORK_EVENTS_GOOD;
    update_network_events_statistics(&key, &initVal);
    return 0;
}
*/
#endif /* __NETWORK_EVENTS_MONITORING_H__ */
