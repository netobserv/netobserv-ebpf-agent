/*
    kTLS tracker
*/
#include "utils.h"

#ifndef __KTLS_TRACKER_H__
#define __KTLS_TRACKER_H__

#define MAX_SOCK_OPS_MAP_ENTRIES 65535
struct sock_key {
    u8 remote_ip[IP_MAX_LEN];
    u8 local_ip[IP_MAX_LEN];
    u32 remote_port;
    u32 local_port;
    u32 family;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, MAX_SOCK_OPS_MAP_ENTRIES);
    __type(key, struct sock_key);
    __type(value, u64);
} sock_hash SEC(".maps");

static __always_inline void bpf_sock_ops_ip(struct bpf_sock_ops *skops) {
    int ret;

    struct sock_key skk = {
        .local_port = skops->local_port,
        .remote_port = bpf_ntohl(skops->remote_port),
        .family = skops->family,
    };

    switch (skops->family) {
    case AF_INET:
        __builtin_memcpy(skk.remote_ip, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(skk.local_ip, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(skk.remote_ip + sizeof(ip4in6), &skops->remote_ip4,
                         sizeof(skops->remote_ip4));
        __builtin_memcpy(skk.local_ip + sizeof(ip4in6), &skops->local_ip4,
                         sizeof(skops->local_ip4));
        break;
    case AF_INET6:
        return;
    }

    ret = bpf_sock_hash_update(skops, &sock_hash, &skk, BPF_NOEXIST);
    if (ret) {
        bpf_printk("failed to update sock hash op: %d, port %d --> %d\n", skops->op, skk.local_port,
                   skk.remote_port);
        return;
    }
}

SEC("sockops")
int bpf_sockops(struct bpf_sock_ops *skops) {
    u32 op = skops->op;

    switch (op) {
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        bpf_sock_ops_ip(skops);
        break;
    default:
        break;
    }

    return 0;
}

static __always_inline int find_update_flow(struct sk_msg_md *msg, int verdict) {
    int ret = 0;
    flow_id id;

    __builtin_memset(&id, 0, sizeof(id));

    id.src_port = msg->sk->src_port;
    id.dst_port = bpf_ntohs(msg->sk->dst_port);
    id.transport_protocol = msg->sk->protocol;
    __builtin_memcpy(id.src_ip, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(id.dst_ip, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(id.src_ip + sizeof(ip4in6), &msg->sk->src_ip4, sizeof(msg->sk->src_ip4));
    __builtin_memcpy(id.dst_ip + sizeof(ip4in6), &msg->sk->dst_ip4, sizeof(msg->sk->dst_ip4));

    u64 current_ts = bpf_ktime_get_ns();
    additional_metrics *aggregate_flow =
        (additional_metrics *)bpf_map_lookup_elem(&additional_flow_metrics, &id);
    if (aggregate_flow != NULL) {
        aggregate_flow->end_mono_time_ts = current_ts;
        if (aggregate_flow->start_mono_time_ts == 0) {
            aggregate_flow->start_mono_time_ts = current_ts;
        }
        aggregate_flow->verdict = verdict;
        ret = bpf_map_update_elem(&additional_flow_metrics, &id, aggregate_flow, BPF_ANY);
    } else {
        additional_metrics new_flow = {
            .start_mono_time_ts = current_ts,
            .end_mono_time_ts = current_ts,
            .verdict = verdict,
        };
        ret = bpf_map_update_elem(&additional_flow_metrics, &id, &new_flow, BPF_ANY);
    }
    return ret;
}

SEC("sk_msg")
int bpf_ktls_redir(struct sk_msg_md *msg) {
    struct sock_key skk = {
        .local_port = bpf_ntohl(msg->remote_port),
        .remote_port = msg->local_port,
        .family = msg->family,
    };

    switch (msg->family) {
    case AF_INET:
        __builtin_memcpy(skk.remote_ip, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(skk.local_ip, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(skk.remote_ip + sizeof(ip4in6), &msg->remote_ip4, sizeof(msg->remote_ip4));
        __builtin_memcpy(skk.local_ip + sizeof(ip4in6), &msg->local_ip4, sizeof(msg->local_ip4));
        break;
    case AF_INET6:
        return SK_PASS;
    }

    int verdict = bpf_msg_redirect_hash(msg, &sock_hash, &skk, BPF_F_INGRESS);
    int ret = find_update_flow(msg, verdict);
    if (ret != 0 && trace_messages) {
        bpf_printk("error updating flow %d\n", ret);
    }

    return SK_PASS;
}

#endif // __KTLS_TRACKER_H__
