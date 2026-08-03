/*
    kTLS tracker: capture kernel TLS plaintext via sk_msg hook.
*/
#include "utils.h"

#ifndef __KTLS_TRACKER_H__
#define __KTLS_TRACKER_H__

#include "tls_plaintext.h"

#define MAX_SOCK_OPS_MAP_ENTRIES 65535

#define KTLS_STAT_SOCKOPS_ESTABLISHED 0
#define KTLS_STAT_SOCKHASH_UPDATED 1
#define KTLS_STAT_SK_MSG_ENTER 2
#define KTLS_STAT_SK_MSG_CAPTURED 3
#define KTLS_STAT_SOCKOPS_ENTER 4
#define KTLS_STAT_SOCKOPS_OP_CONNECT 5
#define KTLS_STAT_SOCKOPS_OP_ACTIVE 6
#define KTLS_STAT_SOCKOPS_OP_PASSIVE 7
#define KTLS_STAT_SOCKOPS_OP_LISTEN 8
#define KTLS_STAT_SOCKOPS_OP_OTHER 9
#define KTLS_STAT_SOCKOPS_OP_RTT 10
#define KTLS_STAT_SOCKOPS_OP_STATE 11
#define KTLS_STAT_SOCKHASH_FROM_RTT 12
#define KTLS_STAT_SOCKHASH_UPDATE_ERR 13
#define KTLS_STAT_SOCKHASH_TRY 14
#define KTLS_STAT_SOCKHASH_NOT_FULLSOCK 15

#define TCP_ESTABLISHED 1

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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, u32);
    __type(value, u64);
} ktls_stats SEC(".maps");

static __always_inline void ktls_stat_inc(u32 idx) {
    u64 *v = bpf_map_lookup_elem(&ktls_stats, &idx);
    if (v) {
        *v += 1;
    }
}

static __always_inline void sock_key_from_ipv4(struct sock_key *skk, __u32 remote_ip4,
                                               __u32 local_ip4) {
    __builtin_memcpy(skk->remote_ip, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(skk->local_ip, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(skk->remote_ip + sizeof(ip4in6), &remote_ip4, sizeof(remote_ip4));
    __builtin_memcpy(skk->local_ip + sizeof(ip4in6), &local_ip4, sizeof(local_ip4));
}

static __always_inline void sock_key_from_ipv6(struct sock_key *skk, struct bpf_sock_ops *skops) {
    __u32 *dst_remote = (__u32 *)skk->remote_ip;
    __u32 *dst_local = (__u32 *)skk->local_ip;
    // Verifier allows only fixed ctx offsets; no loops or pointer arithmetic on skops.
    __u32 rip0 = skops->remote_ip6[0];
    __u32 rip1 = skops->remote_ip6[1];
    __u32 rip2 = skops->remote_ip6[2];
    __u32 rip3 = skops->remote_ip6[3];
    __u32 lip0 = skops->local_ip6[0];
    __u32 lip1 = skops->local_ip6[1];
    __u32 lip2 = skops->local_ip6[2];
    __u32 lip3 = skops->local_ip6[3];

    dst_remote[0] = rip0;
    dst_remote[1] = rip1;
    dst_remote[2] = rip2;
    dst_remote[3] = rip3;
    dst_local[0] = lip0;
    dst_local[1] = lip1;
    dst_local[2] = lip2;
    dst_local[3] = lip3;
}

static __always_inline void bpf_sock_ops_ip(struct bpf_sock_ops *skops) {
    struct sock_key skk = {};
    __u32 family = skops->family;

    ktls_stat_inc(KTLS_STAT_SOCKHASH_TRY);

    if (skops->is_fullsock == 0) {
        ktls_stat_inc(KTLS_STAT_SOCKHASH_NOT_FULLSOCK);
        return;
    }

    skk.local_port = bpf_htonl(skops->local_port);
    skk.remote_port = skops->remote_port;
    skk.family = family;

    switch (family) {
    case AF_INET:
        sock_key_from_ipv4(&skk, skops->remote_ip4, skops->local_ip4);
        break;
    case AF_INET6:
        sock_key_from_ipv6(&skk, skops);
        break;
    default:
        return;
    }

    long ret = bpf_sock_hash_update(skops, &sock_hash, &skk, BPF_ANY);
    if (ret == 0) {
        ktls_stat_inc(KTLS_STAT_SOCKHASH_UPDATED);
    } else {
        ktls_stat_inc(KTLS_STAT_SOCKHASH_UPDATE_ERR);
    }
}

static __always_inline void bpf_sock_ops_register_established(struct bpf_sock_ops *skops) {
    bpf_sock_ops_ip(skops);
}

SEC("sockops")
int bpf_sockops(struct bpf_sock_ops *skops) {
    u32 op = skops->op;

    ktls_stat_inc(KTLS_STAT_SOCKOPS_ENTER);
    bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG | BPF_SOCK_OPS_RTT_CB_FLAG);

    switch (op) {
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
        ktls_stat_inc(KTLS_STAT_SOCKOPS_OP_CONNECT);
        break;
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        ktls_stat_inc(KTLS_STAT_SOCKOPS_OP_ACTIVE);
        ktls_stat_inc(KTLS_STAT_SOCKOPS_ESTABLISHED);
        bpf_sock_ops_register_established(skops);
        break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        ktls_stat_inc(KTLS_STAT_SOCKOPS_OP_PASSIVE);
        ktls_stat_inc(KTLS_STAT_SOCKOPS_ESTABLISHED);
        bpf_sock_ops_register_established(skops);
        break;
    case BPF_SOCK_OPS_TCP_LISTEN_CB:
        ktls_stat_inc(KTLS_STAT_SOCKOPS_OP_LISTEN);
        break;
    case BPF_SOCK_OPS_STATE_CB: {
        ktls_stat_inc(KTLS_STAT_SOCKOPS_OP_STATE);
        if (skops->args[1] == TCP_ESTABLISHED) {
            ktls_stat_inc(KTLS_STAT_SOCKOPS_ESTABLISHED);
            bpf_sock_ops_register_established(skops);
        }
        break;
    }
    case BPF_SOCK_OPS_RTT_CB:
        ktls_stat_inc(KTLS_STAT_SOCKOPS_OP_RTT);
        if (skops->state == TCP_ESTABLISHED) {
            ktls_stat_inc(KTLS_STAT_SOCKHASH_FROM_RTT);
            bpf_sock_ops_ip(skops);
        }
        break;
    default:
        ktls_stat_inc(KTLS_STAT_SOCKOPS_OP_OTHER);
        if (skops->state == TCP_ESTABLISHED) {
            ktls_stat_inc(KTLS_STAT_SOCKHASH_FROM_RTT);
            bpf_sock_ops_ip(skops);
        }
        break;
    }

    return 0;
}

static __always_inline void ktls_event_tuple_from_sk_msg(struct ssl_data_event_t *event,
                                                         struct sk_msg_md *msg) {
    event->tuple_valid = 1;
    event->conn_user_ptr = 0;
    event->socket_fd = -1;
    event->src_port = (__u16)msg->local_port;
    event->dst_port = (__u16)(bpf_ntohl(msg->remote_port) & 0xffff);

    switch (msg->family) {
    case AF_INET:
        __builtin_memcpy(event->src_addr, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(event->dst_addr, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(event->src_addr + sizeof(ip4in6), &msg->local_ip4, sizeof(msg->local_ip4));
        __builtin_memcpy(event->dst_addr + sizeof(ip4in6), &msg->remote_ip4,
                         sizeof(msg->remote_ip4));
        break;
    case AF_INET6: {
        __u32 *src = (__u32 *)event->src_addr;
        __u32 *dst = (__u32 *)event->dst_addr;
        src[0] = msg->local_ip6[0];
        src[1] = msg->local_ip6[1];
        src[2] = msg->local_ip6[2];
        src[3] = msg->local_ip6[3];
        dst[0] = msg->remote_ip6[0];
        dst[1] = msg->remote_ip6[1];
        dst[2] = msg->remote_ip6[2];
        dst[3] = msg->remote_ip6[3];
        break;
    }
    default:
        event->tuple_valid = 0;
        break;
    }
}

static __always_inline void capture_ktls_msg(struct sk_msg_md *msg) {
    unsigned char *p = (unsigned char *)(long)msg->data;
    unsigned char *end = (unsigned char *)(long)msg->data_end;
    if (p >= end) {
        return;
    }

    u32 avail = (u32)(end - p);
    if (avail == 0) {
        return;
    }

    // Best-effort linearize; kTLS sk_msg may already expose a contiguous slice.
    bpf_msg_pull_data(msg, 0, avail, 0);
    p = (unsigned char *)(long)msg->data;
    end = (unsigned char *)(long)msg->data_end;
    if (p >= end) {
        return;
    }
    avail = (u32)(end - p);
    if (avail == 0) {
        return;
    }

    u32 capture_len = avail;
    if (capture_len > MAX_DATA_SIZE_OPENSSL) {
        capture_len = MAX_DATA_SIZE_OPENSSL;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_data_event_t *event;
    event = bpf_ringbuf_reserve(&ssl_data_event_map, sizeof(*event), 0);
    if (!event) {
        return;
    }
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid_tgid = pid_tgid;
    event->ssl_type = 0;
    event->direction = SSL_DIRECTION_WRITE;
    event->tls_source = TLS_SOURCE_KTLS;
    event->data_len = (__s32)capture_len;
    bpf_probe_read_kernel(&event->data, capture_len, (const char *)p);
    ktls_event_tuple_from_sk_msg(event, msg);
    bpf_ringbuf_submit(event, 0);
    ktls_stat_inc(KTLS_STAT_SK_MSG_CAPTURED);
}

SEC("sk_msg")
int bpf_ktls_redir(struct sk_msg_md *msg) {
    if (enable_ktls_tracking == 0) {
        return SK_PASS;
    }

    ktls_stat_inc(KTLS_STAT_SK_MSG_ENTER);
    capture_ktls_msg(msg);
    return SK_PASS;
}

#endif // __KTLS_TRACKER_H__
