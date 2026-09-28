/*
 * Shared TLS plaintext event helpers.
 */

#ifndef __TLS_PLAINTEXT_H__
#define __TLS_PLAINTEXT_H__

#include "types.h"
#include <bpf_core_read.h>

// Resolve the descriptor while the TLS call still owns it. Reading /proc after
// ring-buffer delivery can observe a different socket reusing the same fd.
static __always_inline void ssl_socket_tuple(struct ssl_data_event_t *event, s32 fd) {
    if (fd < 0) {
        return;
    }
    struct task_struct *task = (void *)bpf_get_current_task();
    struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
    if (!fdt || (u32)fd >= BPF_CORE_READ(fdt, max_fds)) {
        return;
    }
    struct file **fds = BPF_CORE_READ(fdt, fd);
    struct file *file = NULL;
    if (bpf_probe_read_kernel(&file, sizeof(file), fds + fd) || !file) {
        return;
    }
    // private_data is a socket only for S_IFSOCK files.
    if ((BPF_CORE_READ(file, f_inode, i_mode) & 0170000) != 0140000) {
        return;
    }
    struct socket *socket = BPF_CORE_READ(file, private_data);
    if (!socket || BPF_CORE_READ(socket, type) != 1) { // SOCK_STREAM
        return;
    }
    struct sock *sk = BPF_CORE_READ(socket, sk);
    if (!sk) {
        return;
    }
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    event->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (!event->src_port || !event->dst_port) {
        return;
    }
    if (family == AF_INET) { // AF_INET, stored as IPv4-mapped IPv6.
        __builtin_memset(event->src_addr, 0, sizeof(event->src_addr));
        __builtin_memset(event->dst_addr, 0, sizeof(event->dst_addr));
        event->src_addr[10] = event->dst_addr[10] = 0xff;
        event->src_addr[11] = event->dst_addr[11] = 0xff;
        BPF_CORE_READ_INTO((u32 *)&event->src_addr[12], sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO((u32 *)&event->dst_addr[12], sk, __sk_common.skc_daddr);
    } else if (family == AF_INET6) { // AF_INET6
        BPF_CORE_READ_INTO(&event->src_addr, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&event->dst_addr, sk, __sk_common.skc_v6_daddr);
    } else {
        return;
    }
    event->tuple_valid = 1;
}

#define SSL_DIRECTION_WRITE 0
#define SSL_DIRECTION_READ 1
#define TLS_SOURCE_OPENSSL 0
// Reserved for follow-ups: 1=gotls, 2=ktls

static __always_inline void generate_SSL_data_event(struct pt_regs *ctx, u64 pid_tgid, u8 ssl_type,
                                                    u8 direction, u8 tls_source, const char *buf,
                                                    uint32_t len, u64 conn_user_ptr) {
    if (len <= 0) {
        return;
    }

    struct ssl_data_event_t *event;
    event = bpf_ringbuf_reserve(&ssl_data_event_map, sizeof(*event), 0);
    if (!event) {
        return;
    }
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid_tgid = pid_tgid;
    event->ssl_type = ssl_type;
    event->direction = direction;
    event->tls_source = tls_source;
    event->tuple_valid = 0;
    event->conn_user_ptr = conn_user_ptr;
    event->socket_fd = -1;
    if (tls_source == TLS_SOURCE_OPENSSL && conn_user_ptr != 0) {
        struct ssl_fd_key_t key = {};
        key.ssl_ptr = conn_user_ptr;
        key.tgid = (u32)(pid_tgid >> 32);
        s32 *fd = bpf_map_lookup_elem(&ssl_fd_map, &key);
        if (fd != NULL && *fd >= 0) {
            event->socket_fd = *fd;
            ssl_socket_tuple(event, *fd);
        }
    }
    u32 capture_len = len < MAX_DATA_SIZE_OPENSSL ? len : MAX_DATA_SIZE_OPENSSL;
    event->data_len = (__s32)capture_len;
    bpf_probe_read_user(&event->data, capture_len, buf);
    bpf_ringbuf_submit(event, 0);
}

#endif /* __TLS_PLAINTEXT_H__ */
