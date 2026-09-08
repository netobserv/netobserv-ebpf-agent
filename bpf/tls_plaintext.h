/*
 * Shared TLS plaintext event helpers.
 */

#ifndef __TLS_PLAINTEXT_H__
#define __TLS_PLAINTEXT_H__

#include "types.h"

#define SSL_DIRECTION_WRITE 0
#define SSL_DIRECTION_READ 1
#define TLS_SOURCE_OPENSSL 0
// Reserved for follow-ups: 1=gotls, 2=ktls

static inline void generate_SSL_data_event(struct pt_regs *ctx, u64 pid_tgid, u8 ssl_type,
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
        }
    }
    u32 capture_len = len < MAX_DATA_SIZE_OPENSSL ? len : MAX_DATA_SIZE_OPENSSL;
    event->data_len = (__s32)capture_len;
    bpf_probe_read_user(&event->data, capture_len, buf);
    bpf_ringbuf_submit(event, 0);
}

#endif /* __TLS_PLAINTEXT_H__ */
