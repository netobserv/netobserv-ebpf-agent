/*
 * OpenSSL monitoring uprobe eBPF hooks.
 */

#ifndef __OPENSSL_TRACKER_H__
#define __OPENSSL_TRACKER_H__

#include "tls_plaintext.h"

static __always_inline u8 openssl_ssl_type(void *ssl) {
    u32 ssl_type_raw = 0;
    if (bpf_probe_read_user(&ssl_type_raw, sizeof(ssl_type_raw), ssl) != 0) {
        return 0;
    }
    return (u8)ssl_type_raw;
}

// int SSL_set_fd(SSL *ssl, int fd);
SEC("uprobe/SSL_set_fd")
int probe_entry_SSL_set_fd(struct pt_regs *ctx) {
    if (enable_openssl_tracking == 0) {
        return 0;
    }

    void *ssl = (void *)PT_REGS_PARM1(ctx);
    s32 fd = (s32)PT_REGS_PARM2(ctx);
    if (ssl == NULL || fd < 0) {
        return 0;
    }

    u64 key = (u64)ssl;
    bpf_map_update_elem(&ssl_fd_map, &key, &fd, BPF_ANY);
    return 0;
}

// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uprobe/SSL_write")
int probe_entry_SSL_write(struct pt_regs *ctx) {
    if (enable_openssl_tracking == 0) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    uint32_t num = (uint32_t)PT_REGS_PARM3(ctx);

    if (num > 0 && buf != NULL) {
        generate_SSL_data_event(ctx, pid_tgid, openssl_ssl_type(ssl), SSL_DIRECTION_WRITE,
                                TLS_SOURCE_OPENSSL, buf, num, (u64)ssl);
    }

    return 0;
}

// int SSL_read(SSL *ssl, void *buf, int num);
SEC("uprobe/SSL_read")
int probe_entry_SSL_read(struct pt_regs *ctx) {
    if (enable_openssl_tracking == 0) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    void *ssl = (void *)PT_REGS_PARM1(ctx);

    struct ssl_read_active_t active = {};
    active.ssl_type = openssl_ssl_type(ssl);
    active.buf_user = (u64)PT_REGS_PARM2(ctx);
    active.conn_user_ptr = (u64)ssl;
    bpf_map_update_elem(&ssl_read_active_map, &pid_tgid, &active, BPF_ANY);

    return 0;
}

SEC("uretprobe/SSL_read")
int probe_ret_SSL_read(struct pt_regs *ctx) {
    if (enable_openssl_tracking == 0) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_read_active_t *active = bpf_map_lookup_elem(&ssl_read_active_map, &pid_tgid);
    if (!active) {
        return 0;
    }

    int ret = PT_REGS_RC(ctx);
    bpf_map_delete_elem(&ssl_read_active_map, &pid_tgid);
    if (ret <= 0 || active->buf_user == 0) {
        return 0;
    }

    generate_SSL_data_event(ctx, pid_tgid, active->ssl_type, SSL_DIRECTION_READ, TLS_SOURCE_OPENSSL,
                            (const char *)active->buf_user, (uint32_t)ret, active->conn_user_ptr);
    return 0;
}

#endif /* __OPENSSL_TRACKER_H__  */
