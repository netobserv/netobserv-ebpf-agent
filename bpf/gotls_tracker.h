/*
 * GoTLS monitoring uprobe hooks (crypto/tls).
 * writeRecordLocked on entry; Read via entry uprobe + uretprobe (OpenSSL-style).
 */

#ifndef __GOTLS_TRACKER_H__
#define __GOTLS_TRACKER_H__

#include "go_argument.h"
#include "tls_plaintext.h"

// TLS application data record type (RFC 5246 §6.2.1; Go: recordTypeApplicationData in
// https://go.dev/src/crypto/tls/common.go). We hook writeRecordLocked and only emit when
// typ == application data (plaintext HTTP, etc.): https://go.dev/src/crypto/tls/conn.go
#define GOTLS_RECORD_TYPE_APPLICATION_DATA 23

// writeRecordLocked(typ recordType, data []byte) — register ABI (Go >= 1.17)
SEC("uprobe/gotls_write")
int probe_entry_gotls_write(struct pt_regs *ctx) {
    if (enable_gotls_tracking == 0) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 conn_user = (u64)go_get_argument(ctx, true, 1);
    s32 record_type = 0;
    s32 len = 0;
    void *record_type_reg = go_get_argument(ctx, true, 2);
    void *str_ptr = go_get_argument(ctx, true, 3);
    void *len_reg = go_get_argument(ctx, true, 4);

    bpf_probe_read_kernel(&record_type, sizeof(record_type), (void *)&record_type_reg);
    bpf_probe_read_kernel(&len, sizeof(len), (void *)&len_reg);
    if (len <= 0 || record_type != GOTLS_RECORD_TYPE_APPLICATION_DATA) {
        return 0;
    }

    generate_SSL_data_event(ctx, pid_tgid, 0, SSL_DIRECTION_WRITE, TLS_SOURCE_GOTLS,
                            (const char *)str_ptr, (uint32_t)len, conn_user);
    return 0;
}

// Read(b []byte) (int, error) — save b.data on entry (register ABI arg index 2).
SEC("uprobe/gotls_read")
int probe_entry_gotls_read(struct pt_regs *ctx) {
    if (enable_gotls_tracking == 0) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 conn_user = (u64)go_get_argument(ctx, true, 1);
    u64 buf_user = (u64)go_get_argument(ctx, true, 2);
    if (buf_user == 0) {
        return 0;
    }

    struct ssl_read_active_t active = {};
    active.buf_user = buf_user;
    active.conn_user_ptr = conn_user;
    if (bpf_map_update_elem(&ssl_read_active_map, &pid_tgid, &active, BPF_ANY) != 0) {
        return 0;
    }
    return 0;
}

// Read return — n in RC; plaintext already in user buffer saved on entry.
// Default read path (GOTLS_CAPTURE_READ): entry uprobe above + this uretprobe.
SEC("uretprobe/gotls_read")
int probe_ret_gotls_read(struct pt_regs *ctx) {
    if (enable_gotls_tracking == 0) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_read_active_t *active = bpf_map_lookup_elem(&ssl_read_active_map, &pid_tgid);
    if (!active) {
        return 0;
    }

    s64 ret = (s64)PT_REGS_RC(ctx);
    bpf_map_delete_elem(&ssl_read_active_map, &pid_tgid);
    if (ret <= 0 || active->buf_user == 0) {
        return 0;
    }

    generate_SSL_data_event(ctx, pid_tgid, 0, SSL_DIRECTION_READ, TLS_SOURCE_GOTLS,
                            (const char *)active->buf_user, (uint32_t)ret, active->conn_user_ptr);
    return 0;
}

#if 0
// Legacy alternate read path (mutually exclusive with uretprobe above): uprobes at every RET
// inside Read (eCapture-style). Enable when GOTLS_READ_RET_SITES attachment is wired in userspace.
SEC("uprobe/gotls_read_ret")
int probe_entry_gotls_read_ret(struct pt_regs *ctx) {
    if (enable_gotls_tracking == 0) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    s32 ret_len = 0;
    const char *str = (const char *)go_get_argument(ctx, false, 2);
    void *ret_len_reg = go_get_argument(ctx, true, 1);

    bpf_probe_read_kernel(&ret_len, sizeof(ret_len), (void *)&ret_len_reg);
    if (ret_len <= 0 || str == NULL) {
        return 0;
    }

    generate_SSL_data_event(ctx, pid_tgid, 0, SSL_DIRECTION_READ, TLS_SOURCE_GOTLS, str,
                            (uint32_t)ret_len, 0);
    return 0;
}
#endif

#endif /* __GOTLS_TRACKER_H__ */
