/*
 * OpenSSL monitoring uprobe/uretprobe eBPF hook.
 */

#ifndef __OPENSSL_TRACKER_H__
#define __OPENSSL_TRACKER_H__

#include "utils.h"

static inline void generate_SSL_data_event(struct pt_regs *ctx, u64 pid_tgid, u8 ssl_type,
                                           const char *buf, uint32_t len) {
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
    event->data_len = len < MAX_DATA_SIZE_OPENSSL ? len : MAX_DATA_SIZE_OPENSSL;
    bpf_probe_read_user(&event->data, event->data_len, buf);
    bpf_ringbuf_submit(event, 0);
}

// int SSL_write(SSL *ssl, const void *buf, int num);
// https://github.com/openssl/openssl/blob/master/ssl/ssl_lib.c#L2666
SEC("uprobe/SSL_write")
int probe_entry_SSL_write(struct pt_regs *ctx) {
    if (enable_openssl_tracking == 0) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();

    BPF_PRINTK("openssl uprobe/SSL_write pid: %d\n", pid_tgid);
    // https://github.com/openssl/openssl/blob/master/ssl/ssl_local.h#L1233
    void *ssl = (void *)PT_REGS_PARM1(ctx);

    u32 ssl_type;
    int ret;

    ret = bpf_probe_read_user(&ssl_type, sizeof(ssl_type), (u32 *)ssl);
    if (ret) {
        BPF_PRINTK("(OPENSSL) bpf_probe_read ssl_type_ptr failed, ret: %d\n", ret);
        return 0;
    }
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    uint32_t num = (uint32_t)PT_REGS_PARM3(ctx); // Third parameter: number of bytes to write

    BPF_PRINTK("openssl uprobe/SSL_write type: %d, buf: %p, num: %d\n", ssl_type, buf, num);

    // Read the data immediately in the uprobe (before SSL_write processes it)
    // This captures the plaintext before encryption
    if (num > 0) {
        generate_SSL_data_event(ctx, pid_tgid, ssl_type, buf, num);
    }

    return 0;
}

#endif /* __OPENSSL_TRACKER_H__  */