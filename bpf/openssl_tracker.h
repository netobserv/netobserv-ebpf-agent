/*
 * OpenSSL monitoring uprobe/uretprobe eBPF hook.
 */

#ifndef __OPENSSL_TRACKER_H__
#define __OPENSSL_TRACKER_H__

#include "utils.h"

static inline void generate_SSL_data_event(struct pt_regs *ctx, u64 pid_tgid, u8 ssl_type,
                                           const char *buf) {
    int len = (int)PT_REGS_RC(ctx);
    if (len < 0) {
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
    if (do_sampling == 0 || enable_ssl == 0) {
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

    BPF_PRINTK("openssl uprobe/SSL_write type: %d, buf: %p\n", ssl_type, buf);

    struct active_ssl_buf_t active_ssl_buf_t;
    __builtin_memset(&active_ssl_buf_t, 0, sizeof(active_ssl_buf_t));
    active_ssl_buf_t.ssl_type = ssl_type;
    bpf_probe_read_user(&active_ssl_buf_t.buf, sizeof(active_ssl_buf_t.buf), buf);

    ret = bpf_map_update_elem(&active_ssl_write_map, &pid_tgid, &active_ssl_buf_t, BPF_NOEXIST);
    if (ret != 0) {
        if (trace_messages) {
            BPF_PRINTK("error creating new active_ssl_write_map dir: %d err: %d\n", pid_tgid, ret);
        }
    }
    return 0;
}

SEC("uretprobe/SSL_write")
int probe_exit_SSL_write(struct pt_regs *ctx) {
    if (do_sampling == 0 || enable_ssl == 0) {
        return 0;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct active_ssl_buf_t *active_ssl_buf = bpf_map_lookup_elem(&active_ssl_write_map, &pid_tgid);
    if (active_ssl_buf != NULL) {
        const char *buf;
        u8 ssl_type = active_ssl_buf->ssl_type;
        bpf_probe_read(&buf, sizeof(buf), &active_ssl_buf->buf);
        generate_SSL_data_event(ctx, pid_tgid, ssl_type, buf);
        bpf_map_delete_elem(&active_ssl_write_map, &pid_tgid);
    }
    return 0;
}

#endif /* __OPENSSL_TRACKER_H__  */