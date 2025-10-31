/*
    light weight TLS tracker.
*/

#ifndef __TLS_TRACKER_H__
#define __TLS_TRACKER_H__
#include "utils.h"

#define CONTENT_TYPE_CHANGE_CIPHER 0x14
#define CONTENT_TYPE_ALERT 0x15
#define CONTENT_TYPE_HANDSHAKE 0x16
#define CONTENT_TYPE_APP_DATA 0x17
#define HANDSHAKE_CLIENT_HELLO 0x01
#define HANDSHAKE_SERVER_HELLO 0x02

// https://www.rfc-editor.org/rfc/rfc5246
struct tls_record {
    u8 content_type; // handshake, alert, change cipher, app data
    u8 major;
    u8 minor;
    u16 length;
};

struct tls_handshake_header {
    u8 content_type; // client hello, server hello ...
    u8 len[3];
};

struct tls_handshake_version {
    u8 major;
    u8 minor;
};

// Extract TLS info
static inline void track_tls_version(struct __sk_buff *skb, pkt_info *pkt) {
    if (pkt->id->transport_protocol == IPPROTO_TCP) {
        void *data_end = (void *)(long)skb->data_end;
        struct tcphdr *tcp = (struct tcphdr *)pkt->l4_hdr;
        if (!tcp || ((void *)tcp + sizeof(*tcp) > data_end)) {
            return;
        }

        u8 len = tcp->doff * sizeof(u32);
        if (!len) {
            return;
        }

        struct tls_record rec;
        u32 offset = (long)pkt->l4_hdr - (long)skb->data + len;

        if ((bpf_skb_load_bytes(skb, offset, &rec, sizeof(rec))) < 0) {
            return;
        }

        switch (rec.content_type) {
        case CONTENT_TYPE_HANDSHAKE: {
            pkt->ssl_version = ((u16)rec.major) << 8 | rec.minor;
            struct tls_handshake_header handshake;
            if (bpf_skb_load_bytes(skb, offset + sizeof(rec), &handshake, sizeof(handshake)) < 0) {
                return;
            }
            if (handshake.content_type == HANDSHAKE_CLIENT_HELLO ||
                handshake.content_type == HANDSHAKE_SERVER_HELLO) {
                struct tls_handshake_version handshake_version;
                if (bpf_skb_load_bytes(skb, offset + sizeof(rec) + sizeof(handshake),
                                       &handshake_version, sizeof(handshake_version)) < 0) {
                    return;
                }
                pkt->ssl_version = ((u16)handshake_version.major) << 8 | handshake_version.minor;
            }
            break;
        }
        case CONTENT_TYPE_CHANGE_CIPHER:
        case CONTENT_TYPE_ALERT:
        case CONTENT_TYPE_APP_DATA:
            pkt->ssl_version = ((u16)rec.major) << 8 | rec.minor;
            break;
        }
    }
}

#endif // __TLS_TRACKER_H__
