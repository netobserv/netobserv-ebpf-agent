/*
  TLS tracker detects TLS packets and extracts information such as version or cipher suite.
*/
#ifndef __TLS_TRACKER_H__
#define __TLS_TRACKER_H__

#include "utils.h"

#define TLSTRACKER_UNKNOWN -1
#define TLSTRACKER_NOTLS -2
#define TLSTRACKER_MATCHED 0

#define CONTENT_TYPE_CHANGE_CIPHER 0x14
#define CONTENT_TYPE_ALERT 0x15
#define CONTENT_TYPE_HANDSHAKE 0x16
#define CONTENT_TYPE_APP_DATA 0x17

#define TLSTRACKER_BF_CLIENT_HELLO 0x01
#define TLSTRACKER_BF_SERVER_HELLO 0x02
#define TLSTRACKER_BF_OTHER_HANDSHAKE 0x04
#define TLSTRACKER_BF_CHANGE_CIPHER 0x08
#define TLSTRACKER_BF_ALERT 0x10
#define TLSTRACKER_BF_APP_DATA 0x20

// https://www.rfc-editor.org/rfc/rfc5246
struct tls_record {
    u8 content_type; // handshake, alert, change cipher, app data
    u16 version;
} __attribute__((packed));

struct tls_handshake_header {
    u8 type; // client hello, server hello ...
} __attribute__((packed));

struct tls_extension_header {
    u16 type;
    u16 len;
} __attribute__((packed));

static inline int tls_read_client_hello(struct __sk_buff *skb, u32 offset, tls_info *tls) {
    u16 handshake_version;
    if (bpf_skb_load_bytes(skb, offset, &handshake_version, sizeof(handshake_version)) < 0) {
        // Returning unknown because it could still be a FINISHED encrypted message
        return TLSTRACKER_UNKNOWN;
    }
    handshake_version = bpf_ntohs(handshake_version);
    offset += 2;
    // Accept only 0300 (ssl v3), 0301 (tls 1.0), 0302 (tls 1.1) or 0303 (tls 1.2 or 1.3)
    if (handshake_version < 0x0300 || handshake_version > 0x0303) {
        return TLSTRACKER_UNKNOWN;
    }
    tls->version = handshake_version;
    tls->type = TLSTRACKER_BF_CLIENT_HELLO;
    if (handshake_version == 0x0303) {
        // Check extensions to discriminate 1.2 and 1.3
        u8 session_len, compr_len;
        u16 cipher_len, exts_len;
        offset += 32; /*skip random*/
        // Read session
        if (bpf_skb_load_bytes(skb, offset, &session_len, sizeof(session_len)) < 0) {
            return TLSTRACKER_UNKNOWN;
        }
        offset += 1 + session_len;
        // Read cipher suites
        if (bpf_skb_load_bytes(skb, offset, &cipher_len, sizeof(cipher_len)) < 0) {
            return TLSTRACKER_UNKNOWN;
        }
        offset += 2 + bpf_ntohs(cipher_len);
        // Read compression
        if (bpf_skb_load_bytes(skb, offset, &compr_len, sizeof(compr_len)) < 0) {
            return TLSTRACKER_UNKNOWN;
        }
        offset += 1 + compr_len;
        // Read extensions
        if (bpf_skb_load_bytes(skb, offset, &exts_len, sizeof(exts_len)) < 0) {
            return TLSTRACKER_UNKNOWN;
        }
        exts_len = bpf_ntohs(exts_len);
        offset += 2;
        u16 ext_offset = 0;
        // Read up to 30 extensions
        for (int i = 0; i < 30; i++) {
            if (ext_offset >= exts_len) {
                break;
            }
            struct tls_extension_header ext_hdr;
            if (bpf_skb_load_bytes(skb, offset + ext_offset, &ext_hdr, sizeof(ext_hdr)) < 0) {
                return TLSTRACKER_UNKNOWN;
            }
            ext_hdr.type = bpf_ntohs(ext_hdr.type);
            ext_hdr.len = bpf_ntohs(ext_hdr.len);
            ext_offset += 4;
            if (ext_hdr.type == 0x002b) {
                // Supported Versions
                u16 supportedversions_offset = 1;   // skip supported versions length (u8), it's always ext_hdr.len-1
                // Read up to 5 versions
                for (int j = 0; j < 5; j++) {
                    if (supportedversions_offset >= ext_hdr.len) {
                        break;
                    }
                    u16 version;
                    if (bpf_skb_load_bytes(skb, offset + ext_offset + supportedversions_offset, &version, sizeof(version)) < 0) {
                        return TLSTRACKER_UNKNOWN;
                    }
                    version = bpf_ntohs(version);
                    if (version > tls->version) {
                        tls->version = version;
                    }
                    supportedversions_offset += 2;
                }
                // Stop reading here
                return TLSTRACKER_MATCHED;
            }
            ext_offset += ext_hdr.len;
        }
    }
    return TLSTRACKER_MATCHED;
}

static inline int tls_read_server_hello(struct __sk_buff *skb, u32 offset, tls_info *tls) {
    u16 handshake_version;
    if (bpf_skb_load_bytes(skb, offset, &handshake_version, sizeof(handshake_version)) < 0) {
        // Returning unknown because it could still be a FINISHED encrypted message
        return TLSTRACKER_UNKNOWN;
    }
    handshake_version = bpf_ntohs(handshake_version);
    offset += 2;
    // Accept only 0300 (ssl v3), 0301 (tls 1.0), 0302 (tls 1.1) or 0303 (tls 1.2 or 1.3)
    if (handshake_version < 0x0300 || handshake_version > 0x0303) {
        return TLSTRACKER_UNKNOWN;
    }
    tls->version = handshake_version;
    tls->type = TLSTRACKER_BF_SERVER_HELLO;
    if (handshake_version == 0x0303) {
        // Check extensions to discriminate 1.2 and 1.3
        u8 session_len;
        u16 exts_len;
        offset += 32; /*skip random*/
        // Read session
        if (bpf_skb_load_bytes(skb, offset, &session_len, sizeof(session_len)) < 0) {
            return TLSTRACKER_UNKNOWN;
        }
        offset += 1 + session_len;
        // Read cipher suites
        if (bpf_skb_load_bytes(skb, offset, &tls->cipher_suite, sizeof(tls->cipher_suite)) < 0) {
            return TLSTRACKER_UNKNOWN;
        }
        tls->cipher_suite = bpf_ntohs(tls->cipher_suite);
        offset += 3;        // Skip also compression (1B)
        // Read extensions
        if (bpf_skb_load_bytes(skb, offset, &exts_len, sizeof(exts_len)) < 0) {
            return TLSTRACKER_UNKNOWN;
        }
        exts_len = bpf_ntohs(exts_len);
        offset += 2;
        u16 ext_offset = 0;
        // Read up to 30 extensions
        for (int i = 0; i < 30; i++) {
            if (ext_offset >= exts_len) {
                break;
            }
            struct tls_extension_header ext_hdr;
            if (bpf_skb_load_bytes(skb, offset + ext_offset, &ext_hdr, sizeof(ext_hdr)) < 0) {
                return TLSTRACKER_UNKNOWN;
            }
            ext_hdr.type = bpf_ntohs(ext_hdr.type);
            ext_hdr.len = bpf_ntohs(ext_hdr.len);
            ext_offset += 4;
            if (ext_hdr.type == 0x002b) {
                // Supported Versions: single version expected
                u16 version;
                if (bpf_skb_load_bytes(skb, offset + ext_offset, &version, sizeof(version)) < 0) {
                    return TLSTRACKER_UNKNOWN;
                }
                tls->version = bpf_ntohs(version);
                // Stop reading here
                return TLSTRACKER_MATCHED;
            }
            ext_offset += ext_hdr.len;
        }
    }
    return TLSTRACKER_MATCHED;
}

static inline int track_tls_tcp(struct __sk_buff *skb, void *l4_hdr, tls_info *tls) {
    void *data_end = (void *)(long)skb->data_end;

    struct tcphdr *tcp = (struct tcphdr *)l4_hdr;
    if (!tcp || ((void *)tcp + sizeof(*tcp) > data_end)) {
        return TLSTRACKER_NOTLS;
    }

    u8 len = tcp->doff * sizeof(u32);
    if (!len) {
        return TLSTRACKER_NOTLS;
    }

    struct tls_record rec;
    u32 offset = (long)l4_hdr - (long)skb->data + len;

    if ((bpf_skb_load_bytes(skb, offset, &rec, sizeof(rec))) < 0) {
        return TLSTRACKER_NOTLS;
    }
    offset += 5;
    rec.version = bpf_ntohs(rec.version);

    // Accept only 0300, 0301, 0302 or 0303
    // Note that for compatibility reasons, versions cannot be trusted here:
    // TLS 1.2 or 1.3 packets can be disguised as 1.0, hence further analysis is required
    if (rec.version < 0x0300 || rec.version > 0x0303) {
        return TLSTRACKER_NOTLS;
    }

    switch (rec.content_type) {
    case CONTENT_TYPE_HANDSHAKE: {
        // Handshakes should have the handshake header, except if it's a FINISHED msg, which is encrypted.
        // In both cases, there should be sufficient data to fill tls_handshake_header; but we can't assume it's valid
        struct tls_handshake_header handshake;
        if (bpf_skb_load_bytes(skb, offset, &handshake, sizeof(handshake)) < 0) {
            return TLSTRACKER_NOTLS;
        }
        offset += 4;

        // From now on, if we fail to read what we expect, this was either not a TLS packet, or a FINISHED message.
        switch (handshake.type) {
        case 0x01:
            return tls_read_client_hello(skb, offset, tls);
        case 0x02:
            return tls_read_server_hello(skb, offset, tls);
        case 0x10:
        case 0x0b:
        case 0x0c:
        case 0x0e:
            // Still sounds like a valid handshake, assume it is
            tls->version = rec.version;
            tls->type = TLSTRACKER_BF_OTHER_HANDSHAKE;
            return TLSTRACKER_MATCHED;
        }
        // Either not TLS, or FINISHED
        return TLSTRACKER_UNKNOWN;
    }
    case CONTENT_TYPE_CHANGE_CIPHER:
        tls->version = rec.version;
        tls->type = TLSTRACKER_BF_CHANGE_CIPHER;
        return TLSTRACKER_MATCHED;
    case CONTENT_TYPE_ALERT:
        tls->version = rec.version;
        tls->type = TLSTRACKER_BF_ALERT;
        return TLSTRACKER_MATCHED;
    case CONTENT_TYPE_APP_DATA:
        tls->version = rec.version;
        tls->type = TLSTRACKER_BF_APP_DATA;
        return TLSTRACKER_MATCHED;
    }
    return TLSTRACKER_NOTLS;
}

// Extract TLS info
static inline int track_tls(struct __sk_buff *skb, u8 proto, void *l4_hdr, u8 flags, tls_info *tls) {
    if (proto == IPPROTO_TCP && flags & 0x10) {
        // TCP ACK
        return track_tls_tcp(skb, l4_hdr, tls);
    }
    // TODO: UDP/QUIC
    return TLSTRACKER_UNKNOWN;
}

#endif // __TLS_TRACKER_H__
