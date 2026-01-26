/*
 * QUIC Flow Tracker - Kernel-observed metrics using QUIC Invariants (RFC 8999)
 * Works with unmodified QUIC implementations (quiche, etc.)
 *
 * UDP Packet with QUIC:
 * +------------------+------------------+------------------+------------------+
 * |     Ethernet     |    IP Header     |   UDP Header     |   QUIC Payload   |
 * |     14 bytes     |   20/40 bytes    |     8 bytes      |                  |
 * +------------------+------------------+------------------+------------------+
 *
 * UDP Header (8 bytes):
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |       Destination Port        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            Length             |           Checksum            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * QUIC Long Header (handshake):
 * +-+-+-+-+-+-+-+-+
 * |1|1| Type |Res|  First byte: Form=1 (long), Fixed=1, Type (2 bits)
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Version (32)                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | DCID Len (8)  |          Destination Connection ID           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | SCID Len (8)  |            Source Connection ID              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    [Type-Specific Fields...]                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * QUIC Short Header (post-handshake):
 * +-+-+-+-+-+-+-+-+
 * |0|1|S|R|R|K|P P|  First byte: Form=0 (short), Fixed=1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Destination Connection ID                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    [Encrypted Payload...]                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#ifndef __QUIC_TRACKER_H__
#define __QUIC_TRACKER_H__

#include "utils.h"
#include "maps_definition.h"

#define QUIC_PORT 443         // 443 is the default port for QUIC (RFC 9312)
#define QUIC_LONG_HEADER 0x80 // 0x80 is the fixed bit for long header (RFC 9000)
#define QUIC_FIXED_BIT 0x40   // 0x40 is the fixed bit for short header (RFC 9000)
#define QUIC_MIN_PACKET_SIZE                                                                       \
    21 //21 bytes ==> first byte (1) + version (4) + DCID Len (1) + 15 bytes of DCID room
#define QUIC_MAX_CID_LEN 20 // 20 bytes is the maximum length of a QUIC connection ID (RFC 9000)

/*
 * QUIC long-header (RFC 8999 invariants) byte offsets, relative to the start of
 * the QUIC header (i.e. the first QUIC byte at `offset` in the UDP payload).
 *
 * Long Header format begins with:
 *   [0]  First byte
 *   [1..4] Version (32-bit)
 *   [5]  DCID Len
 *   [6..] DCID bytes...
 *   [6+dcid_len] SCID Len
 *   [... ] SCID bytes...
 */
#define QUIC_LH_VERSION_OFFSET 1
#define QUIC_LH_DCID_LEN_OFFSET (QUIC_LH_VERSION_OFFSET + 4)
#define QUIC_LH_DCID_OFFSET (QUIC_LH_DCID_LEN_OFFSET + 1)
#define QUIC_LH_SCID_LEN_OFFSET(dcid_len) (QUIC_LH_DCID_OFFSET + (dcid_len))
#define QUIC_LH_MIN_LEN (1 + 4 + 1 + 1) /* first byte + version + DCID len + SCID len */

typedef enum quic_header_type_t {
    QUIC_HEADER_TYPE_NOT_QUIC = 0,
    QUIC_HEADER_TYPE_SHORT = 1,
    QUIC_HEADER_TYPE_LONG = 2,
} quic_header_type;

// Parse QUIC header using QUIC invariants.
// Returns: QUIC_HEADER_TYPE_NOT_QUIC, QUIC_HEADER_TYPE_SHORT, QUIC_HEADER_TYPE_LONG.
// If long header, version is set and CID length fields are sanity-checked.
// payload_len is the UDP payload length (bytes) starting at offset.
static __always_inline quic_header_type parse_quic_header(struct __sk_buff *skb, u32 offset,
                                                          u32 payload_len, u32 *version) {
    u8 first_byte;
    if (bpf_skb_load_bytes(skb, offset, &first_byte, 1) < 0) {
        if (trace_messages) {
            bpf_printk("error loading first byte at offset %d\n", offset);
        }
        return QUIC_HEADER_TYPE_NOT_QUIC;
    }

    // QUIC packets must have fixed bit set
    if (!(first_byte & QUIC_FIXED_BIT)) {
        if (trace_messages) {
            bpf_printk("QUIC packet does not have fixed bit set at offset %d\n", offset);
        }
        return QUIC_HEADER_TYPE_NOT_QUIC;
    }

    if (first_byte & QUIC_LONG_HEADER) {
        if (trace_messages) {
            bpf_printk("QUIC packet is a long header at offset %d\n", offset);
        }
        // Need at least: first byte (1) + version (4) + DCID Len (1) + SCID Len (1)
        // (CID contents lengths are checked below)
        if (payload_len < QUIC_LH_MIN_LEN) {
            if (trace_messages) {
                bpf_printk("QUIC packet payload length %d is less than minimum length %d\n",
                           payload_len, QUIC_LH_MIN_LEN);
            }
            return QUIC_HEADER_TYPE_NOT_QUIC;
        }

        // Long header: read version (bytes 1-4)
        u32 ver;
        if (bpf_skb_load_bytes(skb, offset + QUIC_LH_VERSION_OFFSET, &ver, 4) < 0) {
            if (trace_messages) {
                bpf_printk("error loading version at offset %d\n", offset + QUIC_LH_VERSION_OFFSET);
            }
            return QUIC_HEADER_TYPE_NOT_QUIC;
        }
        *version = bpf_ntohl(ver);

        // Sanity-check DCID/SCID length fields (QUIC invariants / RFC 8999)
        u8 dcid_len = 0;
        if (bpf_skb_load_bytes(skb, offset + QUIC_LH_DCID_LEN_OFFSET, &dcid_len, 1) < 0) {
            if (trace_messages) {
                bpf_printk("error loading DCID length at offset %d\n",
                           offset + QUIC_LH_DCID_LEN_OFFSET);
            }
            return QUIC_HEADER_TYPE_NOT_QUIC;
        }
        if (dcid_len > QUIC_MAX_CID_LEN) {
            if (trace_messages) {
                bpf_printk("DCID length %d is greater than maximum length %d\n", dcid_len,
                           QUIC_MAX_CID_LEN);
            }
            return QUIC_HEADER_TYPE_NOT_QUIC;
        }
        if (payload_len < (u32)(QUIC_LH_SCID_LEN_OFFSET(dcid_len) + 1)) {
            if (trace_messages) {
                bpf_printk("QUIC packet payload length %d is less than minimum length %d\n",
                           payload_len, QUIC_LH_SCID_LEN_OFFSET(dcid_len) + 1);
            }
            return QUIC_HEADER_TYPE_NOT_QUIC;
        }

        u8 scid_len = 0;
        if (bpf_skb_load_bytes(skb, offset + QUIC_LH_SCID_LEN_OFFSET(dcid_len), &scid_len, 1) < 0) {
            if (trace_messages) {
                bpf_printk("error loading SCID length at offset %d\n",
                           offset + QUIC_LH_SCID_LEN_OFFSET(dcid_len));
            }
            return QUIC_HEADER_TYPE_NOT_QUIC;
        }
        if (scid_len > QUIC_MAX_CID_LEN) {
            if (trace_messages) {
                bpf_printk("SCID length %d is greater than maximum length %d\n", scid_len,
                           QUIC_MAX_CID_LEN);
            }
            return QUIC_HEADER_TYPE_NOT_QUIC;
        }
        if (payload_len < (u32)(QUIC_LH_MIN_LEN + dcid_len + scid_len)) {
            if (trace_messages) {
                bpf_printk("QUIC packet payload length %d is less than minimum length %d\n",
                           payload_len, QUIC_LH_MIN_LEN + dcid_len + scid_len);
            }
            return QUIC_HEADER_TYPE_NOT_QUIC;
        }

        return QUIC_HEADER_TYPE_LONG;
    }

    if (trace_messages) {
        bpf_printk("QUIC packet is a short header at offset %d\n", offset);
    }
    return QUIC_HEADER_TYPE_SHORT;
}

static __always_inline int track_quic_packet(struct __sk_buff *skb, pkt_info *pkt, u16 eth_protocol,
                                             u8 direction, u32 len) {
    if (pkt->id->transport_protocol != IPPROTO_UDP) {
        if (trace_messages) {
            bpf_printk("QUIC packet is not UDP\n");
        }
        return 0;
    }

    // Mode selection via enable_quic_tracking:
    // QUIC_CONFIG_DISABLED = 0, QUIC_CONFIG_ENABLED = 1, QUIC_CONFIG_ANY_UDP_PORT = 2.
    if (enable_quic_tracking == (u8)QUIC_CONFIG_ENABLED) {
        if (pkt->id->dst_port != QUIC_PORT && pkt->id->src_port != QUIC_PORT) {
            if (trace_messages) {
                bpf_printk("QUIC packet is not on port %d\n", QUIC_PORT);
            }
            return 0;
        }
    }

    struct udphdr *udp = (struct udphdr *)pkt->l4_hdr;
    if (!udp) {
        if (trace_messages) {
            bpf_printk("UDP header not found\n");
        }
        return 0;
    }
    u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len < sizeof(struct udphdr) + QUIC_MIN_PACKET_SIZE) {
        if (trace_messages) {
            bpf_printk("UDP packet length %d is less than minimum length %d\n", udp_len,
                       sizeof(struct udphdr) + QUIC_MIN_PACKET_SIZE);
        }
        return 0;
    }
    u32 quic_offset = (u32)((long)udp - (long)skb->data) + sizeof(struct udphdr);
    u32 quic_payload_len = (u32)udp_len - sizeof(struct udphdr);

    // Parse QUIC header
    u32 version = 0;
    quic_header_type hdr_type = parse_quic_header(skb, quic_offset, quic_payload_len, &version);
    if (hdr_type == QUIC_HEADER_TYPE_NOT_QUIC) {
        if (trace_messages) {
            bpf_printk("QUIC packet is not QUIC at offset %d\n", quic_offset);
        }
        return 0;
    }

    u64 now = pkt->current_ts;
    flow_id *id = pkt->id;

    // Lookup or create QUIC metrics
    quic_metrics *flow = bpf_map_lookup_elem(&quic_flows, id);
    if (flow) {
        flow->end_mono_time_ts = now;
        flow->packets++;
        flow->bytes += len;
        if (hdr_type == QUIC_HEADER_TYPE_LONG) {
            flow->seen_long_hdr = 1;
            if (version != 0)
                flow->version = version;
        } else {
            flow->seen_short_hdr = 1;
        }
    } else {
        quic_metrics new_flow = {
            .start_mono_time_ts = now,
            .end_mono_time_ts = now,
            .bytes = len,
            .packets = 1,
            .version = version,
            .eth_protocol = eth_protocol,
            .seen_long_hdr = (hdr_type == QUIC_HEADER_TYPE_LONG) ? 1 : 0,
            .seen_short_hdr = (hdr_type == QUIC_HEADER_TYPE_SHORT) ? 1 : 0,
        };
        long ret = bpf_map_update_elem(&quic_flows, id, &new_flow, BPF_NOEXIST);
        if (ret != 0) {
            if (trace_messages && ret != -EEXIST) {
                bpf_printk("error adding quic flow %d\n", ret);
            }
            if (ret == -EEXIST) {
                quic_metrics *flow = bpf_map_lookup_elem(&quic_flows, id);
                if (flow) {
                    flow->end_mono_time_ts = now;
                    flow->packets++;
                    flow->bytes += len;
                }
            }
        }
    }

    return 0;
}
#endif /* __QUIC_TRACKER_H__ */
