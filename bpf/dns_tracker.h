/*
    light weight DNS tracker.
*/

#ifndef __DNS_TRACKER_H__
#define __DNS_TRACKER_H__
#include "utils.h"

#define DNS_PORT        53
#define DNS_QR_FLAG     0x8000
#define UDP_MAXMSG      512
#define EINVAL          22

struct dns_header {
    u16 id;
    u16 flags;
    u16 qdcount;
    u16 ancount;
    u16 nscount;
    u16 arcount;
};

static inline void fill_dns_id (flow_id *id, dns_flow_id *dns_flow, u16 dns_id, bool reverse) {
    dns_flow->id = dns_id;
    dns_flow->protocol = id->transport_protocol;
    if (reverse) {
        __builtin_memcpy(dns_flow->src_ip, id->dst_ip, IP_MAX_LEN);
        __builtin_memcpy(dns_flow->dst_ip, id->src_ip, IP_MAX_LEN);
        dns_flow->src_port = id->dst_port;
        dns_flow->dst_port = id->src_port;
    } else {
        __builtin_memcpy(dns_flow->src_ip, id->src_ip, IP_MAX_LEN);
        __builtin_memcpy(dns_flow->dst_ip, id->dst_ip, IP_MAX_LEN);
        dns_flow->src_port = id->src_port;
        dns_flow->dst_port = id->dst_port;
    }
}

static __always_inline u8 calc_dns_header_offset(pkt_info *pkt, void *data_end) {
    u8 len = 0;
    switch (pkt->id->transport_protocol) {
        case IPPROTO_TCP: {
            struct tcphdr *tcp = (struct tcphdr *) pkt->l4_hdr;
            if (!tcp || ((void *)tcp + sizeof(*tcp) > data_end)) {
                return 0;
            }
            len = tcp->doff * sizeof(u32) + 2; // DNS over TCP has 2 bytes of length at the beginning
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr *udp = (struct udphdr *) pkt->l4_hdr;
            if (!udp || ((void *)udp + sizeof(*udp) > data_end)) {
                return 0;
            }
            len = bpf_ntohs(udp->len);
            // make sure udp payload doesn't exceed max msg size
            if (len - sizeof(struct udphdr) > UDP_MAXMSG) {
                return 0;
            }
            // set the length to udp hdr size as it will be used to locate dns header
            len = sizeof(struct udphdr);
            break;
        }
    }
    return len;
}

static __always_inline int track_dns_packet(struct __sk_buff *skb, pkt_info *pkt) {
    void *data_end = (void *)(long)skb->data_end;
    if (pkt->id->dst_port == DNS_PORT || pkt->id->src_port == DNS_PORT) {
        dns_flow_id dns_req;

        u8 len = calc_dns_header_offset(pkt, data_end);
        if (!len) {
            return EINVAL;
        }

        struct dns_header dns;
        int ret;
        u32 dns_offset = (long)pkt->l4_hdr - (long)skb->data + len;

        if ((ret = bpf_skb_load_bytes(skb, dns_offset, &dns, sizeof(dns))) < 0) {
            return -ret;
        }

        u16 dns_id = bpf_ntohs(dns.id);
        u16 flags = bpf_ntohs(dns.flags);
        u64 ts = bpf_ktime_get_ns();

        if ((flags & DNS_QR_FLAG) == 0) { /* dns query */
            fill_dns_id(pkt->id, &dns_req, dns_id, false);
            if (bpf_map_lookup_elem(&dns_flows, &dns_req) == NULL) {
                bpf_map_update_elem(&dns_flows, &dns_req, &ts, BPF_ANY);
            }
        } else { /* dns response */
            fill_dns_id(pkt->id, &dns_req, dns_id, true);
            u64 *value = bpf_map_lookup_elem(&dns_flows, &dns_req);
             if (value != NULL) {
                pkt->dns_latency = ts - *value;
                pkt->dns_id = dns_id;
                pkt->dns_flags = flags;
                bpf_map_delete_elem(&dns_flows, &dns_req);
             }
        } // end of dns response
    } // end of dns port check
    return 0;
}

#endif // __DNS_TRACKER_H__
