/*
    light weight DNS tracker using trace points.
*/

#ifndef __DNS_TRACKER_H__
#define __DNS_TRACKER_H__
#include "utils.h"

#define DNS_PORT        53
#define DNS_QR_FLAG     0x8000
#define UDP_MAXMSG      512

struct dns_header {
    u16 id;
    u16 flags;
    u16 qdcount;
    u16 ancount;
    u16 nscount;
    u16 arcount;
};

static inline void find_or_create_dns_flow(flow_id *id, struct dns_header *dns, int len, u16 flags, u64 latency) {
    flow_metrics *aggregate_flow = bpf_map_lookup_elem(&aggregated_flows, id);
    u64 current_time = bpf_ktime_get_ns();
    // net_dev_queue trace point hook will run before TC hooks, so the flow shouldn't exists, if it does
    // that indicates we have a stale DNS query/response or in the middle of TCP flow so we will do nothing
    if (aggregate_flow == NULL) {
        // there is no matching flows so lets create new one and dns info
         flow_metrics new_flow;
         __builtin_memset(&new_flow, 0, sizeof(new_flow));
         new_flow.start_mono_time_ts = current_time;
         new_flow.end_mono_time_ts = current_time;
         new_flow.packets = 1;
         new_flow.bytes = len;
         new_flow.flags = flags;
         new_flow.dns_record.id = bpf_ntohs(dns->id);
         new_flow.dns_record.flags = bpf_ntohs(dns->flags);
         new_flow.dns_record.latency = latency;
        bpf_map_update_elem(&aggregated_flows, id, &new_flow, BPF_ANY);
    }
}

static inline void fill_dns_id (flow_id *id, dns_flow_id *dns_flow, u16 dns_id, bool reverse) {
    dns_flow->id = dns_id;
    dns_flow->if_index = id->if_index;
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

static inline int trace_dns(struct sk_buff *skb) {
    flow_id id;
    u8 protocol = 0;
    u16 family = 0,flags = 0, len = 0;

    __builtin_memset(&id, 0, sizeof(id));

    id.if_index = skb->skb_iif;

    // read L2 info
    set_key_with_l2_info(skb, &id, &family);

    // read L3 info
    set_key_with_l3_info(skb, family, &id, &protocol);

    switch (protocol) {
    case IPPROTO_UDP:
        len = set_key_with_udp_info(skb, &id, IPPROTO_UDP);
        // make sure udp payload doesn't exceed max msg size
        if (len - sizeof(struct udphdr) > UDP_MAXMSG) {
            return -1;
        }
        // set the length to udp hdr size as it will be used below to locate dns header
        len = sizeof(struct udphdr);
        break;
    case IPPROTO_TCP:
        len = set_key_with_tcp_info(skb, &id, IPPROTO_TCP, &flags);
        break;
    default:
        return -1;
    }

    // check for DNS packets
    if (id.dst_port == DNS_PORT || id.src_port == DNS_PORT) {
        struct dns_header dns;
        dns_flow_id dns_req;
        u64 latency = 0;
        bpf_probe_read(&dns, sizeof(dns), (struct dns_header *)(skb->head + skb->transport_header + len));
        if ((bpf_ntohs(dns.flags) & DNS_QR_FLAG) == 0) { /* dns query */
            fill_dns_id(&id, &dns_req, bpf_ntohs(dns.id), false);
            if (bpf_map_lookup_elem(&dns_flows, &dns_req) == NULL) {
               u64 ts = bpf_ktime_get_ns();
                bpf_map_update_elem(&dns_flows, &dns_req, &ts, BPF_ANY);
            }
            id.direction = EGRESS;
        } else { /* dns response */
            id.direction = INGRESS;
            fill_dns_id(&id, &dns_req, bpf_ntohs(dns.id), true);
            u64 *value = bpf_map_lookup_elem(&dns_flows, &dns_req);
             if (value != NULL) {
                latency = bpf_ktime_get_ns() - *value;
                bpf_map_delete_elem(&dns_flows, &dns_req);
                find_or_create_dns_flow(&id, &dns, skb->len, flags, latency);
             }
        } // end of dns response
    } // end of dns port check

    return 0;
}

SEC("tracepoint/net/net_dev_queue")
int trace_net_packets(struct trace_event_raw_net_dev_template *args) {
    struct sk_buff skb;

    __builtin_memset(&skb, 0, sizeof(skb));
    bpf_probe_read(&skb, sizeof(struct sk_buff), args->skbaddr);
    return trace_dns(&skb);
}

#endif // __DNS_TRACKER_H__
