/*
    Flows v2. A Flow-metric generator using TC.

    This program can be hooked on to TC ingress/egress hook to monitor packets
    to/from an interface.

    Logic:
        1) Store flow information in a per-cpu hash map.
        2) Upon flow completion (tcp->fin event), evict the entry from map, and
           send to userspace through ringbuffer.
           Eviction for non-tcp flows need to done by userspace
        3) When the map is full, we send the new flow entry to userspace via ringbuffer,
            until an entry is available.
        4) When hash collision is detected, we send the new entry to userpace via ringbuffer.
*/

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <string.h>

#include <stdbool.h>
#include <linux/if_ether.h>

#include "flow.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DISCARD 1
#define SUBMIT 0

// according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
#define INGRESS 0
#define EGRESS 1

// Common Ringbuffer as a conduit for ingress/egress maps to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, flow_id);
    __type(value, flow_aggregate);
    __uint(max_entries, INGRESS_MAX_ENTRIES);
} xflow_metric_map_ingress SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, flow_id);
    __type(value, flow_aggregate);
    __uint(max_entries, EGRESS_MAX_ENTRIES);
} xflow_metric_map_egress SEC(".maps");

// Constant definitions, to be overridden by the invoker
volatile const u32 sampling = 0;

const u8 ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

// sets flow fields from IPv4 header information
// Flags is highlight any protocol specific info
static inline int fill_iphdr(struct iphdr *ip, void *data_end, flow_id *id) {
    if ((void *)ip + sizeof(*ip) > data_end) {
        return DISCARD;
    }

    __builtin_memcpy(id->src_ip.s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(id->dst_ip.s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(id->src_ip.s6_addr + sizeof(ip4in6), &ip->saddr, sizeof(ip->saddr));
    __builtin_memcpy(id->dst_ip.s6_addr + sizeof(ip4in6), &ip->daddr, sizeof(ip->daddr));
    id->protocol = ip->protocol;
    id->src_port = 0;
    id->dst_port = 0;
    switch (ip->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            id->src_port = __bpf_ntohs(tcp->source);
            id->dst_port = __bpf_ntohs(tcp->dest);
        }
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) <= data_end) {
            id->src_port = __bpf_ntohs(udp->source);
            id->dst_port = __bpf_ntohs(udp->dest);
        }
    } break;
    default:
        break;
    }
    return SUBMIT;
}

// sets flow fields from IPv6 header information
static inline int fill_ip6hdr(struct ipv6hdr *ip, void *data_end, flow_id *id) {
    if ((void *)ip + sizeof(*ip) > data_end) {
        return DISCARD;
    }

    id->src_ip = ip->saddr;
    id->dst_ip = ip->daddr;
    id->protocol = ip->nexthdr;
    id->src_port = 0;
    id->dst_port = 0;
    switch (ip->nexthdr) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            id->src_port = __bpf_ntohs(tcp->source);
            id->dst_port = __bpf_ntohs(tcp->dest);
        }
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) <= data_end) {
            id->src_port = __bpf_ntohs(udp->source);
            id->dst_port = __bpf_ntohs(udp->dest);
        }
    } break;
    default:
        break;
    }
    return SUBMIT;
}
// sets flow fields from Ethernet header information
static inline int fill_ethhdr(struct ethhdr *eth, void *data_end, flow_id *id) {
    if ((void *)eth + sizeof(*eth) > data_end) {
        return DISCARD;
    }
    __builtin_memcpy(id->dst_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(id->src_mac, eth->h_source, ETH_ALEN);
    id->eth_protocol = __bpf_ntohs(eth->h_proto);

    if (id->eth_protocol == ETH_P_IP) {
        struct iphdr *ip = (void *)eth + sizeof(*eth);
        return fill_iphdr(ip, data_end, id);
    } else if (id->eth_protocol == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);
        return fill_ip6hdr(ip6, data_end, id);
    } else {
        // TODO : Need to implement other specific ethertypes if needed
        // For now other parts of flow id remain zero
        memset (&(id->src_ip),0, sizeof(struct in6_addr));
        memset (&(id->dst_ip),0, sizeof(struct in6_addr));
        id->protocol = 0;
        id->src_port = 0;
        id->dst_port = 0;
    }
    return SUBMIT;
}


static inline int flow_monitor (struct __sk_buff *skb, u8 direction) {
    // If sampling is defined, will only parse 1 out of "sampling" flows
    if (sampling != 0 && (bpf_get_prandom_u32() % sampling) != 0) {
        return TC_ACT_OK;
    }
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    flow_id id;
    int rc = TC_ACT_OK;
    flow_record *flow_event;
    flow_aggregate *my_flow_aggregate;

    u64 current_time = bpf_ktime_get_ns();

    struct ethhdr *eth = data;
    if (fill_ethhdr(eth, data_end, &id) == DISCARD) {
        return TC_ACT_OK;
    }
    id.direction = direction;
    if (direction == INGRESS) {
        my_flow_aggregate = bpf_map_lookup_elem(&xflow_metric_map_ingress, &id);
    } else {
        my_flow_aggregate = bpf_map_lookup_elem(&xflow_metric_map_egress, &id);
    }

    if (my_flow_aggregate != NULL) {
        // The key already exists in the map
        bool update = false;
        my_flow_aggregate->packets += 1;
        my_flow_aggregate->bytes += skb->len;
        my_flow_aggregate->last_pkt_ts = current_time;
        if (my_flow_aggregate->id.eth_protocol == 0) { // Ensures no other flow is residing
            my_flow_aggregate->id = id;
            update = true;
        } else {
            // check flow id stored
            // If its the same, then perform write to map
            // Else send to ringbuffer
            if (my_flow_aggregate->id.src_port == id.src_port &&
                my_flow_aggregate->id.dst_port == id.dst_port &&
                my_flow_aggregate->id.protocol == id.protocol) {
                update = true;
            }
        }
        if (update == true) {
            // Update existing map when no collision detected
            if (direction == INGRESS) {
                bpf_map_update_elem(&xflow_metric_map_ingress, &id, my_flow_aggregate, BPF_EXIST);
            } else {
                bpf_map_update_elem(&xflow_metric_map_egress, &id, my_flow_aggregate, BPF_EXIST);
            }
        } else {
            // Sending to ringbuffer since collision detected
            flow_metrics new_flow_counter = {.bytes=skb->len};
            new_flow_counter.flags = COLLISION_FLAG;
            flow_event = bpf_ringbuf_reserve(&flows, sizeof(flow_record), 0);
            if (!flow_event) {
                return rc;
            }
            flow_event->id = id;
            flow_event->metrics = new_flow_counter;
            bpf_ringbuf_submit(flow_event, 0);
        }
    } else {
        // Key does not exist in the map, and will need to create a new entry.
        flow_aggregate my_flow_aggregate = {
            .packets = 1, .bytes=skb->len};
        my_flow_aggregate.flow_start_ts = current_time;
        my_flow_aggregate.last_pkt_ts = current_time;

        my_flow_aggregate.id = id;
        int ret;
        if (direction == INGRESS) {
            ret = bpf_map_update_elem(&xflow_metric_map_ingress, &id, &my_flow_aggregate,
                                      BPF_NOEXIST);
        } else {
            ret = bpf_map_update_elem(&xflow_metric_map_egress, &id, &my_flow_aggregate,
                                      BPF_NOEXIST);
        }
        if (ret < 0) {
            // Map is full
            /*
                When the map is full, we have two choices, send the new flow entry to userspace via ringbuffer,
                until an entry is available.
            */
            flow_metrics new_flow_counter = {.bytes=skb->len};
            new_flow_counter.flags = MAPFULL_FLAG;
            flow_event = bpf_ringbuf_reserve(&flows, sizeof(flow_record), 0);
            if (!flow_event) {
                return rc;
            }
            flow_event->id = id;
            flow_event->metrics = new_flow_counter;
            bpf_ringbuf_submit(flow_event, 0);
        }
    }
    return rc;

}
SEC("tc_ingress")
int ingress_flow_parse (struct __sk_buff *skb) {
    return flow_monitor(skb, INGRESS);
}

SEC("tc_egress")
int egress_flow_parse (struct __sk_buff *skb) {
    return flow_monitor(skb, EGRESS);
}
char _license[] SEC("license") = "GPL";
