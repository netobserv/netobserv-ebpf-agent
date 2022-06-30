/*
    Flows v2. A Flow-metric generator using TC.

    This program can be hooked on to TC ingress/egress hook to monitor packets
    to/from an interface.

    Logic:
        1) Store flow information in a per-cpu hash map.
        2) Upon flow completion (tcp->fin event), evict the entry from map, and
           send to userspace through ringbuffer.
           Eviction for non-tcp flows need to done by userspace
        3) When the map is full, we have two choices:
                1) Send the new flow entry to userspace via ringbuffer,
                        until an entry is available.
                2) Send an existing flow entry (probably least recently used)
                        to userspace via ringbuffer, delete that entry, and add in the
                        new flow to the hash map.

                Ofcourse, 2nd step involves more manipulations and
                    state maintenance, and will it provide any performance benefit?
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
    __type(key, flow_id_v);
    __type(value, flow_metrics);
    __uint(max_entries, INGRESS_MAX_ENTRIES);
} xflow_metric_map_ingress SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, flow_id_v);
    __type(value, flow_metrics);
    __uint(max_entries, EGRESS_MAX_ENTRIES);
} xflow_metric_map_egress SEC(".maps");


// Constant definitions, to be overridden by the invoker
volatile const u32 sampling = 0;

const u8 ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

// sets flow fields from IPv4 header information
// Flags is highlight any protocol specific info
static inline int fill_iphdr(struct iphdr *ip, void *data_end, flow_id_v *flow_id, u32 *flags) {
    if ((void *)ip + sizeof(*ip) > data_end) {
        return DISCARD;
    }

    __builtin_memcpy(flow_id->src_ip.s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(flow_id->dst_ip.s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(flow_id->src_ip.s6_addr + sizeof(ip4in6), &ip->saddr, sizeof(ip->saddr));
    __builtin_memcpy(flow_id->dst_ip.s6_addr + sizeof(ip4in6), &ip->daddr, sizeof(ip->daddr));
    flow_id->protocol = ip->protocol;
    flow_id->src_port = 0;
    flow_id->dst_port = 0;
    switch (ip->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            flow_id->src_port = __bpf_ntohs(tcp->source);
            flow_id->dst_port = __bpf_ntohs(tcp->dest);
            if (tcp->fin) {
                *flags= *flags | TCP_FIN_FLAG;
            }
            if (tcp->rst) {
                *flags= *flags | TCP_RST_FLAG;
            }
        }
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) <= data_end) {
            flow_id->src_port = __bpf_ntohs(udp->source);
            flow_id->dst_port = __bpf_ntohs(udp->dest);
        }
    } break;
    default:
        break;
    }
    return SUBMIT;
}

// sets flow fields from IPv6 header information
static inline int fill_ip6hdr(struct ipv6hdr *ip, void *data_end, flow_id_v *flow_id, u32 *flags) {
    if ((void *)ip + sizeof(*ip) > data_end) {
        return DISCARD;
    }

    flow_id->src_ip = ip->saddr;
    flow_id->dst_ip = ip->daddr;
    flow_id->protocol = ip->nexthdr;
    flow_id->src_port = 0;
    flow_id->dst_port = 0;
    switch (ip->nexthdr) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            flow_id->src_port = __bpf_ntohs(tcp->source);
            flow_id->dst_port = __bpf_ntohs(tcp->dest);
             if (tcp->fin) {
                 *flags= *flags | TCP_FIN_FLAG;
             }
             if (tcp->rst) {
                 *flags= *flags | TCP_RST_FLAG;
             }
        }
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) <= data_end) {
            flow_id->src_port = __bpf_ntohs(udp->source);
            flow_id->dst_port = __bpf_ntohs(udp->dest);
        }
    } break;
    default:
        break;
    }
    return SUBMIT;
}
// sets flow fields from Ethernet header information
static inline int fill_ethhdr(struct ethhdr *eth, void *data_end, flow_id_v *flow_id, u32 *flags) {
    if ((void *)eth + sizeof(*eth) > data_end) {
        return DISCARD;
    }
    __builtin_memcpy(flow_id->dst_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(flow_id->src_mac, eth->h_source, ETH_ALEN);
    flow_id->eth_protocol = __bpf_ntohs(eth->h_proto);

    if (flow_id->eth_protocol == ETH_P_IP) {
        struct iphdr *ip = (void *)eth + sizeof(*eth);
        return fill_iphdr(ip, data_end, flow_id, flags);
    } else if (flow_id->eth_protocol == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);
        return fill_ip6hdr(ip6, data_end, flow_id, flags);
    } else {
        // TODO : Need to implement other specific ethertypes if needed
        // For now other parts of flow id remain zero
        memset (&(flow_id->src_ip),0, sizeof(struct in6_addr));
        memset (&(flow_id->dst_ip),0, sizeof(struct in6_addr));
        flow_id->protocol = 0;
        flow_id->src_port = 0;
        flow_id->dst_port = 0;
    }
    return SUBMIT;
}

static inline void export_flow_id (flow *my_flow_key, flow_id_v my_flow_id, u8 direction) {
    my_flow_key->protocol = my_flow_id.eth_protocol;
    my_flow_key->direction = direction;
    __builtin_memcpy(my_flow_key->data_link.src_mac, my_flow_id.src_mac, ETH_ALEN);
    __builtin_memcpy(my_flow_key->data_link.dst_mac, my_flow_id.dst_mac, ETH_ALEN);
    my_flow_key->network.src_ip = my_flow_id.src_ip;
    my_flow_key->network.dst_ip = my_flow_id.dst_ip;
    my_flow_key->transport.src_port = my_flow_id.src_port;
    my_flow_key->transport.dst_port = my_flow_id.dst_port;
    my_flow_key->transport.protocol = my_flow_id.protocol;
}

static inline int flow_monitor (struct __sk_buff *skb, u8 direction) {
    // If sampling is defined, will only parse 1 out of "sampling" flows
    if (sampling != 0 && (bpf_get_prandom_u32() % sampling) != 0) {
        return TC_ACT_OK;
    }
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    flow_id_v my_flow_id;
    int rc = TC_ACT_OK;
    u32 flags = 0;
    flow_record *flow_event;
    flow_metrics *my_flow_counters;
    __u64 current_time = bpf_ktime_get_ns();

    struct ethhdr *eth = data;
    if (fill_ethhdr(eth, data_end, &my_flow_id, &flags) == DISCARD) {
        return TC_ACT_OK;
    }
    if (direction == INGRESS) {
        my_flow_counters = bpf_map_lookup_elem(&xflow_metric_map_ingress, &my_flow_id);
    } else {
        my_flow_counters = bpf_map_lookup_elem(&xflow_metric_map_egress, &my_flow_id);
    }

    if (my_flow_counters != NULL) {
        my_flow_counters->packets += 1;
        my_flow_counters->bytes += skb->len;
        my_flow_counters->last_pkt_ts = current_time;
        if (flags & TCP_FIN_FLAG || flags & TCP_RST_FLAG) {
            /* Need to evict the entry and send it via ring buffer */
            flow_event = bpf_ringbuf_reserve(&flows, sizeof(flow_record), 0);
            if (!flow_event) {
                return rc;
            }
            export_flow_id(&flow_event->flow_key, my_flow_id, 1);
            // flow_event->metrics.packets = my_flow_counters->packets;
            // flow_event->metrics.bytes = my_flow_counters->bytes;
            // flow_event->metrics.last_pkt_ts = my_flow_counters->last_pkt_ts;
            flow_event->metrics.flags = flags;
            bpf_ringbuf_submit(flow_event, 0);
            // Defer the deletion of the entry from the map to usespace since it evicts other CPU metrics
        } else {
            if (direction == INGRESS) {
                bpf_map_update_elem(&xflow_metric_map_ingress, &my_flow_id, my_flow_counters, BPF_EXIST);
            } else {
                bpf_map_update_elem(&xflow_metric_map_egress, &my_flow_id, my_flow_counters, BPF_EXIST);
            }
        }
    } else {
        flow_metrics new_flow_counter = {
            .packets = 1, .bytes=skb->len};
        new_flow_counter.flow_start_ts = current_time;
        new_flow_counter.last_pkt_ts = current_time;
        int ret;
        if (direction == INGRESS) {
            ret = bpf_map_update_elem(&xflow_metric_map_ingress, &my_flow_id, &new_flow_counter,
                                      BPF_NOEXIST);
        } else {
            ret = bpf_map_update_elem(&xflow_metric_map_egress, &my_flow_id, &new_flow_counter,
                                      BPF_NOEXIST);
        }
        if (ret < 0) {
            /*
                When the map is full, we have two choices:
                    1) Send the new flow entry to userspace via ringbuffer,
                       until an entry is available.
                    2) Send an existing flow entry (probably least recently used)
                       to userspace via ringbuffer, delete that entry, and add in the
                       new flow to the hash map.

                Ofcourse, 2nd step involves more manipulations and
                       state maintenance, and no guarantee if it will any performance benefit.
                Hence, taking the first approach here to send the entry to userspace
                and do nothing in the eBPF datapath and wait for userspace to create more space in the Map.

            */

            flow_event = bpf_ringbuf_reserve(&flows, sizeof(flow_record), 0);
            if (!flow_event) {
                return rc;
            }
            export_flow_id(&flow_event->flow_key, my_flow_id, 1);
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
