/*
    Flows v2.
    Flow monitor: A Flow-metric generator using TC.

    This program can be hooked on to TC ingress/egress hook to monitor packets
    to/from an interface.

    Logic:
        1) Store flow information in a hash map.
        2) Periodically evict the entry from map from userspace.
        3) When the map is full/busy, we send the new flow entry to userspace via ringbuffer,
            until an entry is available.
*/
#include <vmlinux.h>
#include <bpf_helpers.h>
#include "configs.h"
#include "utils.h"

/*
 * Defines a packet drops statistics tracker,
 * which attaches at kfree_skb hook. Is optional.
 */
#include "pkt_drops.h"

/*
 * Defines a dns tracker,
 * which attaches at net_dev_queue hook. Is optional.
 */
#include "dns_tracker.h"

/*
 * Defines an rtt tracker,
 * which runs inside flow_monitor. Is optional.
 */
#include "rtt_tracker.h"

/*
 * Defines a Packet Capture Agent (PCA) tracker,
 * It is enabled by setting env var ENABLE_PCA= true. Is Optional
 */
#include "pca.h"

/* Do flow filtering. Is optional. */
#include "flows_filter.h"
/*
 * Defines an Network events monitoring tracker,
 * which runs inside flow_monitor. Is optional.
 */
#include "network_events_monitoring.h"
/*
 * Defines packets translation tracker
 */
#include "pkt_translation.h"

// return 0 on success, 1 if capacity reached
static __always_inline int add_observed_intf(flow_metrics *value, pkt_info *pkt, u32 if_index,
                                             u8 direction) {
    if (value->nb_observed_intf >= MAX_OBSERVED_INTERFACES) {
        BPF_PRINTK("observed interface missed (array capacity reached) for ifindex %d\n", if_index);
        return 1;
    }
    for (u8 i = 0; i < value->nb_observed_intf; i++) {
        if (value->observed_intf[i] == if_index) {
            if (value->observed_direction[i] != direction &&
                value->observed_direction[i] != OBSERVED_DIRECTION_BOTH) {
                // Same interface seen on a different direction => mark as both directions
                value->observed_direction[i] = OBSERVED_DIRECTION_BOTH;
            }
            // Interface already seen -> skip
            return 0;
        }
    }
    value->observed_intf[value->nb_observed_intf] = if_index;
    value->observed_direction[value->nb_observed_intf] = direction;
    value->nb_observed_intf++;
    return 0;
}

static __always_inline void update_existing_flow(flow_metrics *aggregate_flow, pkt_info *pkt,
                                                 u64 len, u32 sampling, u32 if_index,
                                                 u8 direction) {
    // Count only packets seen from the same interface as previously to avoid duplicate counts
    int maxReached = 0;
    bpf_spin_lock(&aggregate_flow->lock);
    if (aggregate_flow->if_index_first_seen == if_index) {
        aggregate_flow->packets += 1;
        aggregate_flow->bytes += len;
        aggregate_flow->end_mono_time_ts = pkt->current_ts;
        aggregate_flow->flags |= pkt->flags;
        aggregate_flow->dscp = pkt->dscp;
        aggregate_flow->sampling = sampling;
    } else if (if_index != 0) {
        // Only add info that we've seen this interface (we can also update end time & flags)
        aggregate_flow->end_mono_time_ts = pkt->current_ts;
        aggregate_flow->flags |= pkt->flags;
        maxReached = add_observed_intf(aggregate_flow, pkt, if_index, direction);
    }
    bpf_spin_unlock(&aggregate_flow->lock);
    if (maxReached > 0) {
        increase_counter(OBSERVED_INTF_MISSED);
    }
}

static inline void update_dns(additional_metrics *extra_metrics, pkt_info *pkt, int dns_errno) {
    if (pkt->dns_id != 0) {
        extra_metrics->end_mono_time_ts = pkt->current_ts;
        extra_metrics->dns_record.id = pkt->dns_id;
        extra_metrics->dns_record.flags = pkt->dns_flags;
        extra_metrics->dns_record.latency = pkt->dns_latency;
    }
    if (dns_errno != 0) {
        extra_metrics->dns_record.errno = dns_errno;
    }
}

static inline int flow_monitor(struct __sk_buff *skb, u8 direction) {
    if (!has_filter_sampling) {
        // When no filter sampling is defined, run the sampling check at the earliest for better performances
        // If sampling is defined, will only parse 1 out of "sampling" flows
        if (sampling > 1 && (bpf_get_prandom_u32() % sampling) != 0) {
            do_sampling = 0;
            return TC_ACT_OK;
        }
        do_sampling = 1;
    }

    u16 eth_protocol = 0;
    pkt_info pkt;
    __builtin_memset(&pkt, 0, sizeof(pkt));

    flow_id id;
    __builtin_memset(&id, 0, sizeof(id));

    pkt.current_ts = bpf_ktime_get_ns(); // Record the current time first.
    pkt.id = &id;

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = (struct ethhdr *)data;
    u64 len = skb->len;

    if (fill_ethhdr(eth, data_end, &pkt, &eth_protocol) == DISCARD) {
        return TC_ACT_OK;
    }

    // check if this packet need to be filtered if filtering feature is enabled
    u32 filter_sampling = 0;
    bool skip =
        check_and_do_flow_filtering(&id, pkt.flags, 0, eth_protocol, &filter_sampling, direction);
    if (has_filter_sampling) {
        if (filter_sampling == 0) {
            filter_sampling = sampling;
        }
        // If sampling is defined, will only parse 1 out of "sampling" flows
        if (filter_sampling > 1 && (bpf_get_prandom_u32() % filter_sampling) != 0) {
            do_sampling = 0;
            return TC_ACT_OK;
        }
        do_sampling = 1;
    }
    if (skip) {
        return TC_ACT_OK;
    }

    int dns_errno = 0;
    if (enable_dns_tracking) {
        dns_errno = track_dns_packet(skb, &pkt);
    }
    flow_metrics *aggregate_flow = (flow_metrics *)bpf_map_lookup_elem(&aggregated_flows, &id);
    if (aggregate_flow != NULL) {
        update_existing_flow(aggregate_flow, &pkt, len, filter_sampling, skb->ifindex, direction);
    } else {
        // Key does not exist in the map, and will need to create a new entry.
        flow_metrics new_flow;
        __builtin_memset(&new_flow, 0, sizeof(new_flow));
        new_flow.if_index_first_seen = skb->ifindex;
        new_flow.direction_first_seen = direction;
        new_flow.packets = 1;
        new_flow.bytes = len;
        new_flow.eth_protocol = eth_protocol;
        new_flow.start_mono_time_ts = pkt.current_ts;
        new_flow.end_mono_time_ts = pkt.current_ts;
        new_flow.flags = pkt.flags;
        new_flow.dscp = pkt.dscp;
        new_flow.sampling = filter_sampling;
        __builtin_memcpy(new_flow.dst_mac, eth->h_dest, ETH_ALEN);
        __builtin_memcpy(new_flow.src_mac, eth->h_source, ETH_ALEN);

        long ret = bpf_map_update_elem(&aggregated_flows, &id, &new_flow, BPF_NOEXIST);
        if (ret != 0) {
            if (trace_messages && ret != -EEXIST) {
                bpf_printk("error adding flow %d\n", ret);
            }
            if (ret == -EEXIST) {
                flow_metrics *aggregate_flow =
                    (flow_metrics *)bpf_map_lookup_elem(&aggregated_flows, &id);
                if (aggregate_flow != NULL) {
                    update_existing_flow(aggregate_flow, &pkt, len, filter_sampling, skb->ifindex,
                                         direction);
                } else {
                    if (trace_messages) {
                        bpf_printk("failed to update an exising flow\n");
                    }
                    // Update global counter for hashmap update errors
                    increase_counter(HASHMAP_FLOWS_DROPPED);
                }
            } else {
                // usually error -16 (-EBUSY) or -7 (E2BIG) is printed here.
                // In this case, we send the single-packet flow via ringbuffer as in the worst case we can have
                // a repeated INTERSECTION of flows (different flows aggregating different packets),
                // which can be re-aggregated at userpace.
                // other possible values https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
                new_flow.errno = -ret;
                flow_record *record =
                    (flow_record *)bpf_ringbuf_reserve(&direct_flows, sizeof(flow_record), 0);
                if (!record) {
                    if (trace_messages) {
                        bpf_printk("couldn't reserve space in the ringbuf. Dropping flow");
                    }
                    return TC_ACT_OK;
                }
                record->id = id;
                record->metrics = new_flow;
                bpf_ringbuf_submit(record, 0);
            }
        }
    }

    // Update additional metrics (per-CPU map)
    if (pkt.dns_id != 0 || dns_errno != 0) {
        additional_metrics *extra_metrics =
            (additional_metrics *)bpf_map_lookup_elem(&additional_flow_metrics, &id);
        if (extra_metrics != NULL) {
            update_dns(extra_metrics, &pkt, dns_errno);
        } else {
            additional_metrics new_metrics = {
                .start_mono_time_ts = pkt.current_ts,
                .end_mono_time_ts = pkt.current_ts,
                .eth_protocol = eth_protocol,
                .dns_record.id = pkt.dns_id,
                .dns_record.flags = pkt.dns_flags,
                .dns_record.latency = pkt.dns_latency,
                .dns_record.errno = dns_errno,
            };
            long ret =
                bpf_map_update_elem(&additional_flow_metrics, &id, &new_metrics, BPF_NOEXIST);
            if (ret != 0) {
                if (trace_messages && ret != -EEXIST) {
                    bpf_printk("error adding DNS %d\n", ret);
                }
                if (ret == -EEXIST) {
                    // Concurrent write from another CPU; retry
                    additional_metrics *extra_metrics =
                        (additional_metrics *)bpf_map_lookup_elem(&additional_flow_metrics, &id);
                    if (extra_metrics != NULL) {
                        update_dns(extra_metrics, &pkt, dns_errno);
                    } else {
                        if (trace_messages) {
                            bpf_printk("failed to update DNS\n");
                        }
                        increase_counter(HASHMAP_FAIL_UPDATE_DNS);
                    }
                } else {
                    increase_counter(HASHMAP_FAIL_UPDATE_DNS);
                }
            }
        }
    }

    return TC_ACT_OK;
}

SEC("classifier/tc_ingress")
int tc_ingress_flow_parse(struct __sk_buff *skb) {
    return flow_monitor(skb, INGRESS);
}

SEC("classifier/tc_egress")
int tc_egress_flow_parse(struct __sk_buff *skb) {
    return flow_monitor(skb, EGRESS);
}

SEC("classifier/tcx_ingress")
int tcx_ingress_flow_parse(struct __sk_buff *skb) {
    flow_monitor(skb, INGRESS);
    // return TCX_NEXT to allow existing with other TCX hooks
    return TCX_NEXT;
}

SEC("classifier/tcx_egress")
int tcx_egress_flow_parse(struct __sk_buff *skb) {
    flow_monitor(skb, EGRESS);
    // return TCX_NEXT to allow existing with other TCX hooks
    return TCX_NEXT;
}

char _license[] SEC("license") = "GPL";
