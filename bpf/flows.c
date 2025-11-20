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

/*
 * Defines ipsec tracker
 */
#include "ipsec.h"

// return 0 on success, 1 if capacity reached
// Optimized: loop unrolled and early exits for common cases
static __always_inline int add_observed_intf(flow_metrics *value, pkt_info *pkt, u32 if_index,
                                             u8 direction) {
    if (value->nb_observed_intf >= MAX_OBSERVED_INTERFACES) {
        return 1;
    }

    // Fast path: unroll loop for small array sizes (most common cases)
    // Check each position explicitly to eliminate loop overhead
    u8 nb = value->nb_observed_intf;

    // Unroll for common cases (0-3 interfaces) - most flows see 1-2 interfaces
    if (nb == 0) {
        // First interface - no check needed
        goto add_new;
    }

    // Check existing interfaces with unrolled comparisons
    if (value->observed_intf[0] == if_index) {
        if (value->observed_direction[0] != direction &&
            value->observed_direction[0] != OBSERVED_DIRECTION_BOTH) {
            value->observed_direction[0] = OBSERVED_DIRECTION_BOTH;
        }
        return 0;
    }

    if (nb >= 2 && value->observed_intf[1] == if_index) {
        if (value->observed_direction[1] != direction &&
            value->observed_direction[1] != OBSERVED_DIRECTION_BOTH) {
            value->observed_direction[1] = OBSERVED_DIRECTION_BOTH;
        }
        return 0;
    }

    if (nb >= 3 && value->observed_intf[2] == if_index) {
        if (value->observed_direction[2] != direction &&
            value->observed_direction[2] != OBSERVED_DIRECTION_BOTH) {
            value->observed_direction[2] = OBSERVED_DIRECTION_BOTH;
        }
        return 0;
    }

    // Fully unroll remaining cases (positions 3-5) for MAX_OBSERVED_INTERFACES=6
    if (nb >= 4 && value->observed_intf[3] == if_index) {
        if (value->observed_direction[3] != direction &&
            value->observed_direction[3] != OBSERVED_DIRECTION_BOTH) {
            value->observed_direction[3] = OBSERVED_DIRECTION_BOTH;
        }
        return 0;
    }

    if (nb >= 5 && value->observed_intf[4] == if_index) {
        if (value->observed_direction[4] != direction &&
            value->observed_direction[4] != OBSERVED_DIRECTION_BOTH) {
            value->observed_direction[4] = OBSERVED_DIRECTION_BOTH;
        }
        return 0;
    }

    if (nb >= 6 && value->observed_intf[5] == if_index) {
        if (value->observed_direction[5] != direction &&
            value->observed_direction[5] != OBSERVED_DIRECTION_BOTH) {
            value->observed_direction[5] = OBSERVED_DIRECTION_BOTH;
        }
        return 0;
    }

add_new:
    // Not found - add new interface
    value->observed_intf[nb] = if_index;
    value->observed_direction[nb] = direction;
    value->nb_observed_intf = nb + 1;
    return 0;
}

static __always_inline void update_existing_flow(flow_metrics *aggregate_flow, pkt_info *pkt,
                                                 u64 len, u32 sampling, u32 if_index,
                                                 u8 direction) {
    // Count only packets seen from the same interface as previously to avoid duplicate counts
    // Using lock-free atomic operations for better performance
    int maxReached = 0;

    // Read if_index_first_seen once (it's never modified after flow creation)
    u32 first_seen = aggregate_flow->if_index_first_seen;

    if (first_seen == if_index) {
        // Common path: same interface - use atomic operations
        __sync_fetch_and_add(&aggregate_flow->packets, 1);
        __sync_fetch_and_add(&aggregate_flow->bytes, len);
        // Timestamp: use simple write (acceptable if slightly out of order, we want latest anyway)
        // On architectures that support it, this will be naturally atomic for aligned 64-bit writes
        aggregate_flow->end_mono_time_ts = pkt->current_ts;
        // Flags is u16 - eBPF doesn't support atomic ops on 16-bit types
        // Use simple write: OR is idempotent, so worst case is missing a flag bit in rare races (acceptable)
        aggregate_flow->flags |= pkt->flags;
        // DSCP and sampling: simple writes (these are infrequently updated, races are acceptable)
        aggregate_flow->dscp = pkt->dscp;
        aggregate_flow->sampling = sampling;
    } else if (if_index != 0) {
        // Different interface path: update timestamps/flags atomically, then add interface
        aggregate_flow->end_mono_time_ts = pkt->current_ts;
        // Flags update - use simple write (OR is idempotent, occasional missed flag is acceptable)
        aggregate_flow->flags |= pkt->flags;
        // Note: add_observed_intf may have races, but worst case is missing one interface entry
        // This is acceptable since interface tracking is best-effort metadata
        maxReached = add_observed_intf(aggregate_flow, pkt, if_index, direction);
    }
    if (maxReached > 0) {
        BPF_PRINTK("observed interface missed (array capacity reached); ifindex=%d, eth_type=%d, "
                   "proto=%d, sport=%d, dport=%d\n",
                   if_index, aggregate_flow->eth_protocol, pkt->id->transport_protocol,
                   pkt->id->src_port, pkt->id->dst_port);
        if (pkt->id->transport_protocol != 0) {
            // Only raise counter on non-zero proto; zero proto traffic is very likely to have its interface max count reached
            increase_counter(OBSERVED_INTF_MISSED);
        }
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
    u32 flow_sampling = 0;
    if (!has_filter_sampling) {
        // When no filter sampling is defined, run the sampling check at the earliest for better performances
        // If sampling is defined, will only parse 1 out of "sampling" flows
        if (sampling > 1 && (bpf_get_prandom_u32() % sampling) != 0) {
            do_sampling = 0;
            return TC_ACT_OK;
        }
        flow_sampling = sampling;
        do_sampling = 1;
    }

    u16 eth_protocol = 0;
    // Initialize pkt_info with only needed fields - compiler zeros the rest
    pkt_info pkt;
    pkt.current_ts = bpf_ktime_get_ns(); // Record the current time first.
    pkt.id = NULL;                       // Will be set below
    pkt.flags = 0;
    pkt.l4_hdr = NULL;
    pkt.dscp = 0;
    pkt.dns_id = 0;
    pkt.dns_flags = 0;
    pkt.dns_latency = 0;
    // DNS name only initialized if DNS tracking enabled (set by track_dns_packet if needed)

    flow_id id = {0}; // All fields zeroed - needed for flow identification

    pkt.id = &id;

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = (struct ethhdr *)data;
    u64 len = skb->len;
    u8 protocol = 0; // Will be set by L3 parsing

    // Optimized: Parse L2+L3 first for early IP filtering
    // This allows us to skip L4 parsing if IP-based filtering rejects the packet
    if (fill_ethhdr_l3only(eth, data_end, &pkt, &eth_protocol, &protocol) == DISCARD) {
        return TC_ACT_OK;
    }

    // Early IP filtering: check if we can reject before parsing L4
    // This saves L4 parsing for packets that will be rejected anyway
    bool filter_enabled = is_filter_enabled();
    if (filter_enabled) {
        filter_action early_action = MAX_FILTER_ACTIONS;
        if (early_ip_filter_check(&id, &early_action, eth_protocol, direction)) {
            // Early rejection - skip L4 parsing entirely
            if (early_action == REJECT) {
                return TC_ACT_OK;
            }
        }
    }
    // Parse L4 (needed for full filtering or flow tracking)
    parse_l4_after_l3(eth, data_end, &pkt, eth_protocol, protocol);

    // Full filter check (now that L4 is parsed if needed)
    bool skip =
        check_and_do_flow_filtering(&id, pkt.flags, 0, eth_protocol, &flow_sampling, direction);
    if (has_filter_sampling) {
        if (flow_sampling == 0) {
            flow_sampling = sampling;
        }
        // If sampling is defined, will only parse 1 out of "sampling" flows
        if (flow_sampling > 1 && (bpf_get_prandom_u32() % flow_sampling) != 0) {
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
        update_existing_flow(aggregate_flow, &pkt, len, flow_sampling, skb->ifindex, direction);
    } else {
        // Key does not exist in the map, and will need to create a new entry.
        // Initialize only the fields we need - compiler will zero the rest
        flow_metrics new_flow = {
            .if_index_first_seen = skb->ifindex,
            .direction_first_seen = direction,
            .packets = 1,
            .bytes = len,
            .eth_protocol = eth_protocol,
            .start_mono_time_ts = pkt.current_ts,
            .end_mono_time_ts = pkt.current_ts,
            .flags = pkt.flags,
            .dscp = pkt.dscp,
            .sampling = flow_sampling,
            .nb_observed_intf = 0 // Explicitly zero for clarity
        };
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
                    update_existing_flow(aggregate_flow, &pkt, len, flow_sampling, skb->ifindex,
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
            // Initialize only needed fields - compiler will zero the rest
            additional_metrics new_metrics = {
                .start_mono_time_ts = pkt.current_ts,
                .end_mono_time_ts = pkt.current_ts,
                .eth_protocol = eth_protocol,
                .dns_record = {.id = pkt.dns_id,
                               .flags = pkt.dns_flags,
                               .latency = pkt.dns_latency,
                               .errno = dns_errno},
                .network_events_idx = 0 // Explicitly zero for clarity
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
