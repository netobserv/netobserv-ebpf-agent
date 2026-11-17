#ifndef __MAPS_DEFINITION_H__
#define __MAPS_DEFINITION_H__

#include <vmlinux.h>
#include "types.h"

#define MAX_FILTER_ENTRIES 16

// Common Ringbuffer as a conduit for ingress/egress flows to userspace
// Unused unless ENABLE_FLOWS_RINGBUF_FALLBACK is set
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // minimized to os.Getpagesize() when unused
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} direct_flows SEC(".maps");

// Key: the flow identifier. Value: the flow metrics for that identifier.
// This is the main flows map, always used
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, flow_id);
    __type(value, flow_metrics);
    __uint(max_entries, 1 << 24); // changed to CACHE_MAX_FLOWS at startup
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aggregated_flows SEC(".maps");

// Key: the flow identifier. Value: dns metrics for that identifier.
// Used if ENABLE_DNS_TRACKING is true
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, flow_id);
    __type(value, dns_metrics);
    __uint(max_entries, 1 << 24); // changed to CACHE_MAX_DNS_FLOWS at startup
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aggregated_flows_dns SEC(".maps");

// Key: the flow identifier. Value: drops metrics for that identifier.
// Used if ENABLE_PKT_DROPS is true
struct {
    // per-cpu because: "tracing progs cannot use bpf_spin_lock yet"
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, flow_id);
    __type(value, pkt_drop_metrics);
    __uint(max_entries, 1 << 24); // changed to CACHE_MAX_PKT_DROPS_FLOWS at startup
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aggregated_flows_pkt_drop SEC(".maps");

// Key: the flow identifier. Value: network events metrics for that identifier.
// Used if ENABLE_NETWORK_EVENTS_MONITORING is true
struct {
    // per-cpu because: "tracing progs cannot use bpf_spin_lock yet"
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, flow_id);
    __type(value, network_events_metrics);
    __uint(max_entries, 1 << 24); // changed to CACHE_MAX_NETWORK_EVENT_FLOWS at startup
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aggregated_flows_network_events SEC(".maps");

// Key: the flow identifier. Value: xlat metrics for that identifier.
// Used if ENABLE_PKT_TRANSLATION is true
struct {
    // per-cpu because: "tracing progs cannot use bpf_spin_lock yet"
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, flow_id);
    __type(value, xlat_metrics);
    __uint(max_entries, 1 << 24); // changed to CACHE_MAX_XLAT_FLOWS at startup
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aggregated_flows_xlat SEC(".maps");

// Key: the flow identifier. Value: extra metrics for that identifier.
// Used if ENABLE_RTT or ENABLE_IPSEC_TRACKING is true
struct {
    // per-cpu because: "tracing progs cannot use bpf_spin_lock yet"
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, flow_id);
    __type(value, additional_metrics);
    __uint(max_entries, 1 << 24); // changed to CACHE_MAX_ADDITIONAL_FLOWS at startup
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} additional_flow_metrics SEC(".maps");

// DNS tracking flow based hashmap used to correlate query and responses
// to allow calculating latency in ebpf agent directly
// Used if ENABLE_DNS_TRACKING is true
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    // Will take around 32MB of space (per entry: key ~ 40B + value 8B + some overhead => 50-60B)
    __uint(max_entries, 1 << 19);
    __type(key, dns_flow_id);
    __type(value, u64);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_flows SEC(".maps");

// Global counter for hashmap update errors
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, MAX_COUNTERS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} global_counters SEC(".maps");

// Per-CPU temporary storage for DNS name (avoids stack limit)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, dns_name_buffer);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_name_map SEC(".maps");

// LPM trie map used to filter traffic by IP address CIDR
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct filter_key_t);
    __type(value, struct filter_value_t);
    __uint(max_entries, MAX_FILTER_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} filter_map SEC(".maps");

// LPM trie map used to filter traffic by peer IP address CIDR
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct filter_key_t);
    __type(value, u8);
    __uint(max_entries, MAX_FILTER_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} peer_filter_map SEC(".maps");

// HashMap to store ingress flowid to be able to retrieve them from kretprobe hook
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 20); // ~64MB; minimized to 1 when unused
    __type(key, u64);
    __type(value, flow_id);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ipsec_ingress_map SEC(".maps");

// HashMap to store egress flowid to be able to retrieve them from kretprobe hook
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 20); // ~64MB; minimized to 1 when unused
    __type(key, u64);
    __type(value, flow_id);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ipsec_egress_map SEC(".maps");

// QUIC flow tracking map - keyed by flow_id (like other flow maps)
// Used if QUIC_TRACKING_MODE != 0
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, flow_id);
    __type(value, quic_metrics);
    __uint(max_entries, 1 << 16); // changed to CACHE_MAX_QUIC_FLOWS at startup
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} quic_flows SEC(".maps");

#endif //__MAPS_DEFINITION_H__
