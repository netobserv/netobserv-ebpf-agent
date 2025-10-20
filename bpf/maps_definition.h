#ifndef __MAPS_DEFINITION_H__
#define __MAPS_DEFINITION_H__

#include <vmlinux.h>

// Common Ringbuffer as a conduit for ingress/egress flows to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} direct_flows SEC(".maps");

// Key: the flow identifier. Value: the flow metrics for that identifier.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, flow_id);
    __type(value, flow_metrics);
    __uint(max_entries, 1 << 24);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aggregated_flows SEC(".maps");

// Key: the flow identifier. Value: dns metrics for that identifier.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, flow_id);
    __type(value, dns_metrics);
    __uint(max_entries, 1 << 24);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aggregated_flows_dns SEC(".maps");

// Key: the flow identifier. Value: drops metrics for that identifier.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, flow_id);
    __type(value, pkt_drop_metrics);
    __uint(max_entries, 1 << 24);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aggregated_flows_pkt_drop SEC(".maps");

// Key: the flow identifier. Value: network events metrics for that identifier.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, flow_id);
    __type(value, network_events_metrics);
    __uint(max_entries, 1 << 24);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aggregated_flows_network_events SEC(".maps");

// Key: the flow identifier. Value: xlat metrics for that identifier.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, flow_id);
    __type(value, xlat_metrics);
    __uint(max_entries, 1 << 24);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aggregated_flows_xlat SEC(".maps");

// Key: the flow identifier. Value: extra metrics for that identifier.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, flow_id);
    __type(value, additional_metrics);
    __uint(max_entries, 1 << 24);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} additional_flow_metrics SEC(".maps");

//Ringbuf for Packet Payloads
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 21); // 256 bytes * 1000 events/sec * 5sec "eviction time"
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} packet_record SEC(".maps");

// DNS tracking flow based hashmap used to correlate query and responses
// to allow calculating latency in ebpf agent directly
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 20); // Will take around 64MB of space.
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
    __uint(max_entries, 1 << 20); // Will take around 64MB of space.
    __type(key, u64);
    __type(value, flow_id);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ipsec_ingress_map SEC(".maps");

// HashMap to store egress flowid to be able to retrieve them from kretprobe hook
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 20); // Will take around 64MB of space.
    __type(key, u64);
    __type(value, flow_id);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ipsec_egress_map SEC(".maps");

// Ringbuf for SSL data events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 27); // 16KB * 1000 events/sec * 5sec "eviction time" = ~128MB
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ssl_data_event_map SEC(".maps");

#endif //__MAPS_DEFINITION_H__
