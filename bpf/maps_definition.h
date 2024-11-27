#ifndef __MAPS_DEFINITION_H__
#define __MAPS_DEFINITION_H__

#include <vmlinux.h>

// Common Ringbuffer as a conduit for ingress/egress flows to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} direct_flows SEC(".maps");

// Key: the flow identifier. Value: the flow metrics for that identifier.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, flow_id);
    __type(value, flow_metrics);
    __uint(max_entries, 1 << 24);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} aggregated_flows SEC(".maps");

// Key: the flow identifier. Value: extra metrics for that identifier.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, flow_id);
    __type(value, additional_metrics);
    __uint(max_entries, 1 << 24);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} additional_flow_metrics SEC(".maps");

//PerfEvent Array for Packet Payloads
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 256);
} packet_record SEC(".maps");

// DNS tracking flow based hashmap used to correlate query and responses
// to allow calculating latency in ebpf agent directly
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 20); // Will take around 64MB of space.
    __type(key, dns_flow_id);
    __type(value, u64);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} dns_flows SEC(".maps");

// Global counter for hashmap update errors
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, MAX_COUNTERS);
} global_counters SEC(".maps");

// LPM trie map used to filter traffic by IP address CIDR and direction
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct filter_key_t);
    __type(value, struct filter_value_t);
    __uint(max_entries, MAX_FILTER_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} filter_map SEC(".maps");

#endif //__MAPS_DEFINITION_H__
