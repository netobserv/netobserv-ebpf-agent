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
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, flow_id);
    __type(value, flow_metrics);
    __uint(max_entries, 1 << 24);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} aggregated_flows SEC(".maps");

// Common hashmap to keep track of all flow sequences.
// Key is flow_seq_id which is standard 4 tuple and a sequence id
//     sequence id is specific to the type of transport protocol
// Value is u64 which represents the occurrence timestamp of the packet.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 20);   // Will take around 64MB of space.
    __type(key, flow_seq_id);
    __type(value, u64);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} flow_sequences SEC(".maps");

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
    __uint(max_entries, 1 << 20);   // Will take around 64MB of space.
    __type(key, dns_flow_id);
    __type(value, u64);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} dns_flows SEC(".maps");

#endif //__MAPS_DEFINITION_H__
