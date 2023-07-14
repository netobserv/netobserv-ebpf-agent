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

// Common hashmap to keep track of all flow sequences.
// LRU hashmap is used because if some syn packet is received but ack is not
// then the hashmap entry will need to be evicted
// Key is flow_seq_id which is standard 4 tuple and a sequence id
//     sequence id is specific to the type of transport protocol
// Value is u64 which represents the occurrence timestamp of the packet.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 20);   // Will take around 64MB of space.
    __type(key, flow_seq_id);
    __type(value, u64);
} flow_sequences SEC(".maps");

//PerfEvent Array for Payloads
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, MAX_CPUS);
	__type(key, __u32);
	__type(value, __u32);
} packet_record SEC(".maps");

#endif //__MAPS_DEFINITION_H__
