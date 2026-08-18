#ifndef __PACKETS_MAPS_H__
#define __PACKETS_MAPS_H__

#include <vmlinux.h>
#include "../types.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 21);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} packet_record SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct filter_key_t);
    __type(value, struct filter_value_t);
    __uint(max_entries, MAX_FILTER_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} filter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct filter_key_t);
    __type(value, u8);
    __uint(max_entries, MAX_FILTER_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} peer_filter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, MAX_COUNTERS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} global_counters SEC(".maps");

#endif // __PACKETS_MAPS_H__
