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

// SSL plaintext capture maps (shared structure with flow BPF object).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 27); // 16KB * 1000 events/sec * 5sec "eviction time" = ~128MB
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ssl_data_event_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, u64);
    __type(value, struct ssl_read_active_t);
} ssl_read_active_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ssl_fd_key_t);
    __type(value, s32);
} ssl_fd_map SEC(".maps");

#endif // __PACKETS_MAPS_H__
