#ifndef __COUNTERS_H__
#define __COUNTERS_H__

#include <bpf_core_read.h>
#include "maps_definition.h"

// Update global counter for hashmap update errors
static inline void increase_counter(u32 key) {
    u32 *error_counter_p = NULL;
    u32 initVal = 1;
    error_counter_p = bpf_map_lookup_elem(&global_counters, &key);
    if (!error_counter_p) {
        bpf_map_update_elem(&global_counters, &key, &initVal, BPF_ANY);
    } else {
        __sync_fetch_and_add(error_counter_p, 1);
    }
}

#endif // __COUNTERS_H__
