/*
    A map iterator to delete stale entries.
 */

#ifndef __MAP_DELETE_ITER_H__
#define __MAP_DELETE_ITER_H__

#include <bpf_tracing.h>
#include "utils.h"
#include "maps_definition.h"

SEC("iter/bpf_map_elem")
int flows_hashmap_cleanup(struct bpf_iter__bpf_map_elem *ctx) {
    flow_id *key = ctx->key;
    flow_metrics *value = ctx->value;
    flow_id tmp_key;

    if (!key || !value) {
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    u64 last_seen_timestamp = value->last_seen_timestamp;
    u64 flow_expiration_ns = 1000ULL * 1000ULL * 1000ULL * 5ULL; // 5 seconds

    if (last_seen_timestamp != 0 && last_seen_timestamp + flow_expiration_ns < now) {
        // Flow is expired remove it from hashmap.
        __builtin_memcpy(&tmp_key, key, sizeof(flow_id));
        int ret = bpf_map_delete_elem(&aggregated_flows, &tmp_key);
        if (ret != 0 && trace_messages) {
            bpf_printk("error deleting flows map entry %d\n", ret);
        }
    }
    return 0;
}

#endif /* __MAP_DELETE_ITER_H__ */