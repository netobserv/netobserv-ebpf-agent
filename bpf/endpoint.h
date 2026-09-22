#ifndef __ENDPOINT_H__
#define __ENDPOINT_H__

#include "types.h"
#include "maps_definition.h"
#include "common/packet_utils.h"

/*
 * Map a 16-byte IPv4-mapped / IPv6 address to a stable u32 ID.
 * ID 0 is reserved (lookup/intern failure).
 *
 * TC (intern_flow_endpoints): lookup or assign the next global ID.
 * Tracing hooks only look up (lookup_flow_endpoints). An IP that TC
 * has not interned yet is skipped.
 *
 *   packet_addrs          flow_id              endpoint_ids / endpoint_ips
 *   src_ip[16] --intern--> src_id u32          IP -> ID   (hot path)
 *   dst_ip[16] --intern--> dst_id u32          ID -> IP   (export / IPsec)
 *
 *                    intern_endpoint (TC only)
 *                           |
 *                 lookup endpoint_ids[ip]
 *                      /            \
 *                   hit              miss
 *                    |                |
 *              return existing   XADD next; id = *next
 *                                    |
 *                     reserve endpoint_ips[id] = ip (NOEXIST)
 *                           /            \
 *                      success            taken: retry
 *           endpoint_ids[ip] = id (NOEXIST)
 *                           /            \
 *                      success            -EEXIST
 *                    return id            drop reserved id; re-lookup winner
 */
static __always_inline void endpoint_key_from_ip(endpoint_addr *key, const u8 ip[IP_MAX_LEN]) {
    __builtin_memset(key, 0, sizeof(*key));
    __builtin_memcpy(key->ip, ip, IP_MAX_LEN);
}

static __always_inline u32 lookup_endpoint(const u8 ip[IP_MAX_LEN]) {
    endpoint_addr key;
    endpoint_key_from_ip(&key, ip);
    u32 *existing = bpf_map_lookup_elem(&endpoint_ids, &key);
    if (existing && *existing != 0) {
        return *existing;
    }
    return 0;
}

// Assign an ID if missing. Call only from TC/TCX/netkit.
static __always_inline u32 intern_endpoint(const u8 ip[IP_MAX_LEN]) {
    endpoint_addr key;
    endpoint_key_from_ip(&key, ip);

    u32 *existing = bpf_map_lookup_elem(&endpoint_ids, &key);
    if (existing && *existing != 0) {
        return *existing;
    }

    u32 zero = 0;
    u32 *next = bpf_map_lookup_elem(&endpoint_id_counter, &zero);
    if (!next) {
        increase_counter(ENDPOINT_INTERN_FAIL);
        return 0;
    }

    // BPF XADD on map values cannot return the new value (kernel < 5.12).
    // Increment, then read. If two CPUs observe the same id, endpoint_ips
    // NOEXIST fails and we retry.
    for (int i = 0; i < 4; i++) {
        __sync_fetch_and_add(next, 1);
        u32 new_id = *next;
        if (new_id == 0) {
            increase_counter(ENDPOINT_INTERN_FAIL);
            return 0;
        }

        if (bpf_map_update_elem(&endpoint_ips, &new_id, &key, BPF_NOEXIST) != 0) {
            continue;
        }

        long ret = bpf_map_update_elem(&endpoint_ids, &key, &new_id, BPF_NOEXIST);
        if (ret == 0) {
            return new_id;
        }

        bpf_map_delete_elem(&endpoint_ips, &new_id);
        existing = bpf_map_lookup_elem(&endpoint_ids, &key);
        if (existing && *existing != 0) {
            return *existing;
        }
        increase_counter(ENDPOINT_INTERN_FAIL);
        return 0;
    }

    increase_counter(ENDPOINT_INTERN_FAIL);
    return 0;
}

static __always_inline bool lookup_flow_endpoints(flow_id *id, const packet_addrs *addrs) {
    id->src_id = lookup_endpoint(addrs->src_ip);
    id->dst_id = lookup_endpoint(addrs->dst_ip);
    return id->src_id != 0 && id->dst_id != 0;
}

static __always_inline bool intern_flow_endpoints(flow_id *id, const packet_addrs *addrs) {
    id->src_id = intern_endpoint(addrs->src_ip);
    id->dst_id = intern_endpoint(addrs->dst_ip);
    return id->src_id != 0 && id->dst_id != 0;
}

#endif // __ENDPOINT_H__
