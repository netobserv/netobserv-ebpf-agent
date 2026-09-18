#ifndef __ENDPOINT_H__
#define __ENDPOINT_H__

#include "types.h"
#include "maps_definition.h"
#include "common/packet_utils.h"

/*
 * Intern one 16-byte IPv4-mapped / IPv6 address to a stable u32 ID.
 * intern_flow_endpoints() does this for src and dst after CIDR filtering.
 *
 *   packet_addrs (raw IPs)              flow_id (map key)
 *   +------------------+                +------------------+
 *   | src_ip [16]      | --intern-->    | src_id  u32      |
 *   | dst_ip [16]      | --intern-->    | dst_id  u32      |
 *   +------------------+                | ports / proto    |
 *                                       +------------------+
 *                                                |
 *   endpoint_ids (IP -> ID)                      |  endpoint_ips (ID -> IP)
 *   +----------------------+                     |  +----------------------+
 *   | ::ffff:10.0.0.1 -> 5 |  hot-path lookup    +->| 5 -> ::ffff:10.0.0.1 |
 *   | 2001:db8::1     -> 6 |                     |  | 6 -> 2001:db8::1     |
 *   +----------------------+                     |  +----------------------+
 *                                                v
 *                                           export resolve
 *
 *                    intern_endpoint(ip)
 *                           |
 *                           v
 *                 lookup endpoint_ids[ip]
 *                      /            \
 *                   hit              miss
 *                    |                |
 *              return existing        v
 *                              bump this CPU's seq
 *                              id = (cpu+1)<<20 | seq
 *                                    |
 *                                    v
 *                     update endpoint_ids[ip] = id
 *                            (BPF_NOEXIST)
 *                           /            \
 *                      success            -EEXIST (other CPU won)
 *                         |                      |
 *           update endpoint_ips[id] = ip         re-lookup
 *           return id                            endpoint_ids[ip]
 *                                                   /        \
 *                                                hit          miss
 *                                                 |            |
 *                                           return winner    fail (0)
 *
 * Packed ID (cpu+1 so CPU 0 never yields ID 0):
 *
 *   |<-- 12 bits cpu+1 -->|<------- 20 bits seq ------->|
 *  31                   20 19                           0
 *   CPU 0 first  -> 0x00100001
 *   CPU 3 first  -> 0x00400001
 *
 * Same-IP race: both CPUs allocate different packed IDs; only one NOEXIST
 * insert wins. Loser re-looks up and returns the winner. Unused ID is skipped.
 *
 *   CPU 0                         CPU 1
 *     |                             |
 *     +-- miss 10.0.0.1 ------------+-- miss 10.0.0.1
 *     |  alloc 0x00100001           |  alloc 0x00200001
 *     +-- NOEXIST wins              +-- NOEXIST loses
 *     |  endpoint_ips[0x00100001]   |  re-lookup -> 0x00100001
 *
 * Returns 0 on missing counter, seq overflow, map full, or lost race
 * with no winner. Callers drop the packet from flow accounting.
 */
static __always_inline u32 intern_endpoint(const u8 ip[IP_MAX_LEN]) {
    endpoint_addr key;
    __builtin_memset(&key, 0, sizeof(key));
    __builtin_memcpy(key.ip, ip, IP_MAX_LEN);

    u32 *existing = bpf_map_lookup_elem(&endpoint_ids, &key);
    if (existing && *existing != 0) {
        return *existing;
    }

    u32 zero = 0;
    endpoint_id_state *state = bpf_map_lookup_elem(&endpoint_id_counter, &zero);
    if (!state) {
        increase_counter(ENDPOINT_INTERN_FAIL);
        return 0;
    }

    u32 seq = state->next + 1;
    if (seq == 0 || seq > ENDPOINT_ID_SEQ_MASK) {
        increase_counter(ENDPOINT_INTERN_FAIL);
        return 0;
    }
    state->next = seq;
    // Bound cpu so the packed ID stays within 32 bits for the verifier.
    u32 cpu = bpf_get_smp_processor_id() & 0xfff;
    u32 new_id = ((cpu + 1) << ENDPOINT_ID_SEQ_BITS) | seq;

    long ret = bpf_map_update_elem(&endpoint_ids, &key, &new_id, BPF_NOEXIST);
    if (ret == 0) {
        bpf_map_update_elem(&endpoint_ips, &new_id, &key, BPF_NOEXIST);
        return new_id;
    }

    // Race: another CPU interned the same address. Re-lookup.
    existing = bpf_map_lookup_elem(&endpoint_ids, &key);
    if (existing && *existing != 0) {
        return *existing;
    }

    increase_counter(ENDPOINT_INTERN_FAIL);
    return 0;
}

// Fill flow_id src/dst IDs from packet-boundary addresses.
// Returns false if either intern failed (ID 0).
static __always_inline bool intern_flow_endpoints(flow_id *id, const packet_addrs *addrs) {
    id->src_id = intern_endpoint(addrs->src_ip);
    id->dst_id = intern_endpoint(addrs->dst_ip);
    return id->src_id != 0 && id->dst_id != 0;
}

#endif // __ENDPOINT_H__
