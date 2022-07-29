#ifndef __FLOW_H__
#define __FLOW_H__

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define IP_MAX_LEN 16

// TODO : Since, this cannot be programmed from userspace, its possible to
// build multiple executables with different sizes and control the executables
// based on configuration
#define INGRESS_MAX_ENTRIES 10000
#define EGRESS_MAX_ENTRIES  10000

// Bitmask of flags to be embedded in the 32-bit
// In Future, Other TCP Flags can be added
#define TCP_FIN_FLAG 0x1
#define TCP_RST_FLAG 0x10
#define COLLISION_FLAG 0x100

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef struct flow_aggregate_t {
    // key info for validation and direct eviction
    u16 eth_protocol;
    u8 direction;
    // L2 data link layer
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    // L3 network layer
    // IPv4 addresses are encoded as IPv6 addresses with prefix ::ffff/96
    // as described in https://datatracker.ietf.org/doc/html/rfc4038#section-4.2
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    // L4 transport layer
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    // Actual Metrics
    u32 packets;
    u64 bytes;
    u64 flow_start_ts;
    u64 last_pkt_ts;
    // Used to indicate certain info related to the flow
    u32 flags;
} __attribute__((packed)) flow_aggregate;


typedef struct flow_metrics_t {
    u32 packets;
    u64 bytes;
    u64 flow_start_ts;
    u64 last_pkt_ts;
    u32 flags;  // Could be used to indicate certain things
} __attribute__((packed)) flow_metrics;

typedef struct flow_id_t {
    u16 eth_protocol;
    u8 direction;
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
} __attribute__((packed)) flow_id;

// Flow record is the typical information sent from eBPF to userspace
// contents in this struct must match byte-by-byte with Go's pkc/flow/Record struct
typedef struct flow_record_t {
    flow_id id;
    flow_metrics metrics;
} __attribute__((packed)) flow_record;
#endif
