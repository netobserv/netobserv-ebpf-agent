#ifndef __FLOW_H__
#define __FLOW_H__

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define IP_MAX_LEN 16
// TODO : Explore if this can be programmed from go launcher
#define INGRESS_MAX_ENTRIES 1000
#define EGRESS_MAX_ENTRIES  1000


// Bitmask of flags to be embedded in the 32-bit
#define TCP_FIN_FLAG 0x1
#define TCP_RST_FLAG 0x10

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;


// L2 data link layer
struct data_link {
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
} __attribute__((packed));

// L3 network layer
struct v4ip {
    u32 src_ip;
    u32 dst_ip;
} __attribute__((packed));

struct v6ip {
    struct in6_addr src_ip6;
    struct in6_addr dst_ip6;
} __attribute__((packed));

struct network {
    struct v4ip v4ip;
    struct v6ip v6ip;
} __attribute__((packed));

// L4 transport layer
struct transport {
    u16 src_port;
    u16 dst_port;
    u8 protocol;
} __attribute__((packed));

// TODO: L5 session layer to bound flows to connections?

// contents in this struct must match byte-by-byte with Go's pkc/flow/Record struct
typedef struct flow_t {
    u16 protocol;
    u8 direction;
    struct data_link data_link;
    struct network network;
    struct transport transport;
} __attribute__((packed)) flow;


typedef struct flow_metrics_t {
	__u32 packets;
	__u64 bytes;
	__u64 flow_start_ts;
    __u64 last_pkt_ts;
	__u32 flags;  // Could be used to indicate certain things
} __attribute__((packed)) flow_metrics;

//TODO : Merge IPv4 and IPv6 as in
//       PR 32(https://github.com/netobserv/netobserv-ebpf-agent/pull/32/files)
typedef struct flow_id_v4_t {
    u16 eth_protocol;
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
} __attribute__((packed)) flow_id_v4;



typedef struct flow_record_t {
	flow flow_key;
	flow_metrics metrics;
} __attribute__((packed)) flow_record;
#endif
