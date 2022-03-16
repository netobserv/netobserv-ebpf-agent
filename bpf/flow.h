#ifndef __FLOW_H__
#define __FLOW_H__

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define IP_MAX_LEN 16

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

// L2 data link layer
struct data_link {
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
};

// L3 network layer
struct network {
    // todo: add protocol
    // todo: support ipv6
    u32 src_ip;
    u32 dst_ip;
};

// L4 transport layer
struct transport {
    u16 src_port;
    u16 dst_port;
    u8 protocol;
};

// TODO: L5 session layer to bound flows to connections?

// contents in this struct must match byte-by-byte with Go's pkc/flow/Record struct
struct flow {
    u16 protocol;
    u8 direction;
    struct data_link data_link;
    struct network network;
    struct transport transport;
    u64 bytes;
} __attribute__((packed));

#endif
