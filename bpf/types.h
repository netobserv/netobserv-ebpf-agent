#ifndef __TYPES_H__
#define __TYPES_H__

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_UNSPEC -1
#define IP_MAX_LEN 16

#define DISCARD 1
#define SUBMIT 0

// Flags according to RFC 9293 & https://www.iana.org/assignments/ipfix/ipfix.xhtml
#define FIN_FLAG 0x01
#define SYN_FLAG 0x02
#define RST_FLAG 0x04
#define PSH_FLAG 0x08
#define ACK_FLAG 0x10
#define URG_FLAG 0x20
#define ECE_FLAG 0x40
#define CWR_FLAG 0x80
// Custom flags exported
#define SYN_ACK_FLAG 0x100
#define FIN_ACK_FLAG 0x200
#define RST_ACK_FLAG 0x400

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohs(x)        __builtin_bswap16(x)
#define bpf_htons(x)        __builtin_bswap16(x)
#define bpf_ntohl(x)        __builtin_bswap32(x)
#define bpf_htonl(x)        __builtin_bswap32(x)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_ntohs(x)        (x)
#define bpf_htons(x)        (x)
#define bpf_ntohl(x)        (x)
#define bpf_htonl(x)        (x)
#else
# error "Endianness detection needs to be set up for your compiler?!"
#endif

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

#define AF_INET  2
#define AF_INET6 10
#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_ARP 0x0806
#define IPPROTO_ICMPV6 58

// according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
typedef enum {
    INGRESS         = 0,
    EGRESS          = 1,
    MAX_DIRECTION   = 2,
} direction_t;

const u8 ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

typedef struct flow_metrics_t {
    u32 packets;
    u64 bytes;
    // Flow start and end times as monotomic timestamps in nanoseconds
    // as output from bpf_ktime_get_ns()
    u64 start_mono_time_ts;
    u64 end_mono_time_ts;
    // TCP Flags from https://www.ietf.org/rfc/rfc793.txt
    u16 flags;
    // The positive errno of a failed map insertion that caused a flow
    // to be sent via ringbuffer.
    // 0 otherwise
    // https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
    u8 errno;
    struct pkt_drops_t {
        u32 packets;
        u64 bytes;
        u16 latest_flags;
        u8 latest_state;
        u32 latest_drop_cause;
    } __attribute__((packed)) pkt_drops;
    struct dns_record_t {
        u16 id;
        u16 flags;
        u64 latency;
    } __attribute__((packed)) dns_record;
    u64 flow_rtt;
} __attribute__((packed)) flow_metrics;

// Force emitting struct pkt_drops into the ELF.
const struct pkt_drops_t *unused0 __attribute__((unused));

// Force emitting struct flow_metrics into the ELF.
const struct flow_metrics_t *unused1 __attribute__((unused));

// Attributes that uniquely identify a flow
typedef struct flow_id_t {
    u16 eth_protocol;
    u8 direction;
    // L2 data link layer
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    // L3 network layer
    // IPv4 addresses are encoded as IPv6 addresses with prefix ::ffff/96
    // as described in https://datatracker.ietf.org/doc/html/rfc4038#section-4.2
    u8 src_ip[IP_MAX_LEN];
    u8 dst_ip[IP_MAX_LEN];
    // L4 transport layer
    u16 src_port;
    u16 dst_port;
    u8 transport_protocol;
    // ICMP protocol
    u8  icmp_type;
    u8  icmp_code;
    // OS interface index
    u32 if_index;
} __attribute__((packed)) flow_id;

// Force emitting struct flow_id into the ELF.
const struct flow_id_t *unused2 __attribute__((unused));

// Standard 4 tuple, transport protocol and a sequence identifier.
// No need to emit this struct. It's used only in kernel space
typedef struct flow_seq_id_t {
    u16 src_port;
    u16 dst_port;
    u8 src_ip[IP_MAX_LEN];
    u8 dst_ip[IP_MAX_LEN];
    u32 seq_id;
    u8 transport_protocol;
    u32 if_index; // OS interface index
} __attribute__((packed)) flow_seq_id;

// Flow record is a tuple containing both flow identifier and metrics. It is used to send
// a complete flow via ring buffer when only when the accounting hashmap is full.
// Contents in this struct must match byte-by-byte with Go's pkc/flow/Record struct
typedef struct flow_record_t {
    flow_id id;
    flow_metrics metrics;
} __attribute__((packed)) flow_record;

// Force emitting struct flow_record into the ELF.
const struct flow_record_t *unused3 __attribute__((unused));

// Force emitting struct dns_record into the ELF.
const struct dns_record_t *unused4 __attribute__((unused));

// Internal structure: Packet info structure parsed around functions.
typedef struct pkt_info_t {
    flow_id *id;
    u64 current_ts; // ts recorded when pkt came.
    u16 flags;      // TCP specific
    void *l4_hdr;   // Stores the actual l4 header
    u64 rtt;        // rtt calculated from the flow if possible. else zero
} pkt_info;

// Structure for payload metadata
typedef struct payload_meta_t {
    u32 if_index;
    u32 pkt_len;
    u64 timestamp;  // timestamp when packet received by ebpf
} __attribute__((packed)) payload_meta;

// DNS Flow record used as key to correlate DNS query and response
typedef struct dns_flow_id_t {
    u16 src_port;
    u16 dst_port;
    u8 src_ip[IP_MAX_LEN];
    u8 dst_ip[IP_MAX_LEN];
    u16 id;
    u8 protocol;
} __attribute__((packed)) dns_flow_id;

#endif /* __TYPES_H__ */

