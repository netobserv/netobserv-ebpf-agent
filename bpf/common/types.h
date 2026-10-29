#ifndef __COMMON_TYPES_H__
#define __COMMON_TYPES_H__

#define IP_MAX_LEN 16

// Flags according to RFC 9293 & https://www.iana.org/assignments/ipfix/ipfix.xhtml
typedef enum tcp_flags_t {
    FIN_FLAG = 0x01,
    SYN_FLAG = 0x02,
    RST_FLAG = 0x04,
    PSH_FLAG = 0x08,
    ACK_FLAG = 0x10,
    URG_FLAG = 0x20,
    ECE_FLAG = 0x40,
    CWR_FLAG = 0x80,
    // Custom flags exported
    SYN_ACK_FLAG = 0x100,
    FIN_ACK_FLAG = 0x200,
    RST_ACK_FLAG = 0x400,
} tcp_flags;

// Force emitting enums/structs into the ELF
const static enum tcp_flags_t *unused_tcpflags __attribute__((unused));

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

// according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
typedef enum direction_t {
    INGRESS,
    EGRESS,
    MAX_DIRECTION = 2,
} direction;

// Force emitting enums/structs into the ELF
const static enum direction_t *unused_direction __attribute__((unused));

// Attributes that uniquely identify a flow
typedef struct flow_id_t {
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
    u8 icmp_type;
    u8 icmp_code;
} flow_id;

// Force emitting enums/structs into the ELF
const static struct flow_id_t *unused_flowid __attribute__((unused));

// Internal structure: Packet info structure passed around functions.
typedef struct pkt_info_t {
    flow_id *id;
    u64 current_ts; // ts recorded when pkt came.
    u16 flags;      // TCP specific
    void *l4_hdr;   // Stores the actual l4 header
    u8 dscp;        // IPv4/6 DSCP value
    u16 dns_id;
    u16 dns_flags;
    u64 dns_latency;
    char *dns_name;
} pkt_info;

// filter key used as key to LPM map to filter out flows that are not interesting for the user
struct filter_key_t {
    u32 prefix_len;
    u8 ip_data[IP_MAX_LEN];
} filter_key;

// Force emitting enums/structs into the ELF
const static struct filter_key_t *unused_fkey __attribute__((unused));

// Enum to define filter action
typedef enum filter_action_t {
    ACCEPT,
    REJECT,
    MAX_FILTER_ACTIONS,
} filter_action;

// Force emitting enums/structs into the ELF
const static enum filter_action_t *unused_fact __attribute__((unused));

// filter value used as value from LPM map lookup to filter out flows that are not interesting for the user
struct filter_value_t {
    u8 protocol;
    u16 dstPortStart;
    u16 dstPortEnd;
    u16 dstPort1;
    u16 dstPort2;
    u16 srcPortStart;
    u16 srcPortEnd;
    u16 srcPort1;
    u16 srcPort2;
    u16 portStart;
    u16 portEnd;
    u16 port1;
    u16 port2;
    u8 icmpType;
    u8 icmpCode;
    direction direction;
    filter_action action;
    tcp_flags tcpFlags;
    u8 filter_drops;
    u32 sample;
    u8 do_peerCIDR_lookup;
} filter_value;

// Force emitting enums/structs into the ELF
const static struct filter_value_t *unused_fval __attribute__((unused));

#endif /* __COMMON_TYPES_H__ */
