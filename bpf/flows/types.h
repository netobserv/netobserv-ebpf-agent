#ifndef __TYPES_H__
#define __TYPES_H__

#include "../common/types.h"

#define ETH_ALEN 6
#define MAX_EVENT_MD 8
#define MAX_NETWORK_EVENTS 4
#define MAX_OBSERVED_INTERFACES 6
#define DNS_NAME_MAX_LEN 32

// Per-CPU temporary storage for DNS name (avoids stack limit)
typedef struct dns_name_buffer_t {
    char name[DNS_NAME_MAX_LEN];
} dns_name_buffer;

typedef struct flow_metrics_t {
    // Flow start and end times as monotomic timestamps in nanoseconds
    // as output from bpf_ktime_get_ns()
    u64 start_mono_time_ts;
    u64 end_mono_time_ts;
    u64 bytes;
    u32 packets;
    u16 eth_protocol;
    // TCP Flags from https://www.ietf.org/rfc/rfc793.txt
    u16 flags;
    // L2 data link layer
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    // OS interface index
    u32 if_index_first_seen;
    struct bpf_spin_lock lock;
    u32 sampling;
    u8 direction_first_seen;
    // The positive errno of a failed map insertion that caused a flow
    // to be sent via ringbuffer.
    // 0 otherwise
    // https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
    u8 errno;
    u8 dscp;
    u8 nb_observed_intf;
    u8 observed_direction[MAX_OBSERVED_INTERFACES];
    u32 observed_intf[MAX_OBSERVED_INTERFACES];
    u16 ssl_version;
    u16 tls_cipher_suite;
    u16 tls_key_share;
    u8 tls_types;
    u8 misc_flags;
} flow_metrics;

// Force emitting enums/structs into the ELF
const static struct flow_metrics_t *unused_flowmet __attribute__((unused));

typedef struct dns_metrics_t {
    u64 start_mono_time_ts;
    u64 end_mono_time_ts;
    u64 latency;
    u16 id;
    u16 flags;
    u16 eth_protocol;
    u8 errno;
    char name[DNS_NAME_MAX_LEN];
} dns_metrics;

typedef struct pkt_drop_metrics_t {
    u64 start_mono_time_ts;
    u64 end_mono_time_ts;
    u16 bytes;
    u16 packets;
    u32 latest_drop_cause;
    u16 latest_flags;
    u16 eth_protocol;
    u8 latest_state;
} pkt_drop_metrics;

typedef struct network_events_metrics_t {
    u64 start_mono_time_ts;
    u64 end_mono_time_ts;
    u8 network_events[MAX_NETWORK_EVENTS][MAX_EVENT_MD];
    u16 bytes[MAX_NETWORK_EVENTS];
    u16 packets[MAX_NETWORK_EVENTS];
    u16 eth_protocol;
    u8 network_events_idx;
} network_events_metrics;

typedef struct xlat_metrics_t {
    u64 start_mono_time_ts;
    u64 end_mono_time_ts;
    u8 saddr[IP_MAX_LEN];
    u8 daddr[IP_MAX_LEN];
    u16 sport;
    u16 dport;
    u16 zone_id;
    u16 eth_protocol;
} xlat_metrics;

typedef struct additional_metrics_t {
    u64 start_mono_time_ts;
    u64 end_mono_time_ts;
    u64 flow_rtt;
    int ipsec_encrypted_ret;
    u16 eth_protocol;
    bool ipsec_encrypted;
} additional_metrics;

// // Force emitting enums/structs into the ELF
const static struct dns_metrics_t *unused_dns __attribute__((unused));
const static struct pkt_drop_metrics_t *unused_drop __attribute__((unused));
const static struct network_events_metrics_t *unused_netev __attribute__((unused));
const static struct xlat_metrics_t *unused_xlat __attribute__((unused));
const static struct additional_metrics_t *unused_addmet __attribute__((unused));

// Flow record is a tuple containing both flow identifier and metrics. It is used to send
// a complete flow via ring buffer when only when the accounting hashmap is full.
// Contents in this struct must match byte-by-byte with Go's pkc/flow/Record struct
typedef struct flow_record_t {
    flow_id id;
    flow_metrics metrics;
} flow_record;

// Force emitting enums/structs into the ELF
const struct flow_record_t *unused_flowrec __attribute__((unused));

// Internal structure: TLS info.
typedef struct tls_info_t {
    u16 hello_version;
    u16 cipher_suite;
    u16 key_share;
    u8 type;
} tls_info;

// DNS Flow record used as key to correlate DNS query and response
typedef struct dns_flow_id_t {
    u16 src_port;
    u16 dst_port;
    u8 src_ip[IP_MAX_LEN];
    u8 dst_ip[IP_MAX_LEN];
    u16 id;
    u8 protocol;
} dns_flow_id;

// Enum to define global counters keys and share it with userspace
typedef enum global_counters_key_t {
    HASHMAP_FAIL_UPDATE_FLOW,
    HASHMAP_FAIL_CREATE_FLOW,
    HASHMAP_FAIL_UPDATE_DNS,
    FILTER_REJECT,
    FILTER_ACCEPT,
    FILTER_NOMATCH,
    NETWORK_EVENTS_ERR,
    NETWORK_EVENTS_ERR_GROUPID_MISMATCH,
    NETWORK_EVENTS_ERR_UPDATE_MAP_FLOWS,
    NETWORK_EVENTS_GOOD,
    NETWORK_EVENTS_OVERFLOW,
    NETWORK_EVENTS_COOKIE_TOO_BIG,
    OBSERVED_INTF_MISSED,
    MAX_COUNTERS,
} global_counters_key;

// Force emitting enums/structs into the ELF
const enum global_counters_key_t *unused_counters __attribute__((unused));

// QUIC flow metrics
typedef struct quic_metrics_t {
    u64 start_mono_time_ts;
    u64 end_mono_time_ts;
    u32 version;       // QUIC version (from long header), 0 if unknown
    u16 eth_protocol;  // ETH_P_IP or ETH_P_IPV6
    u8 seen_long_hdr;  // Saw handshake packets (long header)
    u8 seen_short_hdr; // Saw established packets (short header)
} quic_metrics;

// Force emitting struct into the ELF
const static struct quic_metrics_t *unused_quic __attribute__((unused));

typedef enum quic_config_t {
    QUIC_CONFIG_DISABLED,
    QUIC_CONFIG_ENABLED,
    QUIC_CONFIG_ANY_UDP_PORT,
} quic_config;

// Force emitting enums/structs into the ELF/BTF (for bpf2go -type quic_config_t)
const static enum quic_config_t *unused_quiccfg __attribute__((unused, used));

#endif /* __TYPES_H__ */
