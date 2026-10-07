#ifndef __TYPES_H__
#define __TYPES_H__

#include "../common/types.h"

#define MAX_PAYLOAD_SIZE 256
#define MAX_DATA_SIZE_OPENSSL 1024 * 16

// Structure for payload metadata
typedef struct payload_meta_t {
    u32 if_index;
    u32 pkt_len;
    u64 timestamp; // timestamp when packet received by ebpf
    u8 payload[MAX_PAYLOAD_SIZE];
} payload_meta;

// Enum to define global counters keys and share it with userspace
typedef enum global_counters_key_t {
    FILTER_REJECT,
    FILTER_ACCEPT,
    FILTER_NOMATCH,
    MAX_COUNTERS,
} global_counters_key;

// Force emitting enums/structs into the ELF
const enum global_counters_key_t *unused_counters __attribute__((unused));
// SSL data event
struct ssl_data_event_t {
    u64 timestamp_ns;
    u64 pid_tgid;
    s32 data_len;
    u8 ssl_type;
    u8 direction;   // 0=write/outbound, 1=read/inbound
    u8 tls_source;  // 0=openssl (1=gotls, 2=ktls reserved)
    u8 tuple_valid; // 1 when the local/remote tuple was captured from the socket
    u16 src_port;
    u16 dst_port;
    u8 src_addr[IP_MAX_LEN];
    u8 dst_addr[IP_MAX_LEN];
    s32 socket_fd;     // host fd when known, else -1
    u64 conn_user_ptr; // OpenSSL SSL* or Go *tls.Conn user pointer
    char data[MAX_DATA_SIZE_OPENSSL];
} ssl_data_event;

// Force emitting enums/structs into the ELF
const static struct ssl_data_event_t *unused_ssl_data_event __attribute__((unused));

struct ssl_read_active_t {
    u8 ssl_type;
    u8 _pad[7];
    u64 buf_user;
    u64 conn_user_ptr;
};

const static struct ssl_read_active_t *unused_ssl_read_active __attribute__((unused));

// OpenSSL SSL* -> fd map key: isolate entries across processes that may share SSL* values.
struct ssl_fd_key_t {
    u64 ssl_ptr;
    u32 tgid;
    u32 _pad;
};

const static struct ssl_fd_key_t *unused_ssl_fd_key __attribute__((unused));
struct ssl_fd_pending_t {
    struct ssl_fd_key_t key;
    s32 fd;
};

#endif /* __TYPES_H__ */
