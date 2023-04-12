#ifndef __TCP_SOCKET_H__
#define __TCP_SOCKET_H__

#define IP_MAX_LEN 16

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef struct ident_t {
	u32 pid;
	u64 cgroup_id;
} __attribute__((packed)) ident;
// Force emitting struct ident into the ELF.
const struct ident_t *unused1 __attribute__((unused));

typedef struct event_t {
	u8 saddr[IP_MAX_LEN];
	u8 daddr[IP_MAX_LEN];
	u64 ts_us;
	u64 span_us;
	u64 rx_bytes;
	u64 tx_bytes;
	u32 pid;
	u16 sport;
	u16 dport;
	u16 family;
	u64 cgroup_id;
} event;
// Force emitting struct event into the ELF.
const struct event_t *unused2 __attribute__((unused));

#endif
