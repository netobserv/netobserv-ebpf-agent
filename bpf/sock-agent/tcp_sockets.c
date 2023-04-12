/*
    This program can be hooked on to socket trace point hook to measure lifespan of tcp socket

    Logic:
        1) Store socket in a hash map.
        2) store process id and cgroup as identity in hashmap
        3) Upon TCP session completion measure elapsed time and generate perf events to user
           space containing socket information, received and transmitted bytes and
           lifespan of this socket.
*/
#include <vmlinux.h>
#include <bpf_core_read.h>
#include <bpf_helpers.h>

#include "tcp_socket.h"

#define MAX_ENTRIES	10240
#define AF_INET		2
#define AF_INET6	10

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, __u64);
} birth SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, struct ident_t);
} idents SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
	__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohs(x)		__builtin_bswap16(x)
#define bpf_htons(x)		__builtin_bswap16(x)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
	__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_ntohs(x)		(x)
#define bpf_htons(x)		(x)
#else
# error "Endianness detection needs to be set up for your compiler?!"
#endif

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *args)
{
	u64 ts, *start, delta_us, rx_bytes, tx_bytes, cgroup_id;
	struct ident_t ident = {}, *identp;
	u16 sport, dport, family;
	struct event_t event = {};
	struct tcp_sock *tp;
	struct sock *sk;
	u32 pid;

	if (BPF_CORE_READ(args, protocol) != IPPROTO_TCP)
		return 0;

	family = BPF_CORE_READ(args, family);

	sport = BPF_CORE_READ(args, sport);
	dport = BPF_CORE_READ(args, dport);

	sk = (struct sock *)BPF_CORE_READ(args, skaddr);
	if (BPF_CORE_READ(args, newstate) < TCP_FIN_WAIT1) {
		ts = bpf_ktime_get_ns();
		bpf_map_update_elem(&birth, &sk, &ts, BPF_ANY);
	}

	if (BPF_CORE_READ(args, newstate) == TCP_SYN_SENT || BPF_CORE_READ(args, newstate) == TCP_LAST_ACK) {
		pid = bpf_get_current_pid_tgid() >> 32;
		ident.pid = pid;
		ident.cgroup_id = bpf_get_current_cgroup_id();
		bpf_map_update_elem(&idents, &sk, &ident, BPF_ANY);
	}

	if (BPF_CORE_READ(args, newstate) != TCP_CLOSE)
		return 0;

	start = bpf_map_lookup_elem(&birth, &sk);
	if (!start) {
		bpf_map_delete_elem(&idents, &sk);
		return 0;
	}
	ts = bpf_ktime_get_ns();
	delta_us = (ts - *start) / 1000;

	identp = bpf_map_lookup_elem(&idents, &sk);

	if (identp) {
	    pid = identp->pid;
	    cgroup_id = identp->cgroup_id;
	} else {
	    pid = bpf_get_current_pid_tgid() >> 32;
	    cgroup_id = bpf_get_current_cgroup_id();
	}

	tp = (struct tcp_sock *)sk;
	rx_bytes = BPF_CORE_READ(tp, bytes_received);
	tx_bytes = BPF_CORE_READ(tp, bytes_acked);

	event.ts_us = ts / 1000;
	event.span_us = delta_us;
	event.rx_bytes = rx_bytes;
	event.tx_bytes = tx_bytes;
	event.pid = pid;
	event.cgroup_id = cgroup_id;
	event.sport = sport;
	event.dport = dport;
	event.family = family;
	if (family == AF_INET) {
		bpf_probe_read_kernel(&event.saddr, sizeof(args->saddr), BPF_CORE_READ(args, saddr));
		bpf_probe_read_kernel(&event.daddr, sizeof(args->daddr), BPF_CORE_READ(args, daddr));
	} else {	/*  AF_INET6 */
		bpf_probe_read_kernel(&event.saddr, sizeof(args->saddr_v6), BPF_CORE_READ(args, saddr_v6));
		bpf_probe_read_kernel(&event.daddr, sizeof(args->daddr_v6), BPF_CORE_READ(args, daddr_v6));
	}
	bpf_perf_event_output(args, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	bpf_map_delete_elem(&birth, &sk);
	bpf_map_delete_elem(&idents, &sk);
	return 0;
}

char _license[] SEC("license") = "GPL";
