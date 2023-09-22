/*
    TCP retransmit tracker using trace points.
*/

#ifndef __TCP_RETRANS_H__
#define __TCP_RETRANS_H__

#include "utils.h"
#include <bpf_core_read.h>

static inline int update_tcp_retrans_flow(flow_id *id, int len, u8 flags) {
    long ret = 0;
    flow_metrics *aggregate_flow = bpf_map_lookup_elem(&aggregated_flows, id);
    if (aggregate_flow != NULL) {
        u64 current_time = bpf_ktime_get_ns();
        aggregate_flow->end_mono_time_ts = current_time;
        if (aggregate_flow->start_mono_time_ts == 0) {
            aggregate_flow->start_mono_time_ts = current_time;
        }
        aggregate_flow->packets++;
        aggregate_flow->bytes += len;
        aggregate_flow->flags |= flags;
        aggregate_flow->tcp_retrans++;
        ret = bpf_map_update_elem(&aggregated_flows, id, aggregate_flow, BPF_ANY);
    } else {
        flow_metrics new_flow;
        __builtin_memset(&new_flow, 0, sizeof(new_flow));
        u64 current_time = bpf_ktime_get_ns();
        new_flow.start_mono_time_ts = current_time;
        new_flow.end_mono_time_ts = current_time;
        new_flow.packets = 1;
        new_flow.bytes = len;
        new_flow.flags = flags;
        new_flow.tcp_retrans = 1;
        ret = bpf_map_update_elem(&aggregated_flows, id, &new_flow, BPF_ANY);
    }
    if (trace_messages && ret != 0) {
        bpf_printk("error tcp_retrans updating flow %d\n", ret);
    }
    return ret;
}

static inline int trace_tcp_retrans(struct trace_event_raw_tcp_event_sk_skb *args) {
    u16 sport = 0, dport = 0, family = 0;
    const struct sock *sk = args->skaddr;
    struct tcp_skb_cb *tcb;
    struct sk_buff skb;
    u8 flags = 0;
    flow_id id;

    if (sk == NULL)
        return 0;

    if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_TCP)
        return 0;

    __builtin_memset(&skb, 0, sizeof(skb));
    bpf_probe_read(&skb, sizeof(struct sk_buff), args->skbaddr);

    __builtin_memset(&id, 0, sizeof(id));
    id.transport_protocol = IPPROTO_TCP;
    id.if_index = skb.skb_iif;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    switch (family) {
    case AF_INET:
        __builtin_memcpy(&id.src_ip, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(&id.dst_ip, ip4in6, sizeof(ip4in6));
        bpf_probe_read(id.src_ip + sizeof(ip4in6), sizeof(args->saddr), args->saddr);
        bpf_probe_read(id.dst_ip + sizeof(ip4in6), sizeof(args->daddr), args->daddr);
        id.eth_protocol =  ETH_P_IP;
        break;

    case AF_INET6:
        bpf_probe_read(id.src_ip, sizeof(args->saddr_v6), args->saddr_v6);
        bpf_probe_read(id.dst_ip, sizeof(args->daddr_v6), args->daddr_v6);
        id.eth_protocol =  ETH_P_IPV6;
        break;

    default:
        // drop
        return 0;
    }

    // The tcp_retransmit_skb tracepoint is fired with a skb that does not
    // contain the TCP header because the TCP header is built on a cloned skb
    // we don't have access to.
    // skb->transport_header is not set: skb_transport_header_was_set() == false.
    // Instead, we have to read the TCP flags from the TCP control buffer.
    tcb = (struct tcp_skb_cb *)&(skb.cb[0]);
    bpf_probe_read_kernel(&flags, sizeof(flags), &tcb->tcp_flags);

    bpf_probe_read(&dport, sizeof(args->dport), &args->dport);
    id.dst_port = bpf_ntohs(dport);

    bpf_probe_read(&sport, sizeof(args->sport), &args->sport);
    id.src_port = bpf_ntohs(sport);

    id.direction = EGRESS;
    return update_tcp_retrans_flow(&id, skb.len, flags);
}

SEC("tracepoint/tcp/tcp_retransmit_skb")
int trace_tcp_retrans_packets(struct trace_event_raw_tcp_event_sk_skb *args) {
    return trace_tcp_retrans(args);
}

#endif // __TCP_RETRANS_H__
