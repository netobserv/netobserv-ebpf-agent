/*
    Flows v2.

    Contains various hookpoints present in the netobserv-ebpf-agent.
    1. A Flow-metric generator using TC.
    2. A tcp_drops tracing program
    3. A dns tracking program.
*/
#include <vmlinux.h>
#include <bpf_helpers.h>

#include "configs.h"
#include "utils.h"
#include "flow_monitor.h"
#include "tcp_drops.h"
#include "dns_tracker.h"

SEC("tc_ingress")
int ingress_flow_parse(struct __sk_buff *skb) {
    return flow_monitor(skb, INGRESS);
}

SEC("tc_egress")
int egress_flow_parse(struct __sk_buff *skb) {
    return flow_monitor(skb, EGRESS);
}

SEC("tracepoint/skb/kfree_skb")
int kfree_skb(struct trace_event_raw_kfree_skb *args) {
    struct sk_buff skb;
    __builtin_memset(&skb, 0, sizeof(skb));

    bpf_probe_read(&skb, sizeof(struct sk_buff), args->skbaddr);
    struct sock *sk = skb.sk;
    enum skb_drop_reason reason = args->reason;

    // SKB_NOT_DROPPED_YET,
    // SKB_CONSUMED,
    // SKB_DROP_REASON_NOT_SPECIFIED,
    if (reason > SKB_DROP_REASON_NOT_SPECIFIED) {
        return trace_tcp_drop(args, sk, &skb, reason);
    }
    return 0;
}

SEC("tracepoint/net/net_dev_queue")
int trace_net_packets(struct trace_event_raw_net_dev_template *args) {
    struct sk_buff skb;

    __builtin_memset(&skb, 0, sizeof(skb));
    bpf_probe_read(&skb, sizeof(struct sk_buff), args->skbaddr);
    return trace_dns(&skb);
}

char _license[] SEC("license") = "GPL";

