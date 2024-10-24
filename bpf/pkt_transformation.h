/*
 * Packets Transformations tracker eBPF hooks.
 */

#ifndef __PKT_TRANSFORMATION_H__
#define __PKT_TRANSFORMATION_H__

#include "utils.h"

#define s6_addr in6_u.u6_addr8

static inline void parse_tuple(struct nf_conntrack_tuple *t, struct translated_flow_t *flow,
                               u16 zone_id, u16 family, bool invert) {
    if (invert) {
        flow->dport = bpf_ntohs(t->src.u.all);
        flow->sport = bpf_ntohs(t->dst.u.all);

        switch (family) {
        case AF_INET:
            __builtin_memcpy(flow->saddr, ip4in6, sizeof(ip4in6));
            __builtin_memcpy(flow->daddr, ip4in6, sizeof(ip4in6));
            bpf_probe_read(flow->daddr + sizeof(ip4in6), sizeof(u32), &t->src.u3.in.s_addr);
            bpf_probe_read(flow->saddr + sizeof(ip4in6), sizeof(u32), &t->dst.u3.in.s_addr);
            break;

        case AF_INET6:
            bpf_probe_read(flow->daddr, IP_MAX_LEN, &t->src.u3.in6.s6_addr);
            bpf_probe_read(flow->saddr, IP_MAX_LEN, &t->dst.u3.in6.s6_addr);
            break;
        }
    } else {
        flow->dport = bpf_ntohs(t->dst.u.all);
        flow->sport = bpf_ntohs(t->src.u.all);

        switch (family) {
        case AF_INET:
            __builtin_memcpy(flow->saddr, ip4in6, sizeof(ip4in6));
            __builtin_memcpy(flow->daddr, ip4in6, sizeof(ip4in6));
            bpf_probe_read(flow->daddr + sizeof(ip4in6), sizeof(u32), &t->dst.u3.in.s_addr);
            bpf_probe_read(flow->saddr + sizeof(ip4in6), sizeof(u32), &t->src.u3.in.s_addr);
            break;

        case AF_INET6:
            bpf_probe_read(flow->daddr, IP_MAX_LEN, &t->dst.u3.in6.s6_addr);
            bpf_probe_read(flow->saddr, IP_MAX_LEN, &t->src.u3.in6.s6_addr);
            break;
        }
    }
    flow->zone_id = zone_id;
}

static inline long translate_lookup_and_update_flow(flow_id *id, u16 flags,
                                                    struct nf_conntrack_tuple *orig_t,
                                                    struct nf_conntrack_tuple *reply_t, u64 len,
                                                    u16 zone_id, u16 family) {
    long ret = 0;
    u64 current_time = bpf_ktime_get_ns();
    struct translated_flow_t orig;

    parse_tuple(orig_t, &orig, zone_id, family, true);

    // update id with original flow info
    __builtin_memcpy(id->src_ip, orig.daddr, IP_MAX_LEN);
    __builtin_memcpy(id->dst_ip, orig.saddr, IP_MAX_LEN);
    id->src_port = orig.dport;
    id->dst_port = orig.sport;

    flow_metrics *aggregate_flow = bpf_map_lookup_elem(&aggregated_flows, id);
    if (aggregate_flow != NULL) {
        aggregate_flow->end_mono_time_ts = current_time;
        parse_tuple(reply_t, &aggregate_flow->translated_flow, zone_id, family, true);
        ret = bpf_map_update_elem(&aggregated_flows, id, aggregate_flow, BPF_EXIST);
        if (trace_messages && ret != 0) {
            bpf_printk("error packet translation updating flow %d\n", ret);
        }
    }

    return ret;
}

static inline int trace_nat_manip_pkt(struct nf_conn *ct, struct sk_buff *skb) {
    struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];
    u16 family = 0, flags = 0, zone_id = 0;
    u8 dscp = 0, protocol = 0;
    long ret = 0;
    u64 len = 0;
    flow_id id;

    if (!enable_pkt_transformation_tracking) {
        return 0;
    }
    __builtin_memset(&id, 0, sizeof(id));

    bpf_probe_read(&tuplehash, sizeof(tuplehash), &ct->tuplehash);

    bpf_probe_read(&zone_id, sizeof(zone_id), &ct->zone.id);
    bpf_probe_read(&zone_id, sizeof(zone_id), &ct->zone.id);

    struct nf_conntrack_tuple *orig_tuple = &tuplehash[IP_CT_DIR_ORIGINAL].tuple;
    struct nf_conntrack_tuple *reply_tuple = &tuplehash[IP_CT_DIR_REPLY].tuple;

    len = BPF_CORE_READ(skb, len);
    id.if_index = BPF_CORE_READ(skb, skb_iif);
    // read L2 info
    core_fill_in_l2(skb, &id, &family);

    // read L3 info
    core_fill_in_l3(skb, &id, family, &protocol, &dscp);

    // read L4 info
    switch (protocol) {
    case IPPROTO_TCP:
        core_fill_in_tcp(skb, &id, &flags);
        break;
    case IPPROTO_UDP:
        core_fill_in_udp(skb, &id);
        break;
    case IPPROTO_SCTP:
        core_fill_in_sctp(skb, &id);
        break;
    case IPPROTO_ICMP:
        core_fill_in_icmpv4(skb, &id);
        break;
    case IPPROTO_ICMPV6:
        core_fill_in_icmpv6(skb, &id);
        break;
    default:
        fill_in_others_protocol(&id, protocol);
    }

    bpf_probe_read(&zone_id, sizeof(zone_id), &ct->zone.id);
    ret =
        translate_lookup_and_update_flow(&id, flags, orig_tuple, reply_tuple, len, zone_id, family);

    return ret;
}

SEC("kprobe/nf_nat_manip_pkt")
int BPF_KPROBE(track_nat_manip_pkt) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct nf_conn *ct = (struct nf_conn *)PT_REGS_PARM2(ctx);

    return trace_nat_manip_pkt(ct, skb);
}

#endif /* __PKT_TRANSFORMATION_H__ */