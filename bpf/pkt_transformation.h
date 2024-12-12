/*
 * Packets Transformations tracker eBPF hooks.
 */

#ifndef __PKT_TRANSFORMATION_H__
#define __PKT_TRANSFORMATION_H__

#include "utils.h"

#define s6_addr in6_u.u6_addr8

static inline void dump_xlated_flow(struct translated_flow_t *flow) {
    BPF_PRINTK("zone_id %d sport %d dport %d icmpId %d\n", flow->zone_id, flow->sport, flow->dport,
               flow->icmp_id);
    int i;
    for (i = 0; i < IP_MAX_LEN; i += 4) {
        BPF_PRINTK("scrIP[%d]:%d.%d.%d.%d\n", i, flow->saddr[0 + i], flow->saddr[1 + i],
                   flow->saddr[2 + i], flow->saddr[3 + i]);
    }
    for (i = 0; i < IP_MAX_LEN; i += 4) {
        BPF_PRINTK("dstIP[%d]:%d.%d.%d.%d\n", i, flow->daddr[0 + i], flow->daddr[1 + i],
                   flow->daddr[2 + i], flow->daddr[3 + i]);
    }
}

static inline void parse_tuple(struct nf_conntrack_tuple *t, struct translated_flow_t *flow,
                               u16 zone_id, u16 family, bool invert) {
    __builtin_memset(flow, 0, sizeof(*flow));
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
    flow->icmp_id = t->src.u.icmp.id;
    flow->zone_id = zone_id;
    dump_xlated_flow(flow);
}

static inline long translate_lookup_and_update_flow(flow_id *id, u16 flags,
                                                    struct nf_conntrack_tuple *orig_t,
                                                    struct nf_conntrack_tuple *reply_t, u16 zone_id,
                                                    u16 family) {
    long ret = 0;
    struct translated_flow_t orig;

    parse_tuple(orig_t, &orig, zone_id, family, false);

    // update id with original flow info
    __builtin_memcpy(id->src_ip, orig.saddr, IP_MAX_LEN);
    __builtin_memcpy(id->dst_ip, orig.daddr, IP_MAX_LEN);
    id->src_port = orig.sport;
    id->dst_port = orig.dport;

    additional_metrics *extra_metrics = bpf_map_lookup_elem(&additional_flow_metrics, id);
    if (extra_metrics != NULL) {
        parse_tuple(reply_t, &extra_metrics->translated_flow, zone_id, family, true);
        return ret;
    }

    // there is no matching flows so lets create new one and add the xlation
    additional_metrics new_extra_metrics = {};
    parse_tuple(reply_t, &new_extra_metrics.translated_flow, zone_id, family, true);
    ret = bpf_map_update_elem(&additional_flow_metrics, id, &new_extra_metrics, BPF_NOEXIST);
    if (ret != 0) {
        if (trace_messages && ret != -EEXIST) {
            bpf_printk("error packet translation creating new flow %d\n", ret);
        }
        if (ret == -EEXIST) {
            additional_metrics *extra_metrics = bpf_map_lookup_elem(&additional_flow_metrics, id);
            if (extra_metrics != NULL) {
                parse_tuple(reply_t, &extra_metrics->translated_flow, zone_id, family, true);
                return 0;
            }
        }
    }

    return ret;
}

static inline int trace_nat_manip_pkt(struct nf_conn *ct, struct sk_buff *skb) {
    struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];
    u16 family = 0, flags = 0, zone_id = 0, eth_protocol = 0;
    ;
    u8 dscp = 0, protocol = 0;
    long ret = 0;
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

    // read L2 info
    core_fill_in_l2(skb, &eth_protocol, &family);

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

    // check if this packet need to be filtered if filtering feature is enabled
    bool skip = check_and_do_flow_filtering(&id, flags, 0, eth_protocol);
    if (skip) {
        return 0;
    }

    BPF_PRINTK("Xlat: protocol %d flags 0x%x family %d dscp %d\n", protocol, flags, family, dscp);

    bpf_probe_read(&zone_id, sizeof(zone_id), &ct->zone.id);
    ret = translate_lookup_and_update_flow(&id, flags, orig_tuple, reply_tuple, zone_id, family);

    return ret;
}

SEC("kprobe/nf_nat_manip_pkt")
int BPF_KPROBE(track_nat_manip_pkt) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct nf_conn *ct = (struct nf_conn *)PT_REGS_PARM2(ctx);

    return trace_nat_manip_pkt(ct, skb);
}

#endif /* __PKT_TRANSFORMATION_H__ */