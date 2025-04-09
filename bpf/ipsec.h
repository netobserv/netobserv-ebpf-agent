/*
 * IPsec monitoring kretprobe eBPF hook.
 */

#ifndef __IPSEC_H__
#define __IPSEC_H__

#include "utils.h"

static inline int ipsec_lookup_and_update_flow(flow_id *id, int flow_encrypted_ret,
                                               u16 eth_protocol) {
    additional_metrics *extra_metrics = bpf_map_lookup_elem(&additional_flow_metrics, id);
    if (extra_metrics != NULL) {
        extra_metrics->end_mono_time_ts = bpf_ktime_get_ns();
        extra_metrics->eth_protocol = eth_protocol;
        if (flow_encrypted_ret != 0) {
            extra_metrics->flow_encrypted_ret = flow_encrypted_ret;
            if (extra_metrics->flow_encrypted) {
                extra_metrics->flow_encrypted = false;
            }
            increase_counter(IPSEC_OPERATION_ERR);
        }
        return 0;
    }
    return -1;
}

static inline int update_flow_with_ipsec_return(int flow_encrypted_ret, direction dir) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u16 eth_protocol = 0;
    flow_id *id = NULL;
    int ret = 0;

    if (dir == INGRESS) {
        id = bpf_map_lookup_elem(&ipsec_ingress_map, &pid_tgid);
    } else {
        id = bpf_map_lookup_elem(&ipsec_egress_map, &pid_tgid);
    }

    if (!id) {
        BPF_PRINTK("ipsec flow id not found in dir: %d", dir);
        return 0;
    }

    if (is_ipv4(id->src_ip)) {
        eth_protocol = ETH_P_IP;
    } else {
        eth_protocol = ETH_P_IPV6;
    }

    BPF_PRINTK("found encrypted flow dir: %d encrypted: %d\n", dir,
               flow_encrypted_ret == 0 ? true : false);

    // update flow with ipsec info
    ret = ipsec_lookup_and_update_flow(id, flow_encrypted_ret, eth_protocol);
    if (ret == 0) {
        goto end;
    }

    u64 current_time = bpf_ktime_get_ns();
    additional_metrics new_flow;
    __builtin_memset(&new_flow, 0, sizeof(new_flow));
    new_flow.start_mono_time_ts = current_time;
    new_flow.end_mono_time_ts = current_time;
    new_flow.eth_protocol = eth_protocol;
    new_flow.flow_encrypted_ret = flow_encrypted_ret;
    if (flow_encrypted_ret == 0) {
        new_flow.flow_encrypted = true;
    } else {
        increase_counter(IPSEC_OPERATION_ERR);
    }
    ret = bpf_map_update_elem(&additional_flow_metrics, id, &new_flow, BPF_NOEXIST);
    if (ret != 0) {
        if (ret != -EEXIST) {
            BPF_PRINTK("error ipsec creating flow err: %d\n", ret);
        }
        if (ret == -EEXIST) {
            ret = ipsec_lookup_and_update_flow(id, flow_encrypted_ret, eth_protocol);
            if (ret != 0) {
                BPF_PRINTK("error ipsec updating an existing flow err: %d\n", ret);
            }
        }
    }
end:
    if (dir == INGRESS) {
        bpf_map_delete_elem(&ipsec_ingress_map, &pid_tgid);
    } else {
        bpf_map_delete_elem(&ipsec_egress_map, &pid_tgid);
    }
    return 0;
}

static inline int enter_xfrm_func(struct sk_buff *skb, direction dir) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u16 family = 0, flags = 0, eth_protocol = 0;
    u8 dscp = 0, protocol = 0;
    flow_id id;
    int ret = 0;

    __builtin_memset(&id, 0, sizeof(id));

    u32 if_index = BPF_CORE_READ(skb, skb_iif);

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
    bool skip = check_and_do_flow_filtering(&id, flags, 0, eth_protocol, NULL, dir);
    if (skip) {
        return 0;
    }

    BPF_PRINTK("Enter xfrm dir: %d protocol: %d family: %d if_index: %d \n", dir, protocol, family,
               if_index);

    if (dir == INGRESS) {
        ret = bpf_map_update_elem(&ipsec_ingress_map, &pid_tgid, &id, BPF_NOEXIST);
    } else {
        ret = bpf_map_update_elem(&ipsec_egress_map, &pid_tgid, &id, BPF_NOEXIST);
    }
    if (ret != 0) {
        if (trace_messages) {
            BPF_PRINTK("error creating new ipsec map dir: %d err: %d\n", dir, ret);
        }
    }
    return 0;
}

SEC("kprobe/xfrm_input")
int BPF_KPROBE(xfrm_input_kprobe) {
    if (do_sampling == 0 || enable_ipsec == 0) {
        return 0;
    }
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    if (!skb) {
        return 0;
    }
    return enter_xfrm_func(skb, INGRESS);
}

SEC("kretprobe/xfrm_input")
int BPF_KRETPROBE(xfrm_input_kretprobe) {
    if (do_sampling == 0 || enable_ipsec == 0) {
        return 0;
    }
    int xfrm_ret = PT_REGS_RC(ctx);
    return update_flow_with_ipsec_return(xfrm_ret, INGRESS);
}

SEC("kprobe/xfrm_output")
int BPF_KPROBE(xfrm_output_kprobe) {
    if (do_sampling == 0 || enable_ipsec == 0) {
        return 0;
    }
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    if (!skb) {
        return 0;
    }
    return enter_xfrm_func(skb, EGRESS);
}

SEC("kretprobe/xfrm_output")
int BPF_KRETPROBE(xfrm_output_kretprobe) {
    if (do_sampling == 0 || enable_ipsec == 0) {
        return 0;
    }
    int xfrm_ret = PT_REGS_RC(ctx);
    return update_flow_with_ipsec_return(xfrm_ret, EGRESS);
}

#endif /* __IPSEC_H__  */