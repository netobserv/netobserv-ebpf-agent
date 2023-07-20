/*
    A simple RTT tracker implemented to be used at the ebpf layer inside the flow_monitor hookpoint.
    This tracker currently tracks RTT for TCP flows by looking at the TCP start sequence and estimates
    RTT by perform (timestamp of receiveing ack packet - timestamp of sending syn packet)
 */

#ifndef __RTT_TRACKER_H__
#define __RTT_TRACKER_H__

#include "utils.h"
#include "maps_definition.h"

static __always_inline void fill_flow_seq_id(flow_seq_id *seq_id, pkt_info *pkt, u32 seq, u8 reversed) {
    flow_id *id = pkt->id;
    if (reversed) {
        __builtin_memcpy(seq_id->src_ip, id->dst_ip, IP_MAX_LEN);
        __builtin_memcpy(seq_id->dst_ip, id->src_ip, IP_MAX_LEN);
        seq_id->src_port = id->dst_port;
        seq_id->dst_port = id->src_port;
    } else {
        __builtin_memcpy(seq_id->src_ip, id->src_ip, IP_MAX_LEN);
        __builtin_memcpy(seq_id->dst_ip, id->dst_ip, IP_MAX_LEN);
        seq_id->src_port = id->src_port;
        seq_id->dst_port = id->dst_port;
    }
    seq_id->seq_id = seq;
}

static __always_inline void reverse_flow_id(flow_id *o, flow_id *r) {
    /* eth_protocol, transport_protocol and if_index remains same */
    r->eth_protocol = o->eth_protocol;
    r->transport_protocol = o->transport_protocol;
    r->if_index = o->if_index;
    /* reverse the direction */
    r->direction = (o->direction == INGRESS) ? EGRESS : INGRESS;
    /* src mac and dst mac gets reversed */
    __builtin_memcpy(r->src_mac, o->dst_mac, ETH_ALEN);
    __builtin_memcpy(r->dst_mac, o->src_mac, ETH_ALEN);
    /* src ip and dst ip gets reversed */
    __builtin_memcpy(r->src_ip, o->dst_ip, IP_MAX_LEN);
    __builtin_memcpy(r->dst_ip, o->src_ip, IP_MAX_LEN);
    /* src port and dst port gets reversed */
    r->src_port = o->dst_port;
    r->dst_port = o->src_port;
    /* ICMP type can be ignore for now. We only deal with TCP packets for now.*/
}

static __always_inline void update_reverse_flow_rtt(pkt_info *pkt) {
    flow_id rev_flow_id;
    __builtin_memset(&rev_flow_id, 0, sizeof(rev_flow_id));

    reverse_flow_id(pkt->id, &rev_flow_id);

    flow_metrics *reverse_flow = (flow_metrics *)bpf_map_lookup_elem(&aggregated_flows, &rev_flow_id);
    if (reverse_flow != NULL) {
        reverse_flow->flow_rtt = pkt->rtt;
        long ret = bpf_map_update_elem(&aggregated_flows, &rev_flow_id, reverse_flow, BPF_ANY);
        if (trace_messages && ret != 0) {
            bpf_printk("error updating rtt value in flow %d\n", ret);
        }
    }
}

static __always_inline void calculate_flow_rtt_tcp(pkt_info *pkt, u8 direction, void *data_end, flow_seq_id *seq_id) {
    struct tcphdr *tcp = (struct tcphdr *) pkt->l4_hdr;
    if ( !tcp || ((void *)tcp + sizeof(*tcp) > data_end) ) {
        return;
    }

    switch (direction) {
    case EGRESS: {
        if (IS_SYN_PACKET(pkt)) {
            // Record the outgoing syn sequence number
            u32 seq = bpf_ntohl(tcp->seq);
            fill_flow_seq_id(seq_id, pkt, seq, 0);

            long ret = bpf_map_update_elem(&flow_sequences, seq_id, &pkt->current_ts, BPF_ANY);
            if (trace_messages && ret != 0) {
                bpf_printk("err saving flow sequence record %d", ret);
            }
        }
        break;
    }
    case INGRESS: {
        if (IS_ACK_PACKET(pkt)) {
            // Stored sequence should be ack_seq - 1
            u32 seq = bpf_ntohl(tcp->ack_seq) - 1;
            // check reversed flow
            fill_flow_seq_id(seq_id, pkt, seq, 1);

            u64 *prev_ts = (u64 *)bpf_map_lookup_elem(&flow_sequences, seq_id);
            if (prev_ts != NULL) {
                pkt->rtt = pkt->current_ts - *prev_ts;
                // Delete the flow from flow sequence map so if it
                // restarts we have a new RTT calculation.
                long ret = bpf_map_delete_elem(&flow_sequences, seq_id);
                if (trace_messages && ret != 0) {
                    bpf_printk("error evicting flow sequence: %d", ret);
                }
                // This is an ACK packet with valid sequence id so a SYN must
                // have been sent. We can safely update the reverse flow RTT here.
                update_reverse_flow_rtt(pkt);
            }
        }
        break;
    }
    }
}

static __always_inline void calculate_flow_rtt(pkt_info *pkt, u8 direction, void *data_end) {
    flow_seq_id seq_id;
    __builtin_memset(&seq_id, 0, sizeof(flow_seq_id));

    switch (pkt->id->transport_protocol)
    {
    case IPPROTO_TCP:
        calculate_flow_rtt_tcp(pkt, direction, data_end, &seq_id);
        break;
    default:
        break;
    }
}

#endif /* __RTT_TRACKER_H__ */

