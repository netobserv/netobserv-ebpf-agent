/*
    A simple RTT tracker implemented to be used at the ebpf layer inside the flow_monitor hookpoint.
    This tracker currently tracks RTT for TCP flows by looking at the TCP start sequence and estimates
    RTT by perform (timestamp of receiveing ack packet - timestamp of sending syn packet)
 */

#ifndef __RTT_TRACKER_H__
#define __RTT_TRACKER_H__

#include "utils.h"
#include "maps_definition.h"

const u64 MIN_RTT = 50000; //50 micro seconds

static __always_inline void fill_flow_seq_id(flow_seq_id *seq_id, pkt_info *pkt, u32 seq, bool reverse) {
    flow_id *id = pkt->id;
    if (reverse) {
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
    seq_id->transport_protocol = id->transport_protocol;
    seq_id->seq_id = seq;
    seq_id->if_index = id->if_index;
}

static __always_inline void reverse_flow_id_struct(flow_id *src, flow_id *dst) {
    // Fields which remain same
    dst->eth_protocol = src->eth_protocol;
    dst->transport_protocol = src->transport_protocol;
    dst->if_index = src->if_index;

    // Fields which should be reversed
    dst->direction = (src->direction == INGRESS) ? EGRESS : INGRESS;
    __builtin_memcpy(dst->src_mac, src->dst_mac, ETH_ALEN);
    __builtin_memcpy(dst->dst_mac, src->src_mac, ETH_ALEN);
    __builtin_memcpy(dst->src_ip, src->dst_ip, IP_MAX_LEN);
    __builtin_memcpy(dst->dst_ip, src->src_ip, IP_MAX_LEN);
    dst->src_port = src->dst_port;
    dst->dst_port = src->src_port;
    /* ICMP type can be ignore for now. We only deal with TCP packets for now.*/
}

static __always_inline void update_reverse_flow_rtt(pkt_info *pkt, u32 seq) {
    flow_id rev_flow_id;
    __builtin_memset(&rev_flow_id, 0, sizeof(rev_flow_id));
    reverse_flow_id_struct(pkt->id, &rev_flow_id);

    flow_metrics *reverse_flow = (flow_metrics *)bpf_map_lookup_elem(&aggregated_flows, &rev_flow_id);
    if (reverse_flow != NULL) {
        if (pkt->rtt > reverse_flow->flow_rtt) {
            reverse_flow->flow_rtt = pkt->rtt;
            long ret = bpf_map_update_elem(&aggregated_flows, &rev_flow_id, reverse_flow, BPF_EXIST);
            if (trace_messages && ret != 0) {
                bpf_printk("error updating rtt value in flow %d\n", ret);
            }
        }
    }
}

static __always_inline void __calculate_tcp_rtt(pkt_info *pkt, struct tcphdr *tcp, flow_seq_id *seq_id) {
    // Stored sequence should be ack_seq - 1
    u32 seq = bpf_ntohl(tcp->ack_seq) - 1;
    // check reversed flow
    fill_flow_seq_id(seq_id, pkt, seq, true);

    u64 *prev_ts = (u64 *)bpf_map_lookup_elem(&flow_sequences, seq_id);
    if (prev_ts != NULL) {
        u64 rtt = pkt->current_ts - *prev_ts;
        /**
         * FIXME: Because of SAMPLING the way it is done if we miss one of SYN/SYN+ACK/ACK
         * then we can get RTT values which are the process response time rather than actual RTT.
         * This check below clears them out but needs to be modified with a better solution or change
         * the algorithm for calculating RTT so it doesn't interact with SAMPLING like this.
         */
        if (rtt < MIN_RTT) {
            return;
        }
        pkt->rtt = rtt;
        // Delete the flow from flow sequence map so if it
        // restarts we have a new RTT calculation.
        long ret = bpf_map_delete_elem(&flow_sequences, seq_id);
        if (trace_messages && ret != 0) {
            bpf_printk("error evicting flow sequence: %d", ret);
        }
        // This is an ACK packet with valid sequence id so a SYN must
        // have been sent. We can safely update the reverse flow RTT here.
        update_reverse_flow_rtt(pkt, seq);
    }
    return;
}

static __always_inline void __store_tcp_ts(pkt_info *pkt, struct tcphdr *tcp, flow_seq_id *seq_id) {
    // store timestamp of syn packets.
    u32 seq = bpf_ntohl(tcp->seq);
    fill_flow_seq_id(seq_id, pkt, seq, false);
    long ret = bpf_map_update_elem(&flow_sequences, seq_id, &pkt->current_ts, BPF_NOEXIST);
    if (trace_messages && ret != 0) {
        bpf_printk("err saving flow sequence record %d", ret);
    }
    return;
}

static __always_inline void calculate_flow_rtt_tcp(pkt_info *pkt, u8 direction, void *data_end, flow_seq_id *seq_id) {
    struct tcphdr *tcp = (struct tcphdr *) pkt->l4_hdr;
    if ( !tcp || ((void *)tcp + sizeof(*tcp) > data_end) ) {
        return;
    }

    /* We calculate RTT for both SYN/SYN+ACK and SYN+ACK/ACK and take the maximum of both.*/
    if (tcp->syn && tcp->ack) { // SYN ACK Packet
        __calculate_tcp_rtt(pkt, tcp, seq_id);
        __store_tcp_ts(pkt, tcp, seq_id);
    }
    else if (tcp->ack) {
        __calculate_tcp_rtt(pkt, tcp, seq_id);
    }
    else if (tcp->syn) {
        __store_tcp_ts(pkt, tcp, seq_id);
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