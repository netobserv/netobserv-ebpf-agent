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

static __always_inline void calculate_flow_rtt(pkt_info *pkt, u8 direction, void *data_end) {
    flow_seq_id seq_id;
    __builtin_memset(&seq_id, 0, sizeof(flow_seq_id));

    switch (pkt->id->transport_protocol)
    {
    case IPPROTO_TCP: {
            struct tcphdr *tcp = (struct tcphdr *) pkt->l4_hdr;
            if ( !tcp || ((void *)tcp + sizeof(*tcp) > data_end) ) {
                break;
            }
            if ((direction == EGRESS) && IS_SYN_PACKET(pkt)) {
                // Record the outgoing syn sequence number
                u32 seq = bpf_ntohl(tcp->seq);
                fill_flow_seq_id(&seq_id, pkt, seq, 0);

                long ret = bpf_map_update_elem(&flow_sequences, &seq_id, &pkt->current_ts, BPF_ANY);
                if (trace_messages && ret != 0) {
                    bpf_printk("err saving flow sequence record %d", ret);
                }
                break;
            }
            if ((direction == INGRESS) && IS_ACK_PACKET(pkt)) {
                // Stored sequence should be ack_seq - 1
                u32 seq = bpf_ntohl(tcp->ack_seq) - 1;
                // check reversed flow
                fill_flow_seq_id(&seq_id, pkt, seq, 1); 

                u64 *prev_ts = (u64 *)bpf_map_lookup_elem(&flow_sequences, &seq_id);
                if (prev_ts != NULL) {
                    pkt->rtt = pkt->current_ts - *prev_ts;
                    // Delete the flow from flow sequence map so if it
                    // restarts we have a new RTT calculation.
                    long ret = bpf_map_delete_elem(&flow_sequences, &seq_id);
                    if (trace_messages && ret != 0) {
                        bpf_printk("error evicting flow sequence: %d", ret);
                    }
                }
                break;
            }
        } break;
    default:
        break;
    }
}

#endif /* __RTT_TRACKER_H__ */