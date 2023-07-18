#ifndef __PANO_H__
#define __PANO_H__

#include "utils.h"
#include <string.h>

#define MAX_EVENT_DATA 256

static inline int export_packet_payload (struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    payload_meta meta;
    struct ethhdr *eth  = data;
    struct iphdr  *ip;
    struct udphdr *tproto_data;
    __u64 flags = BPF_F_CURRENT_CPU;
    __u16 headerSize;
    __u64 packet_len;


    if ((void *)eth + sizeof(*eth) > data_end) {
       return TC_ACT_UNSPEC;
    }

    ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) {
       return TC_ACT_UNSPEC;
    }

    tproto_data = (void *)ip + sizeof(*ip);
    if ((void *)tproto_data + sizeof(*tproto_data) > data_end) {
       return TC_ACT_UNSPEC;	
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP) && (eth->h_proto != bpf_htons(ETH_P_IPV6))) {
       return TC_ACT_UNSPEC;	
    }   

    //Only export packets with protocol set by ENV var
    if (ip->protocol != pca_proto) {
       return TC_ACT_UNSPEC;	
    }

    packet_len = data_end - data;
    headerSize = packet_len < MAX_EVENT_DATA ? packet_len : MAX_EVENT_DATA;
    //Only export packets on port number set by ENV var
    if (tproto_data->source == bpf_htons(pca_port) || tproto_data->dest == bpf_htons(pca_port)) {
        // enable the flag to add packet header
        // Packet payload follows immediately after the meta struct
        flags |= (__u64)headerSize << 32;

        meta.if_index = skb->ifindex;
        meta.pkt_len = data_end - data;
        if (bpf_perf_event_output(skb, &packet_record, flags, &meta, sizeof(meta))){
            return TC_ACT_UNSPEC;
        }

    }

    return TC_ACT_OK;   
}

#endif /* __PANO_H__ */