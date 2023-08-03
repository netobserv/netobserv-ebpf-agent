#ifndef __PCA_H__
#define __PCA_H__

#include "utils.h"
#include <string.h>

#define MAX_EVENT_DATA 1024ul

static inline int export_packet_payload (struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    payload_meta meta;
    struct ethhdr *eth  = data;
    struct iphdr  *ip;
    struct udphdr *tproto_data;
    __u64 flags = BPF_F_CURRENT_CPU;
    __u16 packetSize;

    // Record the current time.
    u64 current_time = bpf_ktime_get_ns();
    
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
    
    //Only export packets on port number set by ENV var
    if (tproto_data->source == bpf_htons(pca_port) || tproto_data->dest == bpf_htons(pca_port)) {
        // enable the flag to add packet header
        // Packet payload follows immediately after the meta struct
        packetSize = (__u16)(data_end-data);
        if (packetSize < skb->len){
            bpf_printk("Packets with extended skb %d, %d", packetSize, skb->len);
            packetSize = skb->len;
            bpf_skb_pull_data(skb, skb->len);
        }
        flags |= (__u64)packetSize << 32;

        meta.if_index = skb->ifindex;
        meta.pkt_len = packetSize;
        meta.timestamp = current_time;
        if (bpf_perf_event_output(skb, &packet_record, flags, &meta, sizeof(meta))){
            return TC_ACT_UNSPEC;
        }

    }

    return TC_ACT_OK;    
}

#endif /* __PCA_H__ */