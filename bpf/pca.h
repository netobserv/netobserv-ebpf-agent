#ifndef __PCA_H__
#define __PCA_H__

#include "utils.h"
#include <string.h>

static int attach_packet_payload(void *data, void *data_end, struct __sk_buff *skb, u64 current_time ){
        payload_meta meta;
        u64 flags = BPF_F_CURRENT_CPU;
        // Enable the flag to add packet header
        // Packet payload follows immediately after the meta struct
        u32 packetSize = (__u32)(data_end-data);
        // For packets which are allocated non-linearly struct __sk_buff does not necessarily 
        // has all data lined up in memory but instead can be part of scatter gather lists. 
        // This command pulls data from the buffer but incurs data copying penalty.
        if (packetSize < skb->len){
            packetSize = skb->len;
            bpf_skb_pull_data(skb, skb->len);
        }
        // Set flag's upper 32 bits with the size of the paylaod and the bpf_perf_event_output will 
        // attach the specified amount of bytes from packet to the perf event
        // https://github.com/xdp-project/xdp-tutorial/tree/9b25f0a039179aca1f66cba5492744d9f09662c1/tracing04-xdp-tcpdump       
        flags |= (__u64)packetSize << 32;

        meta.if_index = skb->ifindex;
        meta.pkt_len = packetSize;
        meta.timestamp = current_time;
        if (bpf_perf_event_output(skb, &packet_record, flags, &meta, sizeof(meta))){
            return TC_ACT_OK;
        }
        return TC_ACT_OK;
}

static inline int export_packet_payload (struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr *eth  = data;
    struct iphdr  *ip;
    struct udphdr *udp_header;

    // Record the current time.
    __u64 current_time = bpf_ktime_get_ns();
    
    if ((void *)eth + sizeof(*eth) > data_end) {
       return TC_ACT_UNSPEC;
    }

    // Only IPv4 and IPv6 packets captured
    if (eth->h_proto != bpf_htons(ETH_P_IP) && (eth->h_proto != bpf_htons(ETH_P_IPV6))) {
       return TC_ACT_UNSPEC;	
    }   
    
    ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) {
       return TC_ACT_UNSPEC;
    }
    
    //Only export packets with protocol set by ENV var PCA_FILTER
    if (ip->protocol != pca_proto) {
       return TC_ACT_UNSPEC;	
    }

    if (ip->protocol == IPPROTO_TCP){
        struct tcphdr *tcp_header = (void *)ip + sizeof(*ip);
        if ((void *)tcp_header + sizeof(*tcp_header) > data_end) {
            return TC_ACT_UNSPEC;
        }
        if (tcp_header->source == bpf_htons(pca_port) || tcp_header->dest == bpf_htons(pca_port)){
            return attach_packet_payload(data, data_end, skb, current_time);
        }
        return TC_ACT_OK;
    }

    udp_header = (void *)ip + sizeof(*ip);
    if ((void *)udp_header + sizeof(*udp_header) > data_end) {
       return TC_ACT_UNSPEC;	
    }
    if (udp_header->source == bpf_htons(pca_port) || udp_header->dest == bpf_htons(pca_port)){
        return attach_packet_payload(data, data_end, skb, current_time);
    }
    return TC_ACT_OK;
}


SEC("tc_pca_ingress")
int ingress_pca_parse (struct __sk_buff *skb) {
    return export_packet_payload(skb);
}

SEC("tc_pca_egress")
int egress_pca_parse (struct __sk_buff *skb) {
    return export_packet_payload(skb);
}

#endif /* __PCA_H__ */