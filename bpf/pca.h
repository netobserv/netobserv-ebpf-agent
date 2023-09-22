#ifndef __PCA_H__
#define __PCA_H__

#include "utils.h"
#include <string.h>

static int attach_packet_payload(void *data, void *data_end, struct __sk_buff *skb){
        payload_meta meta;
        u64 flags = BPF_F_CURRENT_CPU;
        // Enable the flag to add packet header
        // Packet payload follows immediately after the meta struct
        u32 packetSize = (u32)(data_end-data);
        
        // Record the current time.
        u64 current_time = bpf_ktime_get_ns();
        
        // For packets which are allocated non-linearly struct __sk_buff does not necessarily 
        // has all data lined up in memory but instead can be part of scatter gather lists. 
        // This command pulls data from the buffer but incurs data copying penalty.
        if (packetSize <= skb->len){
            packetSize = skb->len;
            if (bpf_skb_pull_data(skb, skb->len)){
                return TC_ACT_UNSPEC;
            };
        }
        // Set flag's upper 32 bits with the size of the paylaod and the bpf_perf_event_output will 
        // attach the specified amount of bytes from packet to the perf event
        // https://github.com/xdp-project/xdp-tutorial/tree/9b25f0a039179aca1f66cba5492744d9f09662c1/tracing04-xdp-tcpdump       
        flags |= (u64)packetSize << 32;

        meta.if_index = skb->ifindex;
        meta.pkt_len = packetSize;
        meta.timestamp = current_time;
        if (bpf_perf_event_output(skb, &packet_record, flags, &meta, sizeof(meta))){
            return TC_ACT_OK;
        }
        return TC_ACT_UNSPEC;
}

static inline bool validate_pca_filter(u8 ipproto, void *ipheaderend, void *data_end){
    // If filters: pca_proto and pca_port are not specified, export packet
    if (pca_proto == 0 && pca_port == 0)
        return true;

    //Only export packets with protocol set by ENV var PCA_FILTER
    u16 sourcePort, destPort;
    if (ipproto != pca_proto) {
       return false;	
    }

    if (ipproto == IPPROTO_TCP){
        struct tcphdr *tcp_header = ipheaderend;
        if ((void *)tcp_header + sizeof(*tcp_header) > data_end) {
            return false;
        }
        sourcePort = tcp_header->source;
        destPort = tcp_header->dest;
    }
    else if (ipproto == IPPROTO_UDP){
        struct udphdr *udp_header = ipheaderend;
        if ((void *)udp_header + sizeof(*udp_header) > data_end) {
            return false;	
        }
        sourcePort = udp_header->source;
        destPort = udp_header->dest;
    }
    else if (ipproto == IPPROTO_SCTP){
        struct sctphdr *sctp_header = ipheaderend;
        if ((void *)sctp_header + sizeof(*sctp_header) > data_end) {
                return false;	
            }
            sourcePort = sctp_header->source;
            destPort = sctp_header->dest;        
    }
    else {
        return false;
    }
    u16 pca_port_end = bpf_htons(pca_port);
    if (sourcePort == pca_port_end || destPort == pca_port_end){
        return true;
    }
    return false;
}

static inline int export_packet_payload (struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth  = data;
    struct iphdr  *ip;
    
    if ((void *)eth + sizeof(*eth) > data_end) {
       return TC_ACT_UNSPEC;
    }

    // Only IPv4 and IPv6 packets captured
    u16 ethType = bpf_ntohs(eth->h_proto);
    if (ethType != ETH_P_IP && ethType != ETH_P_IPV6) {
       return TC_ACT_UNSPEC;	
    }   
    
    ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) {
       return TC_ACT_UNSPEC;
    }

    if (validate_pca_filter(ip->protocol, (void *)ip + sizeof(*ip), data_end )){
        return attach_packet_payload(data, data_end, skb);
    }
    return TC_ACT_UNSPEC;
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
