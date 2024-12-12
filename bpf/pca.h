#ifndef __PCA_H__
#define __PCA_H__

#include "utils.h"

static int attach_packet_payload(void *data, void *data_end, struct __sk_buff *skb) {
    payload_meta meta;
    u64 flags = BPF_F_CURRENT_CPU;
    // Enable the flag to add packet header
    // Packet payload follows immediately after the meta struct
    u32 packetSize = (u32)(data_end - data);

    // Record the current time.
    u64 current_time = bpf_ktime_get_ns();

    // For packets which are allocated non-linearly struct __sk_buff does not necessarily
    // has all data lined up in memory but instead can be part of scatter gather lists.
    // This command pulls data from the buffer but incurs data copying penalty.
    if (packetSize <= skb->len) {
        packetSize = skb->len;
        if (bpf_skb_pull_data(skb, skb->len)) {
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
    if (bpf_perf_event_output(skb, &packet_record, flags, &meta, sizeof(meta))) {
        return TC_ACT_OK;
    }
    return TC_ACT_UNSPEC;
}

static inline bool validate_pca_filter(struct __sk_buff *skb, direction dir) {
    pkt_info pkt;
    __builtin_memset(&pkt, 0, sizeof(pkt));
    flow_id id;
    __builtin_memset(&id, 0, sizeof(id));
    u16 eth_protocol = 0;

    pkt.id = &id;

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = (struct ethhdr *)data;

    if (fill_ethhdr(eth, data_end, &pkt, &eth_protocol) == DISCARD) {
        return false;
    }

    //Set extra fields
    id.if_index = skb->ifindex;
    id.direction = dir;

    // check if this packet need to be filtered if filtering feature is enabled
    bool skip = check_and_do_flow_filtering(&id, pkt.flags, 0, eth_protocol);
    if (skip) {
        return false;
    }

    return true;
}

static inline int export_packet_payload(struct __sk_buff *skb, direction dir) {
    // If sampling is defined, will only parse 1 out of "sampling" flows
    if (sampling > 1 && (bpf_get_prandom_u32() % sampling) != 0) {
        return 0;
    }

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    if (validate_pca_filter(skb, dir)) {
        return attach_packet_payload(data, data_end, skb);
    }
    return 0;
}

SEC("tc_pca_ingress")
int tc_ingress_pca_parse(struct __sk_buff *skb) {
    export_packet_payload(skb, INGRESS);
    return TC_ACT_OK;
}

SEC("tc_pca_egress")
int tc_egress_pca_parse(struct __sk_buff *skb) {
    export_packet_payload(skb, EGRESS);
    return TC_ACT_OK;
}

SEC("tcx_pca_ingress")
int tcx_ingress_pca_parse(struct __sk_buff *skb) {
    export_packet_payload(skb, INGRESS);
    return TCX_NEXT;
}

SEC("tcx_pca_egress")
int tcx_egress_pca_parse(struct __sk_buff *skb) {
    export_packet_payload(skb, EGRESS);
    return TCX_NEXT;
}

#endif /* __PCA_H__ */
