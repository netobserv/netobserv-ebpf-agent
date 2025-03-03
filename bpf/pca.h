#ifndef __PCA_H__
#define __PCA_H__

#include "utils.h"

static inline void attach_packet_payload(struct __sk_buff *skb) {
    payload_meta *event;
    u32 packetSize = skb->len;

    event = bpf_ringbuf_reserve(&packet_record, sizeof(payload_meta), 0);
    if (!event) {
        return;
    }

    if (!packetSize) {
        // Release reserved ringbuf location
        bpf_ringbuf_discard(event, 0);
        return;
    }

    if (packetSize > MAX_PAYLOAD_SIZE) {
        packetSize = MAX_PAYLOAD_SIZE;
    }

    event->if_index = skb->ifindex;
    event->pkt_len = packetSize;
    event->timestamp = bpf_ktime_get_ns();
    // bpf_skb_load_bytes will handle cases when packets are allocated linearly or none-linearly where
    // struct __sk_buff does not necessarily has all data lined up in memory but instead
    // can be part of scatter gather lists.
    // so no need to use bpf_skb_pull_data() which has performance side effects for the rest of that skb's lifetime.
    if (bpf_skb_load_bytes(skb, 0, event->payload, packetSize)) {
        // Release reserved ringbuf location
        bpf_ringbuf_discard(event, 0);
        return;
    }
    bpf_ringbuf_submit(event, 0);
    return;
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

    // check if this packet need to be filtered if filtering feature is enabled
    bool skip = check_and_do_flow_filtering(&id, pkt.flags, 0, eth_protocol, NULL, dir);
    if (skip) {
        return false;
    }

    return true;
}

static inline void export_packet_payload(struct __sk_buff *skb, direction dir) {
    if (!enable_pca) {
        return;
    }
    // If sampling is defined, will only parse 1 out of "sampling" flows
    if (sampling > 1 && (bpf_get_prandom_u32() % sampling) != 0) {
        return;
    }

    if (validate_pca_filter(skb, dir)) {
        attach_packet_payload(skb);
    }
}

SEC("classifier/tc_pca_ingress")
int tc_ingress_pca_parse(struct __sk_buff *skb) {
    export_packet_payload(skb, INGRESS);
    return TC_ACT_OK;
}

SEC("classifier/tc_pca_egress")
int tc_egress_pca_parse(struct __sk_buff *skb) {
    export_packet_payload(skb, EGRESS);
    return TC_ACT_OK;
}

SEC("classifier/tcx_pca_ingress")
int tcx_ingress_pca_parse(struct __sk_buff *skb) {
    export_packet_payload(skb, INGRESS);
    return TCX_NEXT;
}

SEC("classifier/tcx_pca_egress")
int tcx_egress_pca_parse(struct __sk_buff *skb) {
    export_packet_payload(skb, EGRESS);
    return TCX_NEXT;
}

#endif /* __PCA_H__ */
