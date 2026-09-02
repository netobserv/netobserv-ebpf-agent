#ifndef __PACKET_CAPTURE_H__
#define __PACKET_CAPTURE_H__

#include "configs.h"
#include "maps.h"
#include "../common/packet_utils.h"

static inline void attach_packet_payload(struct __sk_buff *skb) {
    payload_meta *event;
    u32 packetSize = skb->len;

    event = bpf_ringbuf_reserve(&packet_record, sizeof(payload_meta), 0);
    if (!event) {
        return;
    }

    if (!packetSize) {
        bpf_ringbuf_discard(event, 0);
        return;
    }

    if (packetSize > MAX_PAYLOAD_SIZE) {
        packetSize = MAX_PAYLOAD_SIZE;
    }

    event->if_index = skb->ifindex;
    event->pkt_len = packetSize;
    event->timestamp = bpf_ktime_get_ns();
    if (bpf_skb_load_bytes(skb, 0, event->payload, packetSize)) {
        bpf_ringbuf_discard(event, 0);
        return;
    }
    bpf_ringbuf_submit(event, 0);
}

static inline bool validate_packet_filter(struct __sk_buff *skb, direction dir) {
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

    bool skip = check_and_apply_filter(&id, pkt.flags, 0, eth_protocol, NULL, dir);
    if (skip) {
        return false;
    }

    return true;
}

static inline void export_packet_payload(struct __sk_buff *skb, direction dir) {
    if (sampling > 1 && (bpf_get_prandom_u32() % sampling) != 0) {
        return;
    }

    if (validate_packet_filter(skb, dir)) {
        attach_packet_payload(skb);
    }
}

SEC("classifier/tc_ingress")
int tc_ingress_packet_parse(struct __sk_buff *skb) {
    export_packet_payload(skb, INGRESS);
    return TC_ACT_OK;
}

SEC("classifier/tc_egress")
int tc_egress_packet_parse(struct __sk_buff *skb) {
    export_packet_payload(skb, EGRESS);
    return TC_ACT_OK;
}

SEC("classifier/tcx_ingress")
int tcx_ingress_packet_parse(struct __sk_buff *skb) {
    export_packet_payload(skb, INGRESS);
    return TCX_NEXT;
}

SEC("classifier/tcx_egress")
int tcx_egress_packet_parse(struct __sk_buff *skb) {
    export_packet_payload(skb, EGRESS);
    return TCX_NEXT;
}

SEC("netkit/primary")
int netkit_primary_packet_parse(struct __sk_buff *skb) {
    export_packet_payload(skb, EGRESS);
    return NETKIT_NEXT;
}

SEC("netkit/peer")
int netkit_peer_packet_parse(struct __sk_buff *skb) {
    export_packet_payload(skb, INGRESS);
    return NETKIT_NEXT;
}

#endif /* __PACKET_CAPTURE_H__ */
