#include <vmlinux.h>
#include <bpf_helpers.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

// definitions to not having to include arpa/inet.h version of 32-bit in the compiler
// TODO: to unload even more the Kernel space, we can do this calculation in the Go userspace
#define htons(x)                       \
    ((u16)((((u16)(x)&0xff00U) >> 8) | \
           (((u16)(x)&0x00ffU) << 8)))

#define htonl(x)                            \
    ((u32)((((u32)(x)&0xff000000U) >> 24) | \
           (((u32)(x)&0x00ff0000U) >> 8) |  \
           (((u32)(x)&0x0000ff00U) << 8) |  \
           (((u32)(x)&0x000000ffU) << 24)))

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} flows SEC(".maps");

struct egress_t {
    u32 src_ip;
    u16 src_port;
    u32 dst_ip;
    u16 dst_port;
    u8 protocol;
    u64 bytes;
} __attribute__((packed));

SEC("tc/flow_parse")
static inline int flow_parse(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if ((void *)eth + sizeof(*eth) <= data_end) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) <= data_end) {

            struct egress_t *event = bpf_ringbuf_reserve(&flows, sizeof(struct egress_t), 0);
            if (!event) {
                return TC_ACT_OK;
            }

            event->src_ip = htonl(ip->saddr);
            event->dst_ip = htonl(ip->daddr);
            event->protocol = ip->protocol;

            switch (ip->protocol) {
            case IPPROTO_TCP: {
                struct tcphdr *tcp = (void *)ip + sizeof(*ip);
                if ((void *)tcp + sizeof(*tcp) <= data_end) {
                    event->src_port = htons(tcp->source);
                    event->dst_port = htons(tcp->dest);
                }
            } break;
            case IPPROTO_UDP: {
                struct udphdr *udp = (void *)ip + sizeof(*ip);
                if ((void *)udp + sizeof(*udp) <= data_end) {
                    event->src_port = htons(udp->source);
                    event->dst_port = htons(udp->dest);
                }
            } break;
            default:
                break;
            }
            event->bytes = skb->len;

            bpf_ringbuf_submit(event, 0);
        }
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";