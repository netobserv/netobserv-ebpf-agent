/*
    rule based filter to filter out packets not of interest to users.
*/

#ifndef __FLOWS_FILTER_H__
#define __FLOWS_FILTER_H__

#include "utils.h"

#define BPF_PRINTK(fmt, args...)                                                                   \
    if (trace_messages)                                                                            \
    bpf_printk(fmt, ##args)

static __always_inline int flow_filter_setup_lookup_key(flow_id *id, struct filter_key_t *key,
                                                        u8 *len, u8 *offset, bool use_src_ip,
                                                        u16 eth_protocol) {

    if (eth_protocol == ETH_P_IP) {
        *len = sizeof(u32);
        *offset = sizeof(ip4in6);
        if (use_src_ip) {
            __builtin_memcpy(key->ip_data, id->src_ip + *offset, *len);
        } else {
            __builtin_memcpy(key->ip_data, id->dst_ip + *offset, *len);
        }
        key->prefix_len = 32;
    } else if (eth_protocol == ETH_P_IPV6) {
        *len = IP_MAX_LEN;
        *offset = 0;
        if (use_src_ip) {
            __builtin_memcpy(key->ip_data, id->src_ip + *offset, *len);
        } else {
            __builtin_memcpy(key->ip_data, id->dst_ip + *offset, *len);
        }
        key->prefix_len = 128;
    } else {
        return -1;
    }
    return 0;
}

static __always_inline int do_flow_filter_lookup(flow_id *id, struct filter_key_t *key,
                                                 filter_action *action, u8 len, u8 offset,
                                                 u16 flags, u32 drop_reason, u32 *sampling,
                                                 u8 direction, bool use_src_ip, u16 eth_protocol) {
    int result = 0;

    struct filter_value_t *rule = (struct filter_value_t *)bpf_map_lookup_elem(&filter_map, key);

    if (rule) {
        BPF_PRINTK("rule found drop_reason %d flags %d do_peerCIDR_lookup %d\n", drop_reason, flags,
                   rule->do_peerCIDR_lookup);
        result++;
        if (rule->action != MAX_FILTER_ACTIONS) {
            BPF_PRINTK("action matched: %d\n", rule->action);
            *action = rule->action;
            result++;
        }

        if (rule->do_peerCIDR_lookup) {
            struct filter_key_t peerKey;
            // No need to memset - flow_filter_setup_lookup_key will initialize all fields we use
            // PeerCIDR lookup will will target the opposite IP compared to original CIDR lookup
            // In other words if cidr is using srcIP then peerCIDR will be the dstIP
            if (flow_filter_setup_lookup_key(id, &peerKey, &len, &offset, use_src_ip,
                                             eth_protocol) < 0) {
                BPF_PRINTK("peerCIDR failed to setup lookup key\n");
                result = 0;
                goto end;
            }

            u8 *peer_result = (u8 *)bpf_map_lookup_elem(&peer_filter_map, &peerKey);
            if (peer_result) {
                BPF_PRINTK("peerCIDR matched\n");
                result++;
            } else {
                BPF_PRINTK("peerCIDR couldn't find a matching key\n");
                result = 0;
                goto end;
            }
        }

        if (rule->sample && sampling != NULL) {
            BPF_PRINTK("sampling action is set to %d\n", rule->sample);
            *sampling = rule->sample;
            result++;
        }
        // match specific rule protocol or use wildcard protocol
        if (rule->protocol == id->transport_protocol || rule->protocol == 0) {
            switch (id->transport_protocol) {
            case IPPROTO_TCP:
            case IPPROTO_UDP:
            case IPPROTO_SCTP:
                // dstPort matching
                if ((rule->dstPortStart != 0 && rule->dstPortEnd == 0) || rule->dstPort1 != 0 ||
                    rule->dstPort2 != 0) {
                    if (rule->dstPortStart == id->dst_port || rule->dstPort1 == id->dst_port ||
                        rule->dstPort2 == id->dst_port) {
                        BPF_PRINTK("dstPort matched\n");
                        result++;
                    } else {
                        result = 0;
                        goto end;
                    }
                } else if (rule->dstPortStart != 0 && rule->dstPortEnd != 0) {
                    if (rule->dstPortStart <= id->dst_port && id->dst_port <= rule->dstPortEnd) {
                        BPF_PRINTK("dstPortStart and dstPortEnd matched\n");
                        result++;
                    } else {
                        result = 0;
                        goto end;
                    }
                }
                // srcPort matching
                if ((rule->srcPortStart != 0 && rule->srcPortEnd == 0) || rule->srcPort1 != 0 ||
                    rule->srcPort2 != 0) {
                    if (rule->srcPortStart == id->src_port || rule->srcPort1 == id->src_port ||
                        rule->srcPort2 == id->src_port) {
                        BPF_PRINTK("srcPort matched\n");
                        result++;
                    } else {
                        result = 0;
                        goto end;
                    }
                } else if (rule->srcPortStart != 0 && rule->srcPortEnd != 0) {
                    if (rule->srcPortStart <= id->src_port && id->src_port <= rule->srcPortEnd) {
                        BPF_PRINTK("srcPortStart and srcPortEnd matched\n");
                        result++;
                    } else {
                        result = 0;
                        goto end;
                    }
                }
                // Generic port matching check for either src or dst port
                if ((rule->portStart != 0 && rule->portEnd == 0) || rule->port1 != 0 ||
                    rule->port2 != 0) {
                    if (rule->portStart == id->src_port || rule->portStart == id->dst_port ||
                        rule->port1 == id->src_port || rule->port1 == id->dst_port ||
                        rule->port2 == id->src_port || rule->port2 == id->dst_port) {
                        BPF_PRINTK("port matched\n");
                        result++;
                    } else {
                        result = 0;
                        goto end;
                    }
                } else if (rule->portStart != 0 && rule->portEnd != 0) {
                    if ((rule->portStart <= id->src_port && id->src_port <= rule->portEnd) ||
                        (rule->portStart <= id->dst_port && id->dst_port <= rule->portEnd)) {
                        BPF_PRINTK("portStart and portEnd matched\n");
                        result++;
                    } else {
                        result = 0;
                        goto end;
                    }
                }
                // for TCP only check TCP flags if its set
                if (id->transport_protocol == IPPROTO_TCP) {
                    if (rule->tcpFlags != 0) {
                        if (rule->tcpFlags == flags) {
                            BPF_PRINTK("tcpFlags matched\n");
                            result++;
                        } else {
                            result = 0;
                            goto end;
                        }
                    }
                }
                break;
            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6:
                if (rule->icmpType != 0) {
                    if (rule->icmpType == id->icmp_type) {
                        BPF_PRINTK("icmpType matched\n");
                        result++;
                    } else {
                        result = 0;
                        goto end;
                    }
                    if (rule->icmpCode != 0) {
                        if (rule->icmpCode == id->icmp_code) {
                            BPF_PRINTK("icmpCode matched\n");
                            result++;
                        } else {
                            result = 0;
                            goto end;
                        }
                    }
                }
                break;
            }
        } else {
            result = 0;
            goto end;
        }

        if (rule->direction != MAX_DIRECTION) {
            if (rule->direction == direction) {
                BPF_PRINTK("direction matched\n");
                result++;
            } else {
                result = 0;
                goto end;
            }
        }

        if (rule->filter_drops) {
            if (drop_reason != 0) {
                BPF_PRINTK("drop filter matched\n");
                result++;
            } else {
                result = 0;
                goto end;
            }
        }
    }
end:
    BPF_PRINTK("result: %d action %d\n", result, *action);
    return result;
}

/*
 * Early IP-only filter check - optimized to skip L4 parsing if IP-based rejection is possible.
 * Returns: 1 if packet can be rejected early (IP-only reject rule), 0 if needs full check
 * This is a fast path that only checks CIDR matching, not ports/protocols.
 */
static __always_inline int early_ip_filter_check(flow_id *id, filter_action *action,
                                                 u16 eth_protocol, u8 direction) {
    struct filter_key_t key;
    u8 len, offset;
    struct filter_value_t *rule;

    // Check srcIP CIDR match first
    if (flow_filter_setup_lookup_key(id, &key, &len, &offset, true, eth_protocol) < 0) {
        return 0; // Need full check
    }

    rule = (struct filter_value_t *)bpf_map_lookup_elem(&filter_map, &key);
    if (rule && rule->action == REJECT) {
        // IP matches and action is REJECT - can reject early without checking ports/protocols
        // Note: We check direction if rule specifies it
        if (rule->direction == MAX_DIRECTION || rule->direction == direction) {
            // If rule has port/protocol checks, we can't reject early (would need L4)
            // But if it's IP-only (protocol==0, no ports), we can reject now
            if (rule->protocol == 0 && rule->dstPortStart == 0 && rule->srcPortStart == 0 &&
                rule->portStart == 0 && rule->dstPort1 == 0 && rule->srcPort1 == 0 &&
                rule->port1 == 0 && rule->dstPort2 == 0 && rule->srcPort2 == 0 &&
                rule->port2 == 0 && !rule->do_peerCIDR_lookup && rule->tcpFlags == 0 &&
                rule->icmpType == 0 && rule->filter_drops == 0) {
                *action = REJECT;
                return 1; // Can reject early
            }
        }
    }

    // Check dstIP CIDR match
    if (flow_filter_setup_lookup_key(id, &key, &len, &offset, false, eth_protocol) < 0) {
        return 0; // Need full check
    }

    rule = (struct filter_value_t *)bpf_map_lookup_elem(&filter_map, &key);
    if (rule && rule->action == REJECT) {
        if (rule->direction == MAX_DIRECTION || rule->direction == direction) {
            if (rule->protocol == 0 && rule->dstPortStart == 0 && rule->srcPortStart == 0 &&
                rule->portStart == 0 && rule->dstPort1 == 0 && rule->srcPort1 == 0 &&
                rule->port1 == 0 && rule->dstPort2 == 0 && rule->srcPort2 == 0 &&
                rule->port2 == 0 && !rule->do_peerCIDR_lookup && rule->tcpFlags == 0 &&
                rule->icmpType == 0 && rule->filter_drops == 0) {
                *action = REJECT;
                return 1; // Can reject early
            }
        }
    }

    return 0; // Need full check with L4
}

/*
 * check if the flow match filter rule and return >= 1 if the flow is to be dropped
 */
static __always_inline int is_flow_filtered(flow_id *id, filter_action *action, u16 flags,
                                            u32 drop_reason, u16 eth_protocol, u32 *sampling,
                                            u8 direction) {
    struct filter_key_t key;
    u8 len, offset;
    int result = 0;

    // No need to memset - flow_filter_setup_lookup_key will initialize all fields we use
    *action = MAX_FILTER_ACTIONS;

    // Lets do first CIDR match using srcIP.
    result = flow_filter_setup_lookup_key(id, &key, &len, &offset, true, eth_protocol);
    if (result < 0) {
        return result;
    }

    result = do_flow_filter_lookup(id, &key, action, len, offset, flags, drop_reason, sampling,
                                   direction, false, eth_protocol);
    // we have a match so return
    if (result > 0) {
        return result;
    }

    // if we can't find a match then Lets do second CIDR match using dstIP.
    result = flow_filter_setup_lookup_key(id, &key, &len, &offset, false, eth_protocol);
    if (result < 0) {
        return result;
    }

    return do_flow_filter_lookup(id, &key, action, len, offset, flags, drop_reason, sampling,
                                 direction, true, eth_protocol);
}

#endif //__FLOWS_FILTER_H__
