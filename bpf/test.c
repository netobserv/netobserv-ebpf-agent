#include <stdio.h>
#include <assert.h>

#define false 0
#define true 1
#define bpf_printk printf

typedef int bool;
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned long __u32;
typedef unsigned long long __u64;

enum {
	IPPROTO_ICMP = 1,
	IPPROTO_TCP = 6,
	IPPROTO_UDP = 17,
	IPPROTO_SCTP = 132,
};

struct bpf_spin_lock {
	__u32 val;
};

#include "types.h"

volatile u32 sampling = 0;
volatile u8 trace_messages = 0;
volatile u8 enable_rtt = 0;
volatile u8 enable_pca = 0;
volatile u8 enable_dns_tracking = 0;
volatile u8 enable_flows_filtering = 0;
volatile u16 dns_port = 0;
volatile u8 enable_network_events_monitoring = 0;
volatile u8 network_events_monitoring_groupid = 0;
volatile u8 enable_pkt_translation_tracking = 0;

typedef enum mock_scenario_t {
    NO_RULE,
    REJECT_1_2_3_4_ALLOW_OTHER,
} mock_scenario;

struct mocked_map {
  mock_scenario scen;
};

struct filter_value_t reject_filter = {
  .action = REJECT,
};
struct filter_value_t accept_filter = {
  .action = ACCEPT,
};

volatile struct mocked_map filter_map;

static struct filter_value_t* bpf_map_lookup_elem(struct mocked_map *map, struct filter_key_t *key) {
  if (map->scen == NO_RULE) {
    return NULL;
  }
  u8 ip1234[IP_MAX_LEN] = {1, 2, 3, 4};
  if (__builtin_memcmp(ip1234, key->ip_data, IP_MAX_LEN) == 0) {
    return &reject_filter;
  }
  return &accept_filter;
}

static void increase_counter(u32 key) {
}

#include "flows_filter.h"

int main(int argc, char *argv[]) {
  flow_id id;
  filter_action action;
  u32 sampling = 0;
  filter_map.scen = NO_RULE;
  int skip = check_and_do_flow_filtering(&id, 0, 0, ETH_P_IP, &sampling);
  printf("skip=%d\n", skip);
  assert(skip == 0);
  printf("filter disabled [success]\n");
  
  enable_flows_filtering = 1;
  skip = check_and_do_flow_filtering(&id, 0, 0, ETH_P_IP, &sampling);
  printf("skip=%d\n", skip);
  assert(skip == 1);
  printf("filter enabled [success]\n");

  filter_map.scen = REJECT_1_2_3_4_ALLOW_OTHER;
  __builtin_memcpy(id.src_ip, (u8[IP_MAX_LEN]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}, IP_MAX_LEN);
  __builtin_memcpy(id.dst_ip, (u8[IP_MAX_LEN]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8}, IP_MAX_LEN);
  printf("filter should reject from 1.2.3.4 [...]\n");
  skip = check_and_do_flow_filtering(&id, 0, 0, ETH_P_IP, &sampling);
  printf("skip=%d\n", skip);
  assert(skip == 1);
  printf("filter reject from 1.2.3.4 [success]\n");

  __builtin_memcpy(id.src_ip, (u8[IP_MAX_LEN]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8}, IP_MAX_LEN);
  __builtin_memcpy(id.dst_ip, (u8[IP_MAX_LEN]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}, IP_MAX_LEN);
  printf("filter should reject to 1.2.3.4 [...]\n");
  skip = check_and_do_flow_filtering(&id, 0, 0, ETH_P_IP, &sampling);
  printf("skip=%d\n", skip);
  assert(skip == 1);
  printf("filter reject to 1.2.3.4 [success]\n");

  __builtin_memcpy(id.src_ip, (u8[IP_MAX_LEN]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 4, 5}, IP_MAX_LEN);
  __builtin_memcpy(id.dst_ip, (u8[IP_MAX_LEN]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8}, IP_MAX_LEN);
  printf("filter should accept others [...]\n");
  skip = check_and_do_flow_filtering(&id, 0, 0, ETH_P_IP, &sampling);
  printf("skip=%d\n", skip);
  assert(skip == 0);
  printf("filter accept others [success]\n");

  return 0;
}
