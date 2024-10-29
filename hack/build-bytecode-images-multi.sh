#!/bin/bash

# Set default value for IMAGE_NOO_BC tag if not already set
IMAGE_NOO_BC=${IMAGE_NOO_BC:-quay.io/netobserv/ebpf-bytecode}

# PROGRAMS is a list of <program name>:<program type> tuples
PROGRAMS='{
"tcx_ingress_flow_parse":"tcx",
"tcx_egress_flow_parse":"tcx",
"tc_ingress_flow_parse":"tc",
"tc_egress_flow_parse":"tc",
"tcx_ingress_pca_parse":"tcx",
"tcx_egress_pca_parse":"tcx",
"tc_ingress_pca_parse":"tc",
"tc_egress_pca_parse":"tc",
"tcp_rcv_fentry":"fentry",
"tcp_rcv_kprobe":"kprobe",
"kfree_skb":"tracepoint",
"rh_network_events_monitoring":"kprobe",
"nf_nat_manip_pkt":"kprobe"
}'

# MAPS is a list of <map name>:<map type> tuples
MAPS='{
"direct_flows":"ringbuf",
"aggregated_flows":"hash",
"additional_flow_metrics":"per_cpu_hash"
"packets_record":"perf_event_array",
"dns_flows":"hash",
"global_counters":"per_cpu_array",
"filter_map":"lpm_trie"
}'

docker buildx create --use
docker buildx inspect --bootstrap

DOCKER_BUILDKIT=1 docker buildx build \
 --platform linux/amd64,linux/arm64,linux/s390x,linux/ppc64le \
 --build-arg PROGRAMS="$PROGRAMS" \
 --build-arg MAPS="$MAPS" \
 --build-arg BC_AMD64_EL=bpf_x86_bpfel.o \
 --build-arg BC_ARM64_EL=bpf_arm64_bpfel.o \
 --build-arg BC_S390X_EB=bpf_s390_bpfeb.o \
 --build-arg BC_PPC64LE_EL=bpf_powerpc_bpfel.o \
 -f ./Containerfile.bytecode.multi.arch \
 --push \
 ./pkg/ebpf -t $IMAGE_NOO_BC
