#!/bin/bash

# Set default value for IMAGE_NOO_BC tag if not already set
IMAGE_NOO_BC=${IMAGE_NOO_BC:-quay.io/${USER}/ebpf-bytecode}
OCI_BIN=${OCI_BIN:-docker}

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

echo "$PROGRAMS" | jq empty || { echo "Invalid JSON in PROGRAMS"; exit 1; }

# MAPS is a list of <map name>:<map type> tuples
MAPS='{
"direct_flows":"ringbuf",
"aggregated_flows":"hash",
"additional_flow_metrics":"per_cpu_hash",
"packets_record":"perf_event_array",
"dns_flows":"hash",
"global_counters":"per_cpu_array",
"filter_map":"lpm_trie"
}'

echo "$MAPS" | jq empty || { echo "Invalid JSON in MAPS"; exit 1; }

if [[ ${OCI_BIN} == "docker" ]]; then
  docker buildx create --name bytecode-builder --use
  docker buildx inspect --bootstrap

  docker buildx build \
  --platform linux/amd64,linux/arm64,linux/s390x,linux/ppc64le \
  --build-arg PROGRAMS="$PROGRAMS" \
  --build-arg MAPS="$MAPS" \
  --build-arg BC_AMD64_EL=bpf_x86_bpfel.o \
  --build-arg BC_ARM64_EL=bpf_arm64_bpfel.o \
  --build-arg BC_S390X_EB=bpf_s390_bpfeb.o \
  --build-arg BC_PPC64LE_EL=bpf_powerpc_bpfel.o \
  ${OCI_BUILD_OPTS} \
  -f ./Containerfile.bytecode.multi.arch \
  --push \
  ./pkg/ebpf -t $IMAGE_NOO_BC

  docker buildx rm bytecode-builder
else
  ${OCI_BIN} buildx build \
  --platform linux/amd64,linux/arm64,linux/s390x,linux/ppc64le \
  --build-arg PROGRAMS="$PROGRAMS" \
  --build-arg MAPS="$MAPS" \
  --build-arg BC_AMD64_EL=bpf_x86_bpfel.o \
  --build-arg BC_ARM64_EL=bpf_arm64_bpfel.o \
  --build-arg BC_S390X_EB=bpf_s390_bpfeb.o \
  --build-arg BC_PPC64LE_EL=bpf_powerpc_bpfel.o \
  ${OCI_BUILD_OPTS} \
  -f ./Containerfile.bytecode.multi.arch \
  ./pkg/ebpf -t $IMAGE_NOO_BC

  ${OCI_BIN} push $IMAGE_NOO_BC
fi
