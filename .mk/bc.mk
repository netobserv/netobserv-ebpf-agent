##@ bytecode images

BC_IMAGE_TAG_BASE ?= quay.io/${IMAGE_ORG}/ebpf-bytecode
BC_IMAGE ?= $(BC_IMAGE_TAG_BASE):$(VERSION)

# PROGRAMS is a list of <program name>:<program type> tuples
define PROGRAMS
{
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
	"network_events_monitoring":"kprobe",
	"track_nat_manip_pkt":"kprobe",
	"xfrm_input_kprobe": "kprobe",
	"xfrm_input_kretprobe": "kretprobe",
	"xfrm_output_kprobe": "kprobe",
	"xfrm_output_kretprobe": "kretprobe",
	"probe_entry_SSL_write": "uprobe"
}
endef

# MAPS is a list of <map name>:<map type> tuples
define MAPS
{
	"direct_flows":"ringbuf",
	"aggregated_flows":"hash",
	"aggregated_flows_dns":"per_cpu_hash",
	"aggregated_flows_pkt_drop":"per_cpu_hash",
	"aggregated_flows_network_events":"per_cpu_hash",
	"aggregated_flows_xlat":"per_cpu_hash",
	"additional_flow_metrics":"per_cpu_hash",
	"packet_record":"ringbuf",
	"dns_flows":"hash",
	"global_counters":"per_cpu_array",
	"filter_map":"lpm_trie",
	"peer_filter_map":"lpm_trie",
	"ipsec_ingress_map":"hash",
	"ipsec_egress_map":"hash",
	"ssl_data_event_map":"ringbuf",
	"dns_name_map":"per_cpu_array"
}
endef

# build a single arch target provided as argument
define build_bc_target
	echo 'building bytecode image for arch $(1)'; \
	echo '${PROGRAMS}' | jq empty || { echo "Invalid JSON in PROGRAMS"; exit 1; }; \
	echo '${MAPS}' | jq empty || { echo "Invalid JSON in MAPS"; exit 1; }; \
	DOCKER_BUILDKIT=1 $(OCI_BIN) buildx build --platform linux/$(1) --load --build-arg PROGRAMS='${PROGRAMS}' --build-arg MAPS='${MAPS}' --build-arg BC_AMD64_EL=bpf_x86_bpfel.o --build-arg BC_ARM64_EL=bpf_arm64_bpfel.o --build-arg BC_S390X_EB=bpf_s390_bpfeb.o --build-arg BC_PPC64LE_EL=bpf_powerpc_bpfel.o --build-arg LDFLAGS="${LDFLAGS}" --build-arg TARGETARCH=$(1) ${OCI_BUILD_OPTS} ${EXTRA_BUILD_FLAGS} -t ${BC_IMAGE}-$(1) -f ./Containerfile.bytecode.multi.arch ./pkg/ebpf;
endef

# push a single arch target image
define push_bc_target
	echo 'pushing bytecode image ${BC_IMAGE}-$(1)'; \
	DOCKER_BUILDKIT=1 $(OCI_BIN) push ${BC_IMAGE}-$(1);
endef

# note: to build and push custom image tag use: IMAGE_ORG=myuser VERSION=dev s
.PHONY: bc-image-build
bc-image-build: ## Build MULTIARCH_TARGETS bytecode images
	trap 'exit' INT; \
	$(foreach target,$(MULTIARCH_TARGETS),$(call build_bc_target,$(target)))

.PHONY: bc-image-push
bc-image-push: ## Push MULTIARCH_TARGETS bytecode images
	trap 'exit' INT; \
	$(foreach target,$(MULTIARCH_TARGETS),$(call push_bc_target,$(target)))

.PHONY: bc-manifest-build
bc-manifest-build: ## Build MULTIARCH_TARGETS bytecode manifest
	echo 'building bytecode manifest $(BC_IMAGE)'
	DOCKER_BUILDKIT=1 $(OCI_BIN) rmi ${BC_IMAGE} -f
	DOCKER_BUILDKIT=1 $(OCI_BIN) manifest create ${BC_IMAGE} $(foreach target,$(MULTIARCH_TARGETS), --amend ${BC_IMAGE}-$(target));

.PHONY: bc-manifest-push
bc-manifest-push: ## Push MULTIARCH_TARGETS bytecode manifest
	@echo 'publish bytecode manifest $(BC_IMAGE)'
ifeq (${OCI_BIN}, docker)
	DOCKER_BUILDKIT=1 $(OCI_BIN) manifest push ${BC_IMAGE};
else
	DOCKER_BUILDKIT=1 $(OCI_BIN) manifest push ${BC_IMAGE} docker://${BC_IMAGE};
endif
