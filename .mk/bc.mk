##@ bytecode images

BC_IMAGE_TAG_BASE ?= quay.io/${IMAGE_ORG}/ebpf-bytecode

# When BC_IMAGE is set (e.g. CI: quay.io/netobserv/ebpf-bytecode:tmp), derive split image names.
# Otherwise default to -flows / -packets suffixes with VERSION.
ifneq ($(BC_IMAGE),)
BC_FLOW_IMAGE ?= $(subst /ebpf-bytecode:,/ebpf-bytecode-flows:,$(BC_IMAGE))
BC_PACKET_IMAGE ?= $(subst /ebpf-bytecode:,/ebpf-bytecode-packets:,$(BC_IMAGE))
else
BC_FLOW_IMAGE ?= $(BC_IMAGE_TAG_BASE)-flows:$(VERSION)
BC_PACKET_IMAGE ?= $(BC_IMAGE_TAG_BASE)-packets:$(VERSION)
BC_IMAGE ?= $(BC_FLOW_IMAGE)
endif

# FLOW_PROGRAMS is a list of <program name>:<program type> tuples
define FLOW_PROGRAMS
{
	"tcx_ingress_flow_parse":"tcx",
	"tcx_egress_flow_parse":"tcx",
	"tc_ingress_flow_parse":"tc",
	"tc_egress_flow_parse":"tc",
	"tcp_rcv_fentry":"fentry",
	"tcp_rcv_kprobe":"kprobe",
	"kfree_skb":"tracepoint",
	"network_events_monitoring":"kprobe",
	"track_nat_manip_pkt":"kprobe",
	"xfrm_input_kprobe": "kprobe",
	"xfrm_input_kretprobe": "kretprobe",
	"xfrm_output_kprobe": "kprobe",
	"xfrm_output_kretprobe": "kretprobe",
	"probe_entry_SSL_write": "uprobe",
	"probe_entry_SSL_read": "uprobe",
	"probe_ret_SSL_read": "uretprobe",
	"probe_entry_SSL_set_fd": "uprobe"
}
endef

# FLOW_MAPS is a list of <map name>:<map type> tuples
define FLOW_MAPS
{
	"direct_flows":"ringbuf",
	"aggregated_flows":"hash",
	"aggregated_flows_dns":"per_cpu_hash",
	"aggregated_flows_pkt_drop":"per_cpu_hash",
	"aggregated_flows_network_events":"per_cpu_hash",
	"aggregated_flows_xlat":"per_cpu_hash",
	"additional_flow_metrics":"per_cpu_hash",
	"dns_flows":"hash",
	"global_counters":"per_cpu_array",
	"filter_map":"lpm_trie",
	"peer_filter_map":"lpm_trie",
	"ipsec_ingress_map":"hash",
	"ipsec_egress_map":"hash",
	"ssl_data_event_map":"ringbuf",
	"ssl_read_active_map":"hash",
	"ssl_fd_map":"lru_hash",
	"dns_name_map":"per_cpu_array",
	"quic_flows":"per_cpu_hash"
}
endef

define PACKET_PROGRAMS
{
	"tcx_ingress_packet_parse":"tcx",
	"tcx_egress_packet_parse":"tcx",
	"tc_ingress_packet_parse":"tc",
	"tc_egress_packet_parse":"tc",
	"netkit_primary_packet_parse":"tcx",
	"netkit_peer_packet_parse":"tcx",
	"probe_entry_SSL_write": "uprobe",
	"probe_entry_SSL_read": "uprobe",
	"probe_ret_SSL_read": "uretprobe",
	"probe_entry_SSL_set_fd": "uprobe"
}
endef

define PACKET_MAPS
{
	"packet_record":"ringbuf",
	"filter_map":"lpm_trie",
	"peer_filter_map":"lpm_trie",
	"global_counters":"per_cpu_array",
	"ssl_data_event_map":"ringbuf",
	"ssl_read_active_map":"hash",
	"ssl_fd_map":"lru_hash"
}
endef

# build a single arch flow bytecode image
define build_bc_flow_target
	echo 'building flow bytecode image for arch $(1)'; \
	echo '${FLOW_PROGRAMS}' | jq empty || { echo "Invalid JSON in FLOW_PROGRAMS"; exit 1; }; \
	echo '${FLOW_MAPS}' | jq empty || { echo "Invalid JSON in FLOW_MAPS"; exit 1; }; \
	DOCKER_BUILDKIT=1 $(OCI_BIN) buildx build --platform linux/$(1) --load --build-arg PROGRAMS='${FLOW_PROGRAMS}' --build-arg MAPS='${FLOW_MAPS}' --build-arg BC_AMD64_EL=flows/bpf_x86_bpfel.o --build-arg BC_ARM64_EL=flows/bpf_arm64_bpfel.o --build-arg BC_S390X_EB=flows/bpf_s390_bpfeb.o --build-arg BC_PPC64LE_EL=flows/bpf_powerpc_bpfel.o --build-arg LDFLAGS="${LDFLAGS}" --build-arg TARGETARCH=$(1) ${OCI_BUILD_OPTS} ${EXTRA_BUILD_FLAGS} -t ${BC_FLOW_IMAGE}-$(1) -f ./Containerfile.bytecode.multi.arch ./pkg/ebpf;
endef

# build a single arch packet bytecode image
define build_bc_packet_target
	echo 'building packet bytecode image for arch $(1)'; \
	echo '${PACKET_PROGRAMS}' | jq empty || { echo "Invalid JSON in PACKET_PROGRAMS"; exit 1; }; \
	echo '${PACKET_MAPS}' | jq empty || { echo "Invalid JSON in PACKET_MAPS"; exit 1; }; \
	DOCKER_BUILDKIT=1 $(OCI_BIN) buildx build --platform linux/$(1) --load --build-arg PROGRAMS='${PACKET_PROGRAMS}' --build-arg MAPS='${PACKET_MAPS}' --build-arg BC_AMD64_EL=packets/packets_x86_bpfel.o --build-arg BC_ARM64_EL=packets/packets_arm64_bpfel.o --build-arg BC_S390X_EB=packets/packets_s390_bpfeb.o --build-arg BC_PPC64LE_EL=packets/packets_powerpc_bpfel.o --build-arg LDFLAGS="${LDFLAGS}" --build-arg TARGETARCH=$(1) ${OCI_BUILD_OPTS} ${EXTRA_BUILD_FLAGS} -t ${BC_PACKET_IMAGE}-$(1) -f ./Containerfile.bytecode.multi.arch ./pkg/ebpf;
endef

# push a single arch flow bytecode image
define push_bc_flow_target
	echo 'pushing flow bytecode image ${BC_FLOW_IMAGE}-$(1)'; \
	DOCKER_BUILDKIT=1 $(OCI_BIN) push ${BC_FLOW_IMAGE}-$(1);
endef

# push a single arch packet bytecode image
define push_bc_packet_target
	echo 'pushing packet bytecode image ${BC_PACKET_IMAGE}-$(1)'; \
	DOCKER_BUILDKIT=1 $(OCI_BIN) push ${BC_PACKET_IMAGE}-$(1);
endef

.PHONY: bc-flow-image-build
bc-flow-image-build: ## Build MULTIARCH_TARGETS flow bytecode images
	trap 'exit' INT; \
	$(foreach target,$(MULTIARCH_TARGETS),$(call build_bc_flow_target,$(target)))

.PHONY: bc-packet-image-build
bc-packet-image-build: ## Build MULTIARCH_TARGETS packet bytecode images
	trap 'exit' INT; \
	$(foreach target,$(MULTIARCH_TARGETS),$(call build_bc_packet_target,$(target)))

.PHONY: bc-image-build
bc-image-build: bc-flow-image-build bc-packet-image-build ## Build MULTIARCH_TARGETS flow and packet bytecode images

.PHONY: bc-flow-image-push
bc-flow-image-push: ## Push MULTIARCH_TARGETS flow bytecode images
	trap 'exit' INT; \
	$(foreach target,$(MULTIARCH_TARGETS),$(call push_bc_flow_target,$(target)))

.PHONY: bc-packet-image-push
bc-packet-image-push: ## Push MULTIARCH_TARGETS packet bytecode images
	trap 'exit' INT; \
	$(foreach target,$(MULTIARCH_TARGETS),$(call push_bc_packet_target,$(target)))

.PHONY: bc-image-push
bc-image-push: bc-flow-image-push bc-packet-image-push ## Push MULTIARCH_TARGETS flow and packet bytecode images

.PHONY: bc-flow-manifest-build
bc-flow-manifest-build: ## Build MULTIARCH_TARGETS flow bytecode manifest
	echo 'building flow bytecode manifest $(BC_FLOW_IMAGE)'
	DOCKER_BUILDKIT=1 $(OCI_BIN) rmi ${BC_FLOW_IMAGE} -f
	DOCKER_BUILDKIT=1 $(OCI_BIN) manifest create ${BC_FLOW_IMAGE} $(foreach target,$(MULTIARCH_TARGETS), --amend ${BC_FLOW_IMAGE}-$(target));

.PHONY: bc-packet-manifest-build
bc-packet-manifest-build: ## Build MULTIARCH_TARGETS packet bytecode manifest
	echo 'building packet bytecode manifest $(BC_PACKET_IMAGE)'
	DOCKER_BUILDKIT=1 $(OCI_BIN) rmi ${BC_PACKET_IMAGE} -f
	DOCKER_BUILDKIT=1 $(OCI_BIN) manifest create ${BC_PACKET_IMAGE} $(foreach target,$(MULTIARCH_TARGETS), --amend ${BC_PACKET_IMAGE}-$(target));

.PHONY: bc-manifest-build
bc-manifest-build: bc-flow-manifest-build bc-packet-manifest-build ## Build MULTIARCH_TARGETS flow and packet bytecode manifests

.PHONY: bc-flow-manifest-push
bc-flow-manifest-push: ## Push MULTIARCH_TARGETS flow bytecode manifest
	@echo 'publish flow bytecode manifest $(BC_FLOW_IMAGE)'
ifeq (${OCI_BIN}, docker)
	DOCKER_BUILDKIT=1 $(OCI_BIN) manifest push ${BC_FLOW_IMAGE};
else
	DOCKER_BUILDKIT=1 $(OCI_BIN) manifest push ${BC_FLOW_IMAGE} docker://${BC_FLOW_IMAGE};
endif

.PHONY: bc-packet-manifest-push
bc-packet-manifest-push: ## Push MULTIARCH_TARGETS packet bytecode manifest
	@echo 'publish packet bytecode manifest $(BC_PACKET_IMAGE)'
ifeq (${OCI_BIN}, docker)
	DOCKER_BUILDKIT=1 $(OCI_BIN) manifest push ${BC_PACKET_IMAGE};
else
	DOCKER_BUILDKIT=1 $(OCI_BIN) manifest push ${BC_PACKET_IMAGE} docker://${BC_PACKET_IMAGE};
endif

.PHONY: bc-manifest-push
bc-manifest-push: bc-flow-manifest-push bc-packet-manifest-push ## Push MULTIARCH_TARGETS flow and packet bytecode manifests
