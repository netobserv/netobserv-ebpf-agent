#!/usr/bin/env bash

echo "Updating container file"

: "${CONTAINER_FILE:=./Dockerfile}"
: "${COMMIT:=$(git rev-list --abbrev-commit --tags --max-count=1)}"

cat <<EOF >>"${CONTAINER_FILE}"
LABEL com.redhat.component="network-observability-ebpf-agent-container"
LABEL name="network-observability-ebpf-agent"
LABEL io.k8s.display-name="Network Observability eBPF Agent"
LABEL io.k8s.description="Network Observability eBPF Agent"
LABEL summary="Network Observability eBPF Agent"
LABEL maintainer="support@redhat.com"
LABEL io.openshift.tags="network-observability-ebpf-agent"
LABEL upstream-vcs-ref="${COMMIT}"
LABEL upstream-vcs-type="git"
LABEL description="The Network Observability eBPF Agent allows collecting and aggregating all the ingress and egress flows on a Linux host."
EOF
