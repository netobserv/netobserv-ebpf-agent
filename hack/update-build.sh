#!/usr/bin/env bash

echo "Updating container file"

: "${CONTAINER_FILE:=./Dockerfile}"
: "${COMMIT:=$(git rev-list --abbrev-commit --tags --max-count=1)}"

cat <<EOF >>"${CONTAINER_FILE}"
LABEL com.redhat.component="network-observability-ebpf-agent-container"
LABEL name="network-observability-ebpf-agent"
LABEL io.k8s.display-name="Network Observability EBPF Agent"
LABEL io.k8s.description="Network Observability EBPF Agent"
LABEL summary="Network Observability EBPF Agent"
LABEL maintainer="support@redhat.com"
LABEL io.openshift.tags="network-observability-ebpf-agent"
LABEL upstream-vcs-ref="${COMMIT}"
LABEL upstream-vcs-type="git"
EOF
