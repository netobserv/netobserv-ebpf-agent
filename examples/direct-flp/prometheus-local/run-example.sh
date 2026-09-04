#!/usr/bin/env bash
# Run NetObserv eBPF agent on the host with direct-flp + Prometheus encode, alongside
# a Prometheus instance in Docker that scrapes the embedded flowlogs-pipeline /metrics.
#
# Prerequisites:
#   - Built agent: (cd repo root && make compile)
#   - Docker with compose plugin
#   - Caps: sudo, or CAP_BPF + CAP_PERFMON + CAP_NET_ADMIN (see README)
#   - Packet drops: /sys/kernel/debug mounted read-write (often requires privileged / root)
#   - IPsec/TLS: ENABLE_IPSEC_TRACKING / ENABLE_TLS_TRACKING (extra eBPF hooks; series only if traffic matches)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_BIN="${REPO_ROOT}/bin/netobserv-ebpf-agent"

if [[ ! -x "${AGENT_BIN}" ]]; then
  echo "Missing ${AGENT_BIN}. Run: cd ${REPO_ROOT} && make compile" >&2
  exit 1
fi

cd "${SCRIPT_DIR}"
docker compose up -d

export EXPORT=direct-flp
export FLP_CONFIG="$(cat "${SCRIPT_DIR}/flp-prometheus.yaml")"

export ENABLE_RTT=true
export ENABLE_PKT_DROPS=true
export ENABLE_DNS_TRACKING=true
export ENABLE_IPSEC_TRACKING=true
export ENABLE_TLS_TRACKING=true

# Embedded FLP serves Prometheus on 9102; keep agent metrics on 9090 (default).
export METRICS_SERVER_PORT=9090

echo "Prometheus UI: http://127.0.0.1:9091 (Graph: try netobserv:tcp_flow_rtt:milliseconds; Alerts: NetobservNoFlowMetrics)"
echo "Embedded FLP metrics: http://127.0.0.1:9102/metrics"
echo "Agent metrics: http://127.0.0.1:${METRICS_SERVER_PORT}/metrics"
echo "Starting agent (sudo)…"

exec sudo -E "${AGENT_BIN}"
