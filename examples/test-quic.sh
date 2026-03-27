#!/usr/bin/env bash
# Quick end-to-end QUIC (HTTP/3) test suite on an existing cluster context.
#
# What it does:
# - deploy an in-cluster HTTP/3 (QUIC) server (Caddy) as a Service with TCP/UDP 443
# - run HTTP/3 client pods against that Service (multiple cases)
# - verify QUIC tracking via *agent logs*:
#   looks for "QUIC flow metrics sample" with quicFlowsLogged>0, plus UDP/443 assertions
#
# Usage:
#   ./examples/test-quic.sh
#
# Suite cases (always run with defaults):
# - smoke: QUIC_REQUESTS=2, QUIC_PARALLEL_CLIENTS=1
# - parallel clients: QUIC_REQUESTS=1, QUIC_PARALLEL_CLIENTS=3
# - non-443 port: verifies QUIC detection on a non-443 UDP port by temporarily setting QUIC_TRACKING_MODE=2
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"

CLIENT_IMAGE="mrchoke/curl-http3"
DEBUG_KEEP_POD="false"
CLIENT_TIMEOUT_SECONDS="15"
RUN_TCP_SANITY="false"
QUIC_REQUESTS="2"
QUIC_PARALLEL_CLIENTS="1"
RUN_NEGATIVE_NO_UDP="true"

QUIC_SERVER_NAME="quic-server"
QUIC_NAMESPACE="quic"
QUIC_SERVER_IMAGE="caddy:2"
QUIC_ALT_SERVER_NAME="quic-server-alt"
QUIC_ALT_PORT="8443"
NETOBSERV_NAMESPACE="netobserv-privileged"
AGENT_LOG_WAIT_SECONDS="20"

AGENT_LABEL="k8s-app=netobserv-ebpf-agent"

log() { printf '%s\n' "$*"; }

START_TS=""

# --------------------
# Small helpers
# --------------------
is_pos_int() {
  [[ "${1:-}" =~ ^[1-9][0-9]*$ ]]
}

cleanup_quic_resources() {
  # Best-effort cleanup. This runs on EXIT/INT/TERM so keep it resilient.
  if [[ "${DEBUG_KEEP_POD}" == "true" ]]; then
    log ""
    log "Note: DEBUG_KEEP_POD=true so QUIC resources were not cleaned up."
    return 0
  fi

  log ""
  log "==> Cleaning up QUIC test resources"
  # The script owns the whole namespace; deleting it is the simplest cleanup.
  kubectl delete namespace/"${QUIC_NAMESPACE}" --ignore-not-found=true >/dev/null 2>&1 || true
}

wait_pod_done() {
  local ns="$1"
  local pod="$2"
  local timeout_seconds="${3:-120}"
  local start
  start="$(date +%s)"

  while true; do
    local phase=""
    phase="$(kubectl get pod -n "$ns" "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    if [[ "$phase" == "Succeeded" || "$phase" == "Failed" ]]; then
      return 0
    fi
    if (( $(date +%s) - start > timeout_seconds )); then
      return 1
    fi
    sleep 2
  done
}

run_client_pod() {
  local ns="$1"
  local pod="$2"
  local image="$3"

  kubectl delete pod -n "${ns}" "${pod}" --ignore-not-found=true >/dev/null 2>&1 || true
  shift 3
  # IMPORTANT: Do not assume the client image has a shell. Execute the command directly.
  kubectl run -n "${ns}" "${pod}" --restart=Never --image="${image}" --labels="quic-test=true" --command -- "$@" >/dev/null
}

# --------------------
# QUIC target helpers (Service DNS + optional PodIP override for reliability)
# --------------------
get_quic_server_pod_ip() {
  local server_name="${1:-${QUIC_SERVER_NAME}}"
  kubectl get pod -n "${QUIC_NAMESPACE}" -l app="${server_name}" -o jsonpath='{.items[0].status.podIP}' 2>/dev/null || true
}

get_quic_service_cluster_ip() {
  local server_name="${1:-${QUIC_SERVER_NAME}}"
  kubectl get svc -n "${QUIC_NAMESPACE}" "${server_name}" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true
}

curl_resolve_args_for_quic_server() {
  # For reliability, prefer targeting the server PodIP (bypasses kube-proxy UDP LB quirks)
  # while still using the Service DNS name for SNI/Host via curl --resolve.
  local host="$1"
  local port="${2:-443}"
  local server_name="${3:-${QUIC_SERVER_NAME}}"
  local pod_ip=""
  pod_ip="$(get_quic_server_pod_ip "${server_name}")"
  if [[ -n "${pod_ip:-}" ]]; then
    printf -- "--resolve\n%s:%s:%s\n" "${host}" "${port}" "${pod_ip}"
  fi
}

# Build an array of curl args (Bash 3 compatible) to route the Service DNS name to the server PodIP.
build_resolve_args() {
  local host="$1"
  local port="${2:-443}"
  local server_name="${3:-${QUIC_SERVER_NAME}}"
  local out=()
  local arg=""
  while IFS= read -r arg; do
    [[ -n "${arg:-}" ]] && out+=("${arg}")
  done < <(curl_resolve_args_for_quic_server "${host}" "${port}" "${server_name}")

  # Print one arg per line so callers can capture via a while-read loop.
  for arg in "${out[@]}"; do
    printf '%s\n' "${arg}"
  done
}

repeat_url_args() {
  local url="$1"
  local count="$2"
  local i=1
  while [[ "$i" -le "$count" ]]; do
    printf '%s\n' "${url}"
    i=$((i+1))
  done
}

set_quic_service_tcp_only() {
  local server_name="${1:-${QUIC_SERVER_NAME}}"
  local port="${2:-443}"
  log "==> Negative test setup: updating Service to TCP-only (removing UDP/${port})"
  # Prefer patching the existing Service (more robust than re-applying a whole manifest).
  if ! kubectl patch svc -n "${QUIC_NAMESPACE}" "${server_name}" --type=merge \
    -p "{\"spec\":{\"ports\":[{\"name\":\"https-tcp\",\"port\":${port},\"targetPort\":${port},\"protocol\":\"TCP\"}]}}" >/dev/null 2>&1; then
    log "Warning: could not patch Service; falling back to apply"
    kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata:
  name: ${server_name}
  namespace: ${QUIC_NAMESPACE}
spec:
  selector:
    app: ${server_name}
  ports:
  - name: https-tcp
    port: ${port}
    targetPort: ${port}
    protocol: TCP
EOF
  fi
}

deploy_incluster_quic_server() {
  local server_name="${1:-${QUIC_SERVER_NAME}}"
  local port="${2:-443}"
  log "==> Deploying in-cluster QUIC (HTTP/3) server ($QUIC_SERVER_IMAGE) as ${QUIC_NAMESPACE}/${server_name} (port ${port})"
  local quic_server_fqdn="${server_name}.${QUIC_NAMESPACE}.svc.cluster.local"

  # Keep the server stable across suite cases: avoid delete/recreate, which can cause
  # transient downtime and QUIC client timeouts (especially with parallel clients).

  kubectl apply -f - >/dev/null <<EOF
---
apiVersion: v1
kind: Namespace
metadata:
  name: ${QUIC_NAMESPACE}
---  
apiVersion: v1
kind: ConfigMap
metadata:
  name: ${server_name}
  namespace: ${QUIC_NAMESPACE}
data:
  Caddyfile: |
    {
      servers {
        # Enable HTTP/3 (QUIC) in addition to HTTP/1.1 and HTTP/2
        protocols h1 h2 h3
      }
    }

    ${quic_server_fqdn}:${port} {
      tls internal
      respond "ok\n"
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${server_name}
  namespace: ${QUIC_NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ${server_name}
  template:
    metadata:
      labels:
        app: ${server_name}
    spec:
      containers:
      - name: caddy
        image: ${QUIC_SERVER_IMAGE}
        ports:
        - name: https-tcp
          containerPort: ${port}
          protocol: TCP
        - name: https-udp
          containerPort: ${port}
          protocol: UDP
        volumeMounts:
        - name: caddyfile
          mountPath: /etc/caddy
          readOnly: true
      volumes:
      - name: caddyfile
        configMap:
          name: ${server_name}
---
apiVersion: v1
kind: Service
metadata:
  name: ${server_name}
  namespace: ${QUIC_NAMESPACE}
spec:
  selector:
    app: ${server_name}
  ports:
  - name: https-tcp
    port: ${port}
    targetPort: ${port}
    protocol: TCP
  - name: https-udp
    port: ${port}
    targetPort: ${port}
    protocol: UDP
EOF

  if ! kubectl wait -n "${QUIC_NAMESPACE}" --for=condition=Available deployment/"${server_name}" --timeout=120s >/dev/null 2>&1; then
    log ""
    log "Warning: QUIC server deployment did not become Available."
    kubectl get pods -n "${QUIC_NAMESPACE}" -l app="${server_name}" -o wide || true
    log ""
    log "==> Debug: QUIC server logs"
    kubectl logs -n "${QUIC_NAMESPACE}" -l app="${server_name}" --tail=200 2>/dev/null || true
    log ""
    log "==> Debug: QUIC server describe"
    kubectl describe pods -n "${QUIC_NAMESPACE}" -l app="${server_name}" 2>/dev/null || true
    return 1
  fi

  kubectl get pods -n "${QUIC_NAMESPACE}" -l app="${server_name}" -o wide || true
  return 0
}

ensure_agent_exists() {
  if ! kubectl get ds -n "$NETOBSERV_NAMESPACE" netobserv-ebpf-agent >/dev/null 2>&1; then
    log "==> Agent DaemonSet not found; deploying from scripts/agent.yml"
    kubectl apply -f "$ROOT_DIR/scripts/agent.yml" >/dev/null
  fi
  kubectl rollout status -n "$NETOBSERV_NAMESPACE" ds/netobserv-ebpf-agent --timeout=180s >/dev/null
}

set_agent_quic_tracking_mode() {
  # Args: 1|2
  local mode="${1:-1}"
  if [[ "${mode}" != "1" && "${mode}" != "2" ]]; then
    log "ERROR: set_agent_quic_tracking_mode expects 1|2 (got: ${mode})"
    return 2
  fi

  log "==> Updating agent env: QUIC_TRACKING_MODE=${mode}"
  # Use set env for portability across DS manifests.
  kubectl -n "$NETOBSERV_NAMESPACE" set env ds/netobserv-ebpf-agent \
    QUIC_TRACKING_MODE="${mode}" \
    --overwrite >/dev/null
  kubectl rollout status -n "$NETOBSERV_NAMESPACE" ds/netobserv-ebpf-agent --timeout=180s >/dev/null
}

# --------------------
# Test cases
# --------------------
run_suite() {
  log "==> Running QUIC test suite (multiple cases)"

  # Negative test runs by default; disable with RUN_NEGATIVE_NO_UDP=false.
  if [[ "${RUN_NEGATIVE_NO_UDP}" == "true" ]]; then
    log "==> Case: negative (no UDP Service port; expect HTTP/3 failure)"
    run_quic_negative_no_udp
  fi

  log "==> Case: single client"
  run_quic_client 2 1
  check_agent_logs

  log "==> Case: parallel clients"
  run_quic_client 1 3
  check_agent_logs

  log "==> Case: non-443 QUIC Service port (requires QUIC_TRACKING_MODE=2)"
  run_quic_non_443_port
}

run_quic_negative_no_udp() {
  if [[ "${RUN_NEGATIVE_NO_UDP}" != "true" ]]; then
    return 0
  fi

  # Ensure the server exists so we can reliably identify its IP for log assertions.
  if ! deploy_incluster_quic_server; then
    log ""
    log "ERROR: in-cluster QUIC server failed to start; cannot run negative test."
    return 3
  fi

  set_quic_service_tcp_only

  local quic_url="https://${QUIC_SERVER_NAME}.${QUIC_NAMESPACE}.svc.cluster.local/"
  local pod
  pod="quic-client-neg-$(date +%s)"

  local server_pod_ip=""
  local service_ip=""
  server_pod_ip="$(get_quic_server_pod_ip)"
  service_ip="$(get_quic_service_cluster_ip)"

  log "==> Negative test: HTTP/3 should FAIL when Service has no UDP/443"
  log "    URL: $quic_url"
  log "    Server pod IP: ${server_pod_ip:-unknown}"
  log "    Service ClusterIP: ${service_ip:-unknown}"

  START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Expect failure: no UDP listener in Service and --http3-only forbids fallback.
  run_client_pod "${QUIC_NAMESPACE}" "${pod}" "${CLIENT_IMAGE}" \
    curl --http3-only -sS -D- -o /dev/null -I --max-time "${CLIENT_TIMEOUT_SECONDS}" -4 -k "${quic_url}" >/dev/null

  wait_pod_done "${QUIC_NAMESPACE}" "${pod}" 180 || true
  client_logs="$(kubectl logs -n "${QUIC_NAMESPACE}" "${pod}" 2>/dev/null || true)"
  if [[ -n "${client_logs:-}" ]]; then
    log "$client_logs"
  fi

  local exit_code=""
  exit_code="$(kubectl get pod -n "${QUIC_NAMESPACE}" "${pod}" -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null || true)"
  if [[ "${exit_code:-}" == "0" ]]; then
    log ""
    log "FAIL: Negative test expected curl to fail, but it exited 0."
    return 1
  fi

  # Assert the agent did not report QUIC samples for this server/service since START_TS.
  sleep "$AGENT_LOG_WAIT_SECONDS"
  agent_logs_since="$(kubectl logs -n "$NETOBSERV_NAMESPACE" -l "$AGENT_LABEL" --since-time="$START_TS" 2>/dev/null || true)"
  if [[ -z "${agent_logs_since:-}" ]]; then
    agent_logs_since="$(kubectl logs -n "$NETOBSERV_NAMESPACE" -l "$AGENT_LABEL" --since=5m 2>/dev/null || true)"
  fi

  # Best-effort: match QUIC sample lines that mention our server pod IP or service ClusterIP on dst :443 and UDP.
  local needle1=""
  local needle2=""
  needle1="${server_pod_ip:+>${server_pod_ip}:443}"
  needle2="${service_ip:+>${service_ip}:443}"

  if echo "$agent_logs_since" | grep -E 'QUIC flow metrics sample' | grep -q 'p=17'; then
    if [[ -n "${needle1}" ]] && echo "$agent_logs_since" | grep -E 'QUIC flow metrics sample' | grep -q "${needle1}"; then
      log ""
      log "FAIL: Agent reported a QUIC sample to the server pod IP during the negative test."
      echo "$agent_logs_since" | grep -E 'QUIC flow metrics sample' | tail -n 50 || true
      return 1
    fi
    if [[ -n "${needle2}" ]] && echo "$agent_logs_since" | grep -E 'QUIC flow metrics sample' | grep -q "${needle2}"; then
      log ""
      log "FAIL: Agent reported a QUIC sample to the service ClusterIP during the negative test."
      echo "$agent_logs_since" | grep -E 'QUIC flow metrics sample' | tail -n 50 || true
      return 1
    fi
  fi

  if [[ "$DEBUG_KEEP_POD" != "true" ]]; then
    kubectl delete pod -n "${QUIC_NAMESPACE}" "${pod}" --ignore-not-found=true >/dev/null 2>&1 || true
  else
    log ""
    log "Note: DEBUG_KEEP_POD=true so the negative-test pod was not deleted: ${QUIC_NAMESPACE}/${pod}"
  fi

  log ""
  log "SUCCESS: Negative test passed (HTTP/3 failed as expected; no QUIC samples for the target)."
  log ""
  return 0
}

run_quic_non_443_port() {
  if ! is_pos_int "${QUIC_ALT_PORT}"; then
    log "ERROR: QUIC_ALT_PORT must be a positive integer (got: ${QUIC_ALT_PORT})"
    return 2
  fi
  if [[ "${QUIC_ALT_PORT}" == "443" ]]; then
    log "ERROR: QUIC_ALT_PORT must be != 443 for the non-443 port case."
    return 2
  fi

  # Enable any-port detection for this case, then restore to false to keep the default suite behavior.
  set_agent_quic_tracking_mode 2

  run_quic_client "${QUIC_REQUESTS}" "${QUIC_PARALLEL_CLIENTS}" "${QUIC_ALT_SERVER_NAME}" "${QUIC_ALT_PORT}"
  check_agent_logs_port "${QUIC_ALT_PORT}"

  set_agent_quic_tracking_mode 1
}

run_tcp_sanity() {
  local ns="$1"
  local pod="$2"
  local url="$3"
  local resolve_args_file="${4:-}"

  if [[ "${RUN_TCP_SANITY}" != "true" ]]; then
    return 0
  fi

  local resolve_args=()
  if [[ -n "${resolve_args_file:-}" && -f "${resolve_args_file}" ]]; then
    local a=""
    while IFS= read -r a; do
      [[ -n "${a:-}" ]] && resolve_args+=("${a}")
    done < "${resolve_args_file}"
  fi

  log "==> Sanity check: HTTPS over TCP to the same URL (no HTTP/3 flags)"
  run_client_pod "${ns}" "${pod}" "${CLIENT_IMAGE}" \
    curl -sS -o /dev/null -I \
      -w '__TCP_HEAD_RESULT__ http_version=%{http_version} status=%{response_code}\n' \
      --max-time "${CLIENT_TIMEOUT_SECONDS}" -4 -k \
      "${resolve_args[@]}" \
      "${url}" >/dev/null || true
  wait_pod_done "${ns}" "${pod}" 60 || true
  kubectl logs -n "${ns}" "${pod}" 2>/dev/null || true
  kubectl delete pod -n "${ns}" "${pod}" --ignore-not-found=true >/dev/null 2>&1 || true
  log ""
}

spawn_quic_client_pods() {
  # Args: ns pod_base parallel_count head_urls_file get_urls_file resolve_args_file
  local ns="$1"
  local pod_base="$2"
  local parallel="$3"
  local head_urls_file="$4"
  local get_urls_file="$5"
  local resolve_args_file="$6"

  local resolve_args=()
  local a=""
  while IFS= read -r a; do
    [[ -n "${a:-}" ]] && resolve_args+=("${a}")
  done < "${resolve_args_file}"

  local head_urls=()
  while IFS= read -r a; do
    [[ -n "${a:-}" ]] && head_urls+=("${a}")
  done < "${head_urls_file}"

  local get_urls=()
  while IFS= read -r a; do
    [[ -n "${a:-}" ]] && get_urls+=("${a}")
  done < "${get_urls_file}"

  local i=1
  while [[ "$i" -le "$parallel" ]]; do
    local head_pod="${pod_base}-${i}-head"
    local get_pod="${pod_base}-${i}-get"

    run_client_pod "${ns}" "${head_pod}" "${CLIENT_IMAGE}" \
      curl --http3-only -sS -o /dev/null -I \
        -w '__HEAD_RESULT__ http_version=%{http_version} status=%{response_code}\n' \
        --retry 2 --retry-delay 1 --retry-connrefused \
        --max-time "${CLIENT_TIMEOUT_SECONDS}" -4 -k \
        "${resolve_args[@]}" \
        "${head_urls[@]}" \
        >/dev/null

    run_client_pod "${ns}" "${get_pod}" "${CLIENT_IMAGE}" \
      curl --http3-only -sS -o /dev/null \
        -w '__GET_RESULT__ http_version=%{http_version} status=%{response_code} size=%{size_download}\n' \
        --retry 2 --retry-delay 1 --retry-connrefused \
        --max-time "${CLIENT_TIMEOUT_SECONDS}" -4 -k \
        "${resolve_args[@]}" \
        "${get_urls[@]}" \
        >/dev/null

    i=$((i+1))
  done
}

validate_quic_client_pods() {
  local ns="$1"
  local pod_base="$2"
  local parallel="$3"

  local failures=0
  local i=1
  while [[ "$i" -le "$parallel" ]]; do
    local pod=""
    for pod in "${pod_base}-${i}-head" "${pod_base}-${i}-get"; do
      if ! wait_pod_done "${ns}" "${pod}" 180; then
        log ""
        log "Warning: QUIC client pod did not complete within the timeout: ${ns}/${pod}"
        kubectl describe pod -n "${ns}" "${pod}" || true
      fi

      client_logs="$(kubectl logs -n "${ns}" "${pod}" 2>/dev/null || true)"
      [[ -n "${client_logs:-}" ]] && log "$client_logs"

      # Fail fast if the image doesn't actually support HTTP/3.
      if echo "${client_logs:-}" | grep -q "option --http3-only:.*does not support"; then
        log ""
        log "ERROR: The client image does not support HTTP/3, so no QUIC traffic was generated."
        log "Fix: set CLIENT_IMAGE to an HTTP/3-capable client."
        failures=$((failures+1))
        continue
      fi

      if [[ "${pod}" == *-head ]]; then
        if ! echo "${client_logs:-}" | grep -Eq '__HEAD_RESULT__.*http_version=3(\\.[0-9]+)?[[:space:]].*status=2[0-9]{2}'; then
          log ""
          log "ERROR: QUIC HEAD did not report http_version=3 and a 2xx status (${ns}/${pod})."
          log "==> Debug: HEAD result lines"
          echo "${client_logs:-}" | grep -E '__HEAD_RESULT__' | tail -n 10 || true
          failures=$((failures+1))
        fi
      else
        if ! echo "${client_logs:-}" | grep -Eq '__GET_RESULT__.*http_version=3(\\.[0-9]+)?[[:space:]].*status=2[0-9]{2}.*size=([1-9][0-9]*)(\\.[0-9]+)?'; then
          log ""
          log "ERROR: QUIC GET did not report http_version=3 with a 2xx and non-zero download size (${ns}/${pod})."
          log "==> Debug: GET result lines"
          echo "${client_logs:-}" | grep -E '__GET_RESULT__' | tail -n 10 || true
          failures=$((failures+1))
        fi
      fi

      exit_code="$(kubectl get pod -n "${ns}" "${pod}" -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null || true)"
      if [[ "${exit_code:-}" != "0" ]]; then
        local phase=""
        local reason=""
        local message=""
        phase="$(kubectl get pod -n "${ns}" "${pod}" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
        reason="$(kubectl get pod -n "${ns}" "${pod}" -o jsonpath='{.status.containerStatuses[0].state.terminated.reason}' 2>/dev/null || true)"
        message="$(kubectl get pod -n "${ns}" "${pod}" -o jsonpath='{.status.containerStatuses[0].state.terminated.message}' 2>/dev/null || true)"
        log ""
        log "==> Debug: QUIC client pod status (phase=${phase:-unknown}, exit_code=${exit_code:-unknown}, reason=${reason:-}, message=${message:-})"
        kubectl describe pod -n "${ns}" "${pod}" || true
        failures=$((failures+1))
      fi

      if [[ "$DEBUG_KEEP_POD" != "true" ]]; then
        kubectl delete pod -n "${ns}" "${pod}" --ignore-not-found=true >/dev/null 2>&1 || true
      fi
    done
    i=$((i+1))
  done

  if (( failures > 0 )); then
    log ""
    log "ERROR: ${failures} QUIC client pod(s) failed."
    log ""
    log "==> Debug: QUIC server logs (tail 200)"
    kubectl logs -n "${ns}" -l app="${QUIC_SERVER_NAME}" --tail=200 2>/dev/null || true
    log ""
    return 1
  fi
  return 0
}

run_quic_client() {
  local requests="${1:-${QUIC_REQUESTS}}"
  local parallel="${2:-${QUIC_PARALLEL_CLIENTS}}"
  local server_name="${3:-${QUIC_SERVER_NAME}}"
  local port="${4:-443}"

  if ! deploy_incluster_quic_server "${server_name}" "${port}"; then
    log ""
    log "ERROR: in-cluster QUIC server failed to start; cannot run QUIC client."
    return 3
  fi

  local quic_host="${server_name}.${QUIC_NAMESPACE}.svc.cluster.local"
  local quic_url="https://${quic_host}:${port}/"
  log "==> Generating QUIC (HTTP/3) traffic: $quic_url"
  log "    Using client image: $CLIENT_IMAGE"
  log "    requests=${requests}, parallel_clients=${parallel}"

  if ! is_pos_int "${requests}"; then
    log "ERROR: requests must be a positive integer (got: ${requests})"
    return 2
  fi
  if ! is_pos_int "${parallel}"; then
    log "ERROR: parallel_clients must be a positive integer (got: ${parallel})"
    return 2
  fi

  # Record a timestamp so we can query agent logs after the request.
  START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  local pod_base
  pod_base="quic-client-$(date +%s)"

  # Build resolve args and URL repetition as temporary files to keep the call sites simple
  # (and avoid passing arrays around in Bash 3).
  local tmp_dir
  tmp_dir="$(mktemp -d 2>/dev/null || mktemp -d -t quic)"
  local resolve_args_file="${tmp_dir}/resolve.args"
  local head_urls_file="${tmp_dir}/head.urls"
  local get_urls_file="${tmp_dir}/get.urls"

  build_resolve_args "${quic_host}" "${port}" "${server_name}" > "${resolve_args_file}" || true
  repeat_url_args "${quic_url}" "${requests}" > "${head_urls_file}"
  repeat_url_args "${quic_url}" "${requests}" > "${get_urls_file}"

  run_tcp_sanity "${QUIC_NAMESPACE}" "${pod_base}-tcp" "${quic_url}" "${resolve_args_file}" || true

  spawn_quic_client_pods "${QUIC_NAMESPACE}" "${pod_base}" "${parallel}" "${head_urls_file}" "${get_urls_file}" "${resolve_args_file}"
  validate_quic_client_pods "${QUIC_NAMESPACE}" "${pod_base}" "${parallel}"

  rm -rf "${tmp_dir}" >/dev/null 2>&1 || true
}

check_agent_logs_port() {
  local expected_port="${1:-443}"
  log "==> Checking agent logs for QUIC flow metrics marker"
  log "    (Looking for: \"QUIC flow metrics sample\" with quicFlowsLogged>0)"

  # Give the agent time to flush/merge maps (depends on cache timeout).
  sleep "$AGENT_LOG_WAIT_SECONDS"

  # Prefer --since-time; fall back to tail if unavailable.
  agent_logs_since="$(kubectl logs -n "$NETOBSERV_NAMESPACE" -l "$AGENT_LABEL" --since-time="$START_TS" 2>/dev/null || true)"
  if [[ -z "${agent_logs_since:-}" ]]; then
    agent_logs_since="$(kubectl logs -n "$NETOBSERV_NAMESPACE" -l "$AGENT_LABEL" --since=5m 2>/dev/null || true)"
  fi

  # Match any log line that contains the marker and a non-zero quicFlowsLogged field.
  # logrus usually formats as: ... msg="QUIC flow metrics sample" ... quicFlowsLogged=3 ...
  if echo "$agent_logs_since" | grep -E 'QUIC flow metrics sample' | grep -Eq 'quicFlowsLogged=([1-9][0-9]*)'; then
    log ""
    log "SUCCESS: Agent reports QUIC flows with metrics:"
    echo "$agent_logs_since" | grep -E 'QUIC flow metrics sample' | tail -n 20
    log ""
    log "==> QUIC flow metrics (sample)"
    echo "$agent_logs_since" | grep -E 'QUIC flow metrics sample' | tail -n 50 || true

    # Extra assertions for coverage: confirm the sample includes UDP (p=17) and port 443
    # (either src or dst, depending on which direction is sampled/logged).
    if ! echo "$agent_logs_since" | grep -E 'QUIC flow metrics sample' | grep -Eq 'p=17'; then
      log "FAIL: QUIC metrics sample did not include UDP transport (p=17)."
      return 1
    fi
    if ! echo "$agent_logs_since" | grep -E 'QUIC flow metrics sample' | grep -Eq "(:${expected_port}>|>:${expected_port}[[:space:]])"; then
      log "FAIL: QUIC metrics sample did not include a flow where src or dst port is ${expected_port}."
      log ""
      log "==> Debug: QUIC flow metrics sample (tail 20)"
      echo "$agent_logs_since" | grep -E 'QUIC flow metrics sample' | tail -n 20 || true
      return 1
    fi
    return 0
  fi

  log ""
  log "FAIL: Did not find QUIC flow metrics marker with quicFlowsLogged>0 since $START_TS."
  log ""
  log "==> Debug: recent agent log lines with 'QUIC flow metrics sample' (tail 200 overall)"
  kubectl logs -n "$NETOBSERV_NAMESPACE" -l "$AGENT_LABEL" --tail=200 2>/dev/null | grep -E 'QUIC flow metrics sample' || true
  log ""
  log "==> Debug: agent pods"
  kubectl get pods -n "$NETOBSERV_NAMESPACE" -l "$AGENT_LABEL" -o wide || true
  return 1
}

check_agent_logs() {
  check_agent_logs_port 443
}

main() {
  trap cleanup_quic_resources EXIT INT TERM

  kubectl cluster-info >/dev/null

  ensure_agent_exists
  run_suite
}

main
