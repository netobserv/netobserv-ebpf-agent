#!/usr/bin/env bash
set -euo pipefail

# Benchmark script to compare BPF performance between two agent images
#
# Usage:
#   ./scripts/benchmark-images.sh <image1> <image2> [options]
#
# Options:
#   --duration <seconds>    Duration to run each benchmark (default: 60)
#   --output-dir <dir>      Output directory for results (default: perf/benchmark-<timestamp>)
#   --keep-cluster          Keep KIND cluster after benchmark (default: cleanup)
#   --kubeconfig <file>     Use existing kubeconfig file (skips KIND cluster creation)
#   --help                  Show this help message
#
# Example:
#   ./scripts/benchmark-images.sh quay.io/user/agent:v1.0.0 quay.io/user/agent:v2.0.0 --duration 300

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-}"
DURATION="${DURATION:-300}"  # Default 300 seconds (5 minutes) for better averaging
WARMUP_PERIOD="${WARMUP_PERIOD:-180}"  # 180 seconds for agent and cluster stabilization
TRAFFIC_WARMUP="${TRAFFIC_WARMUP:-120}"  # 120 seconds for traffic to stabilize
CLUSTER_INIT_STABILIZE="${CLUSTER_INIT_STABILIZE:-120}"  # 120 seconds for initial cluster stabilization
KEEP_CLUSTER="${KEEP_CLUSTER:-false}"
EXISTING_KUBECONFIG="${EXISTING_KUBECONFIG:-}"
USE_EXISTING_CLUSTER=false
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
CLUSTER_NAME="benchmark-${TIMESTAMP}"
NAMESPACE1="netobserv-privileged-1"
NAMESPACE2="netobserv-privileged-2"
IPERF3_NAMESPACE="iperf3-traffic"

# Fixed iperf3 parameters for deterministic traffic generation
IPERF3_PARALLEL_STREAMS="${IPERF3_PARALLEL_STREAMS:-8}"  # Number of parallel streams
IPERF3_BANDWIDTH="${IPERF3_BANDWIDTH:-100M}"  # Bandwidth per stream
IPERF3_WINDOW_SIZE="${IPERF3_WINDOW_SIZE:-128K}"  # TCP window size
IPERF3_MSS="${IPERF3_MSS:-1460}"  # Maximum segment size (MTU - IP/TCP headers)
IPERF3_TEST_DURATION="${IPERF3_TEST_DURATION:-3600}"  # Test duration (infinite, restarted)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

show_help() {
    cat <<EOF
Benchmark script to compare BPF performance between two agent images

Usage:
    $0 <image1> <image2> [options]

Arguments:
    image1              First image to benchmark (baseline)
    image2              Second image to benchmark (comparison)

Options:
    --duration <sec>    Duration to run each benchmark in seconds (default: 300)
    --output-dir <dir>  Output directory for results (default: perf/benchmark-<timestamp>)
    --keep-cluster      Keep KIND cluster after benchmark instead of cleaning up
    --kubeconfig <file> Use existing kubeconfig file (skips KIND cluster creation)
    --help              Show this help message

Environment Variables (for advanced tuning):
    WARMUP_PERIOD       Agent warmup period in seconds (default: 180)
    TRAFFIC_WARMUP      Traffic stabilization period in seconds (default: 120)
    CLUSTER_INIT_STABILIZE  Initial cluster stabilization in seconds (default: 120)
    IPERF3_PARALLEL_STREAMS  Number of parallel iperf3 streams (default: 8)
    IPERF3_BANDWIDTH    Bandwidth per stream (default: 100M)
    IPERF3_WINDOW_SIZE  TCP window size (default: 128K)
    IPERF3_MSS          Maximum segment size (default: 1460)

Note: Benchmarks run SEQUENTIALLY in the same cluster. Each image is tested
      independently to ensure accurate statistics collection for all eBPF programs.

Examples:
    # Compare two images with default settings
    $0 quay.io/user/agent:v1.0.0 quay.io/user/agent:v2.0.0

    # Compare with custom duration
    $0 image1:tag image2:tag --duration 900

    # Keep cluster for debugging
    $0 image1:tag image2:tag --keep-cluster

    # Use existing cluster (skip KIND creation)
    $0 image1:tag image2:tag --kubeconfig ~/.kube/config
EOF
}

# Parse arguments
IMAGE1=""
IMAGE2=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --keep-cluster)
            KEEP_CLUSTER="true"
            shift
            ;;
        --kubeconfig)
            EXISTING_KUBECONFIG="$2"
            USE_EXISTING_CLUSTER=true
            shift 2
            ;;
        --help)
            show_help
            exit 0
            ;;
        -*)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
        *)
            if [[ -z "$IMAGE1" ]]; then
                IMAGE1="$1"
            elif [[ -z "$IMAGE2" ]]; then
                IMAGE2="$1"
            else
                log_error "Unexpected argument: $1"
                show_help
                exit 1
            fi
            shift
            ;;
    esac
done

if [[ -z "$IMAGE1" ]] || [[ -z "$IMAGE2" ]]; then
    log_error "Both image1 and image2 must be provided"
    show_help
    exit 1
fi

# Set output directory
if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="${PROJECT_ROOT}/perf/benchmark-$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$OUTPUT_DIR"

# Initialize kubeconfig file path
if [[ "$USE_EXISTING_CLUSTER" == "true" ]]; then
    if [[ ! -f "$EXISTING_KUBECONFIG" ]]; then
        log_error "Kubeconfig file not found: $EXISTING_KUBECONFIG"
        exit 1
    fi
    KUBECONFIG_FILE="$EXISTING_KUBECONFIG"
    log_info "Using existing kubeconfig: $KUBECONFIG_FILE"
    # Try to get cluster name from kubeconfig context
    CLUSTER_NAME=$(kubectl --kubeconfig="$KUBECONFIG_FILE" config view -o jsonpath='{.contexts[0].context.cluster}' 2>/dev/null || echo "existing-cluster")
else
    KUBECONFIG_FILE="${TMPDIR:-/tmp}/kubeconfig-${CLUSTER_NAME}"
fi

log_info "Starting parallel benchmark comparison"
log_info "  Image 1 (baseline): $IMAGE1"
log_info "  Image 2 (comparison): $IMAGE2"
log_info "  Duration: ${DURATION}s (measurement period)"
log_info "  Warmup period: ${WARMUP_PERIOD}s (agent stabilization)"
log_info "  Traffic warmup: ${TRAFFIC_WARMUP}s (traffic stabilization)"
log_info "  Cluster init stabilize: ${CLUSTER_INIT_STABILIZE}s"
log_info "  iperf3 parameters: -P ${IPERF3_PARALLEL_STREAMS} -b ${IPERF3_BANDWIDTH} -w ${IPERF3_WINDOW_SIZE} -M ${IPERF3_MSS}"
log_info "  Output directory: $OUTPUT_DIR"
log_info "  Cluster: $CLUSTER_NAME"
log_info "  Namespace 1 (image 1): $NAMESPACE1"
log_info "  Namespace 2 (image 2): $NAMESPACE2"
log_info "  Running agents SEQUENTIALLY in same cluster for accurate statistics collection"

# Check prerequisites
if ! command -v kubectl &> /dev/null; then
    log_error "kubectl is not installed. Please install it first."
    exit 1
fi

if [[ "$USE_EXISTING_CLUSTER" == "false" ]]; then
    if ! command -v kind &> /dev/null; then
        log_error "kind is not installed. Please install it first."
        exit 1
    fi
fi

# Increase file descriptor limits to prevent "too many open files" errors
# This is especially important when running parallel benchmarks
log_info "Checking and increasing file descriptor limits..."
CURRENT_ULIMIT=$(ulimit -n)
TARGET_ULIMIT=100000
if [[ $CURRENT_ULIMIT -lt $TARGET_ULIMIT ]]; then
    if ulimit -n $TARGET_ULIMIT 2>/dev/null; then
        log_info "  Increased file descriptor limit from $CURRENT_ULIMIT to $TARGET_ULIMIT"
    else
        log_warn "  Could not increase file descriptor limit (current: $CURRENT_ULIMIT)"
        log_warn "  This may cause 'too many open files' errors. Consider running: ulimit -n 100000"
    fi
else
    log_info "  File descriptor limit is already sufficient: $CURRENT_ULIMIT"
fi

# Cleanup function
cleanup() {
    log_info "Cleaning up benchmark resources..."
    
    # Clean up traffic generators and their namespace
    delete_traffic_generators
    
    # Clean up packet-counter (in default namespace)
    delete_packet_counter
    
    # Clean up agent namespaces
    log_info "Cleaning up agent namespaces..."
    kubectl delete namespace "$NAMESPACE1" --ignore-not-found=true --wait=false || true
    kubectl delete namespace "$NAMESPACE2" --ignore-not-found=true --wait=false || true
    
    # Wait a moment for namespace deletion to start
    sleep 2
    
    # Only clean up cluster if we created it (not using existing)
    if [[ "$USE_EXISTING_CLUSTER" == "false" ]]; then
        if [[ "$KEEP_CLUSTER" != "true" ]]; then
            log_info "Cleaning up KIND cluster..."
            kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
            rm -f "${KUBECONFIG_FILE:-}" 2>/dev/null || true
        else
            log_warn "Keeping cluster for inspection"
            log_info "To clean up manually:"
            log_info "  kind delete cluster --name $CLUSTER_NAME"
            log_info "  kubectl delete namespace $NAMESPACE1 $NAMESPACE2 $IPERF3_NAMESPACE"
            log_info "Kubeconfig file: ${KUBECONFIG_FILE:-}"
        fi
    else
        log_info "Using existing cluster - namespaces cleaned up"
    fi
}

trap cleanup EXIT

# Function to create a KIND cluster with retry logic
create_cluster() {
    local cluster_name=$1
    local kubeconfig_file=$2
    local max_retries=3
    local retry_count=0
    
    while [[ $retry_count -lt $max_retries ]]; do
        if [[ $retry_count -gt 0 ]]; then
            log_warn "Retrying cluster creation for $cluster_name (attempt $((retry_count + 1))/$max_retries)..."
            # Clean up any partial cluster from previous attempt
            kind delete cluster --name "$cluster_name" 2>/dev/null || true
            sleep 5
        fi
        
        log_info "Creating KIND cluster: $cluster_name"
        if cat <<EOF | kind create cluster --name "$cluster_name" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  podSubnet: 10.244.0.0/16
  serviceSubnet: 10.96.0.0/16
nodes:
- role: control-plane
- role: worker
EOF
        then
            # Export kubeconfig
            kind get kubeconfig --name "$cluster_name" > "$kubeconfig_file"
            
            # Wait for cluster to be ready
            log_info "Waiting for cluster $cluster_name to be ready..."
            if KUBECONFIG="$kubeconfig_file" kubectl wait --for=condition=Ready nodes --all --timeout=300s 2>&1; then
                # Wait for cluster metrics to stabilize
                log_info "Waiting for cluster $cluster_name metrics to stabilize (${CLUSTER_INIT_STABILIZE}s)..."
                sleep "$CLUSTER_INIT_STABILIZE"
                return 0
            else
                log_warn "Cluster $cluster_name created but nodes not ready, will retry..."
                kind delete cluster --name "$cluster_name" 2>/dev/null || true
            fi
        else
            log_warn "Failed to create cluster $cluster_name, will retry..."
        fi
        
        retry_count=$((retry_count + 1))
    done
    
    log_error "Failed to create cluster $cluster_name after $max_retries attempts"
    return 1
}

# Create cluster or use existing
if [[ "$USE_EXISTING_CLUSTER" == "true" ]]; then
    log_info "Using existing cluster from kubeconfig: $KUBECONFIG_FILE"
    # Verify cluster is accessible and connected
    log_info "Verifying cluster connection..."
    if ! kubectl --kubeconfig="$KUBECONFIG_FILE" cluster-info &>/dev/null; then
        log_error "Cannot access cluster using provided kubeconfig: $KUBECONFIG_FILE"
        log_error "Please ensure the cluster is accessible and you have proper credentials"
        exit 1
    fi
    # Verify we can actually query the cluster (not just that kubeconfig is valid)
    if ! kubectl --kubeconfig="$KUBECONFIG_FILE" get nodes &>/dev/null; then
        log_error "Cannot query cluster nodes - cluster may not be accessible or credentials may be invalid"
        log_error "Please verify cluster connectivity: kubectl --kubeconfig=\"$KUBECONFIG_FILE\" get nodes"
        exit 1
    fi
    log_success "Cluster connected and accessible"
else
    log_info "Creating KIND cluster..."
    if ! create_cluster "$CLUSTER_NAME" "$KUBECONFIG_FILE"; then
        log_error "Failed to create cluster ($CLUSTER_NAME)"
        exit 1
    fi
    log_success "Cluster created and stabilized"
fi

# Function to run benchmark for a single image
run_benchmark() {
    local image=$1
    local label=$2
    local output_file=$3
    local namespace=$4
    
    # Set KUBECONFIG for this benchmark
    export KUBECONFIG="$KUBECONFIG_FILE"
    
    log_info "[$namespace] Running benchmark for $label ($image)..."
    
    # Load image into kind (only for KIND clusters)
    if [[ "$USE_EXISTING_CLUSTER" == "false" ]]; then
        log_info "[$namespace] Loading image into KIND cluster..."
        docker pull "$image" || { log_error "[$namespace] Failed to pull image: $image"; return 1; }
        kind load docker-image "$image" --name "$CLUSTER_NAME"
    else
        log_info "[$namespace] Using existing cluster - assuming image is available in cluster registry"
        # For existing clusters, images should be available via registry or already loaded
        # User is responsible for ensuring images are accessible
    fi
    
    # Deploy packet-counter collector first
    if [[ "$namespace" == "$NAMESPACE1" ]]; then
        log_info "[$namespace] Deploying packet-counter collector..."
        deploy_packet_counter
    else
        log_info "[$namespace] Waiting for packet-counter to be ready (deployed by agent 1)..."
        sleep 5
    fi
    
    # Wait a moment for deployment to be created
    sleep 2
    
    # Wait for packet-counter deployment to be available
    log_info "[$namespace] Waiting for packet-counter to be ready..."
    if kubectl wait --for=condition=Available deployment/packet-counter -n default --timeout=60s 2>/dev/null; then
        log_success "[$namespace] Packet-counter is ready"
    else
        log_warn "[$namespace] Packet-counter deployment may not be ready, checking pod status..."
        # Try waiting for pod as fallback
        sleep 5
        kubectl wait --for=condition=Ready pod -l run=packet-counter -n default --timeout=30s 2>/dev/null || true
    fi
    sleep 3
    
    # Delete any existing agent deployment before deploying new one
    log_info "[$namespace] Cleaning up any existing agent deployment..."
    kubectl delete daemonset netobserv-ebpf-agent -n "$namespace" --ignore-not-found=true
    kubectl wait --for=delete pod -l k8s-app=netobserv-ebpf-agent -n "$namespace" --timeout=60s 2>/dev/null || true
    sleep 3  # Give time for cleanup
    
    # Check if we're on OpenShift and set up SCC if needed
    local is_openshift=false
    if kubectl get crd securitycontextconstraints.security.openshift.io &>/dev/null; then
        is_openshift=true
        log_info "[$namespace] Detected OpenShift cluster - setting up privileged SCC access..."
        
        # Create namespace with privileged pod security labels (if not exists)
        if ! kubectl get namespace "$namespace" &>/dev/null; then
            kubectl create namespace "$namespace"
        fi
        kubectl label namespace "$namespace" pod-security.kubernetes.io/enforce=privileged pod-security.kubernetes.io/audit=privileged --overwrite
        
        # Create service account
        kubectl create serviceaccount netobserv-ebpf-agent -n "$namespace" --dry-run=client -o yaml | kubectl apply -f -
        
        # Grant privileged SCC to service account
        if ! kubectl get clusterrole netobserv-ebpf-agent-privileged &>/dev/null; then
            log_info "[$namespace] Creating ClusterRole for privileged SCC..."
            cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: netobserv-ebpf-agent-privileged
rules:
  - apiGroups:
      - security.openshift.io
    resourceNames:
      - privileged
    resources:
      - securitycontextconstraints
    verbs:
      - use
EOF
        fi
        
        # Bind service account to cluster role
        kubectl create rolebinding netobserv-ebpf-agent-privileged \
            --clusterrole=netobserv-ebpf-agent-privileged \
            --serviceaccount="$namespace:netobserv-ebpf-agent" \
            --namespace="$namespace" \
            --dry-run=client -o yaml | kubectl apply -f -
        
        log_success "[$namespace] Privileged SCC access configured"
    fi
    
    # Deploy agent with this image in the specified namespace
    log_info "[$namespace] Deploying agent..."
    local service_account_spec=""
    if [[ "$is_openshift" == "true" ]]; then
        service_account_spec="serviceAccountName: netobserv-ebpf-agent"
    fi
    
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: $namespace
  labels:
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/audit: privileged
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: netobserv-ebpf-agent
  namespace: $namespace
spec:
  selector:
    matchLabels:
      k8s-app: netobserv-ebpf-agent
  template:
    metadata:
      labels:
        k8s-app: netobserv-ebpf-agent
    spec:
      ${service_account_spec}
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      affinity:
        podAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchLabels:
                    run: packet-counter
                topologyKey: kubernetes.io/hostname
      containers:
      - name: netobserv-ebpf-agent
        image: ${image}
        securityContext:
          privileged: true
          runAsUser: 0
        env:
          - name: GRPC_VERBOSITY
            value: DEBUG
          - name: GRPC_TRACE
            value: call_error,cares_resolver,dns_resolver
          # Use native DNS resolver instead of ares for better Kubernetes DNS support
          # - name: GRPC_DNS_RESOLVER
          #   value: "ares"
          - name: SAMPLING
            value: "1"
          - name: CACHE_ACTIVE_TIMEOUT
            value: 200ms
          - name: LOG_LEVEL
            value: info
          - name: TARGET_HOST
            value: "packet-counter.default.svc.cluster.local"
          - name: TARGET_PORT
            value: "9999"
          - name: ENABLE_RTT
            value: "true"
          - name: ENABLE_PKT_DROPS
            value: "true"
          - name: ENABLE_DNS_TRACKING
            value: "true"
        volumeMounts:
          - name: bpf-kernel-debug
            mountPath: /sys/kernel/debug
            mountPropagation: Bidirectional
      volumes:
        - name: bpf-kernel-debug
          hostPath:
            path: /sys/kernel/debug
            type: Directory
      tolerations:
        - key: node-role.kubernetes.io/control-plane
          operator: Exists
          effect: NoSchedule
EOF
    
    # Wait for agent to be ready
    log_info "[$namespace] Waiting for agent to be ready..."
    if ! kubectl wait --for=condition=Ready pod -l k8s-app=netobserv-ebpf-agent -n "$namespace" --timeout=120s 2>/dev/null; then
        log_error "[$namespace] Agent pod failed to become ready"
        log_info "[$namespace] Checking pod status..."
        kubectl get pods -l k8s-app=netobserv-ebpf-agent -n "$namespace" -o wide
        log_info "[$namespace] Checking pod events..."
        local agent_pod=$(kubectl get pods -l k8s-app=netobserv-ebpf-agent -n "$namespace" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
        if [[ -n "$agent_pod" ]]; then
            kubectl describe pod "$agent_pod" -n "$namespace" | tail -20
            log_info "[$namespace] Checking pod logs..."
            kubectl logs "$agent_pod" -n "$namespace" --tail=50 2>&1 || true
        fi
        return 1
    fi
    
    # Get pod name
    local pod_name=$(kubectl get pods -n "$namespace" -l k8s-app=netobserv-ebpf-agent -o jsonpath='{.items[0].metadata.name}')
    
    # Wait a moment for agent to fully load its programs
    sleep 3
    
    # Wait for agent to stabilize and cluster metrics to settle
    log_info "[$namespace] Waiting for agent and cluster metrics to stabilize (${WARMUP_PERIOD}s)..."
    sleep "$WARMUP_PERIOD"
    
    # Deploy traffic generators (only once, shared between agents)
    if [[ "$namespace" == "$NAMESPACE1" ]]; then
        log_info "[$namespace] Deploying traffic generators..."
        deploy_traffic_generators
    else
        log_info "[$namespace] Traffic generators already deployed by agent 1..."
        sleep 5
    fi
    
    # Wait for traffic generators to be ready
    log_info "[$namespace] Waiting for traffic generators to be ready..."
    kubectl wait --for=condition=Ready pod -l app=iperf3-server -n "$IPERF3_NAMESPACE" --timeout=60s || true
    kubectl wait --for=condition=Ready pod -l app=iperf3-client -n "$IPERF3_NAMESPACE" --timeout=60s || true
    
    # Wait for iperf3 clients to establish connections and start generating traffic
    log_info "[$namespace] Waiting for traffic generators to establish connections and start generating traffic (${TRAFFIC_WARMUP}s)..."
    sleep "$TRAFFIC_WARMUP"
    
    # Get packet-counter pod name for verification
    local packet_counter_pod=$(kubectl get pods -n default -l run=packet-counter -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    # Verify traffic is actually flowing before starting stats collection
    # Lower threshold to 100 packets/s and allow more time since packet-counter needs 60s window
    if ! verify_traffic_flowing "$packet_counter_pod" "$namespace" 100 15 10; then
        log_error "Traffic verification failed - iperf3 traffic generators may not be working"
        log_error "This will cause inaccurate benchmark results"
        log_error "Checking iperf3 client pod status..."
        kubectl get pods -l app=iperf3-client -n "$IPERF3_NAMESPACE" -o wide || true
        kubectl get pods -l app=iperf3-server -n "$IPERF3_NAMESPACE" -o wide || true
        log_error "Checking iperf3 client logs..."
        local client_pods=$(kubectl get pods -l app=iperf3-client -n "$IPERF3_NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
        if [[ -n "$client_pods" ]]; then
            for client_pod in $client_pods; do
                log_error "  Logs from $client_pod:"
                kubectl logs -n "$IPERF3_NAMESPACE" "$client_pod" --tail=20 2>&1 | head -10 || true
            done
        fi
        log_error "Failing benchmark run to prevent invalid results"
        log_error "Please ensure iperf3 traffic generators are working before running benchmarks"
        return 1
    fi
    
    # Additional wait to ensure agent is actively processing traffic before stats collection
    # This gives time for flows to accumulate and agent to be in steady state
    log_info "[$namespace] Waiting additional 30s to ensure agent is processing traffic steadily..."
    sleep 30
    
    # Collect kernel stats using collect-kernel-stats (collects all programs)
    log_info "[$namespace] Collecting kernel stats for ${DURATION}s using collect-kernel-stats..."
    local stats_cmd="/collect-kernel-stats --duration ${DURATION}s"
    
    if ! kubectl exec -n "$namespace" "$pod_name" -- test -f /collect-kernel-stats 2>/dev/null; then
        log_error "[$namespace] collect-kernel-stats binary not found in image: $image"
        log_error "[$namespace] The image must include the /collect-kernel-stats binary"
        return 1
    fi
    
    # Collect packet-counter logs in background
    # Use timeout to prevent hanging and ensure cleanup
    local packet_counter_logs="${output_file%.json}.packet-counter.log"
    if [[ -n "$packet_counter_pod" ]]; then
        log_info "[$namespace] Starting packet-counter log collection..."
        # Use timeout to ensure the log collection doesn't hang indefinitely
        # The timeout should be slightly longer than the measurement duration
        local timeout_seconds=$((DURATION + 60))
        timeout "$timeout_seconds" kubectl logs -n default "$packet_counter_pod" --tail=0 -f > "$packet_counter_logs" 2>&1 &
        local log_pid=$!
    fi
    
    # Run collect-kernel-stats and filter out log messages (lines starting with "time=")
    # to get only the JSON output
    # Use a temporary file to capture the raw output first
    local temp_output=$(mktemp)
    
    # Add timeout to kubectl exec to prevent hanging (DURATION + buffer for overhead)
    local exec_timeout=$((DURATION + 120))  # Add 2 minutes buffer for command overhead
    
    log_info "[$namespace] Running collect-kernel-stats with timeout of ${exec_timeout}s..."
    if timeout "$exec_timeout" kubectl exec -n "$namespace" "$pod_name" -- $stats_cmd > "$temp_output" 2>&1; then
        # Stop packet-counter log collection
        if [[ -n "${log_pid:-}" ]]; then
            kill "$log_pid" 2>/dev/null || true
            wait "$log_pid" 2>/dev/null || true
            sleep 1
        fi
        
        # Filter out log messages (lines starting with "time=") to get only JSON
        grep -v '^time=' "$temp_output" > "$output_file"
        rm -f "$temp_output"
        
        # Verify we got valid JSON (starts with {)
        if [[ ! -s "$output_file" ]] || ! head -n 1 "$output_file" | grep -q '^{'; then
            log_error "[$namespace] collect-kernel-stats did not produce valid JSON output"
            log_error "[$namespace] Output file contents:"
            cat "$output_file" >&2
            return 1
        fi
        
        # Extract packet-counter stats from logs
        if [[ -f "$packet_counter_logs" ]]; then
            extract_packet_counter_stats "$packet_counter_logs" "${output_file%.json}.packet-stats.json"
        fi
        
        log_success "[$namespace] Stats collected successfully"
        log_success "[$namespace] Benchmark completed for $label"
        return 0
    else
        local exit_code=$?
        # Stop packet-counter log collection on error
        if [[ -n "${log_pid:-}" ]]; then
            kill "$log_pid" 2>/dev/null || true
            wait "$log_pid" 2>/dev/null || true
        fi
        
        # Check if timeout killed the command (exit code 124)
        if [[ $exit_code -eq 124 ]]; then
            log_error "[$namespace] collect-kernel-stats timed out after ${exec_timeout}s"
            log_error "[$namespace] The command exceeded the timeout duration. This may indicate:"
            log_error "[$namespace]   - The collect-kernel-stats command is hanging"
            log_error "[$namespace]   - Network issues preventing kubectl exec from completing"
            log_error "[$namespace]   - The pod may be unresponsive"
        else
            log_error "[$namespace] collect-kernel-stats failed with exit code $exit_code"
        fi
        log_error "[$namespace] Raw output:"
        cat "$temp_output" >&2
        rm -f "$temp_output"
        return 1
    fi
}

# Collect cluster information (nodes, instance types, etc.)
collect_cluster_info() {
    local output_file=$1
    log_info "Collecting cluster information..."
    
    # Get node information
    local nodes_json=$(kubectl get nodes -o json 2>/dev/null || echo "{}")
    
    if [[ "$nodes_json" == "{}" ]]; then
        log_warn "Could not collect cluster information"
        return 1
    fi
    
    # Extract node information using jq if available, otherwise use kubectl
    if command -v jq &> /dev/null; then
        local num_nodes=$(echo "$nodes_json" | jq '.items | length' 2>/dev/null || echo "0")
        # Use jq with proper handling of optional fields using try-catch
        local node_info=$(echo "$nodes_json" | jq -r '.items[] | {
            name: .metadata.name,
            instance_type: (.metadata.labels."node.kubernetes.io/instance-type" // .metadata.labels."beta.kubernetes.io/instance-type" // "unknown"),
            zone: (.metadata.labels."topology.kubernetes.io/zone" // .metadata.labels."failure-domain.beta.kubernetes.io/zone" // "unknown"),
            arch: .status.nodeInfo.architecture,
            os: .status.nodeInfo.operatingSystem,
            kernel: .status.nodeInfo.kernelVersion,
            kubelet: .status.nodeInfo.kubeletVersion,
            cpu: .status.capacity.cpu,
            memory: .status.capacity.memory,
            pods: .status.capacity.pods
        }' 2>/dev/null | jq -s '.' 2>/dev/null || echo "[]")
        
        # Create cluster info JSON
        cat > "$output_file" <<EOF
{
  "num_nodes": $num_nodes,
  "cluster_name": "${CLUSTER_NAME}",
  "cluster_type": "$([ "$USE_EXISTING_CLUSTER" == "true" ] && echo "existing" || echo "kind")",
  "nodes": $node_info
}
EOF
    else
        # Fallback: use kubectl to get basic info
        local num_nodes=$(kubectl get nodes --no-headers 2>/dev/null | wc -l)
        local node_names=$(kubectl get nodes -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | tr ' ' ',')
        local instance_types=$(kubectl get nodes -o jsonpath='{.items[*].metadata.labels.node\.kubernetes\.io/instance-type}' 2>/dev/null || \
                               kubectl get nodes -o jsonpath='{.items[*].metadata.labels.beta\.kubernetes\.io/instance-type}' 2>/dev/null || \
                               echo "unknown")
        
        cat > "$output_file" <<EOF
{
  "num_nodes": $num_nodes,
  "cluster_name": "${CLUSTER_NAME}",
  "cluster_type": "$([ "$USE_EXISTING_CLUSTER" == "true" ] && echo "existing" || echo "kind")",
  "node_names": "$node_names",
  "instance_types": "$instance_types"
}
EOF
    fi
    
    log_success "Cluster information collected: $num_nodes nodes"
    return 0
}

# Deploy packet-counter collector
deploy_packet_counter() {
    log_info "Setting up packet-counter collector..."
    
    # Try to pull and load packet-counter image into kind (only for KIND clusters)
    local packet_counter_image="quay.io/mmaciasl/packet-counter-collector:main"
    if [[ "$USE_EXISTING_CLUSTER" == "false" ]]; then
        if docker pull "$packet_counter_image" 2>/dev/null; then
            log_info "Loading packet-counter image into KIND cluster..."
            kind load docker-image "$packet_counter_image" --name "$CLUSTER_NAME" 2>/dev/null || true
        else
            log_warn "Could not pull packet-counter image, will rely on cluster pull"
        fi
    else
        log_info "Using existing cluster - assuming packet-counter image is available in cluster registry"
    fi
    
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: packet-counter
  namespace: default
  labels:
    run: packet-counter
spec:
  ports:
    - port: 9999
      protocol: TCP
      targetPort: 9999
  selector:
    run: packet-counter
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: packet-counter
  namespace: default
  labels:
    run: packet-counter
spec:
  selector:
    matchLabels:
      run: packet-counter
  replicas: 1
  template:
    metadata:
      labels:
        run: packet-counter
    spec:
      containers:
        - name: packet-counter
          image: quay.io/mmaciasl/packet-counter-collector:main
          imagePullPolicy: Always
          ports:
            - containerPort: 9999
          resources:
            limits:
              memory: "512Mi"
              cpu: "1000m"
            requests:
              memory: "256Mi"
              cpu: "500m"
          securityContext:
            # Increase file descriptor limit in container
            # This prevents "too many open files" errors
            runAsNonRoot: false
            capabilities:
              add:
                - NET_ADMIN
                - NET_RAW
                - SYS_ADMIN
      tolerations:
        - key: node-role.kubernetes.io/control-plane
          operator: Exists
          effect: NoSchedule
EOF
    
    # Note: ulimit cannot be set from outside the container in Kubernetes
    # The packet-counter container image needs to set ulimit -n 100000 in its startup script
    # or entrypoint. If the container is hitting "too many open files" errors, the image
    # needs to be updated to increase the file descriptor limit.
    log_info "Packet-counter deployment created"
    log_info "Note: If you see 'too many open files' errors, the packet-counter"
    log_info "container image needs to set 'ulimit -n 100000' in its entrypoint"
}

# Verify traffic is flowing by checking packet-counter logs
verify_traffic_flowing() {
    local packet_counter_pod=$1
    local namespace=$2
    local min_packets_per_sec=${3:-1000}  # Default minimum: 1000 packets/s
    local max_attempts=${4:-10}           # Maximum verification attempts
    local wait_seconds=${5:-10}           # Wait between attempts
    
    if [[ -z "$packet_counter_pod" ]]; then
        log_warn "  Cannot verify traffic: packet-counter pod not found"
        return 1
    fi
    
    log_info "  Verifying traffic is flowing (min ${min_packets_per_sec} packets/s)..."
    
    # First check if packet-counter is actually receiving connections from agent
    log_info "  Checking if agent is connected to packet-counter..."
    local packet_counter_logs=$(kubectl logs -n default "$packet_counter_pod" --tail=50 2>/dev/null || echo "")
    if [[ -z "$packet_counter_logs" ]] || ! echo "$packet_counter_logs" | grep -q "starting flow collector"; then
        log_warn "  Packet-counter may not be fully started yet"
    fi
    
    # Check if we're seeing any iperf3 traffic (port 5201) in the flows
    local iperf3_flows=$(echo "$packet_counter_logs" | grep ":5201" | wc -l || echo "0")
    if [[ $iperf3_flows -gt 0 ]]; then
        log_info "  Found $iperf3_flows flow entries with port 5201 (iperf3 traffic detected)"
    else
        log_warn "  No iperf3 traffic (port 5201) detected in packet-counter flows yet"
    fi
    
    # Check agent logs to see if it's sending flows (only check current namespace)
    if [[ -n "$namespace" ]]; then
        local agent_pod=$(kubectl get pods -n "$namespace" -l k8s-app=netobserv-ebpf-agent -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
        if [[ -n "$agent_pod" ]]; then
            log_info "  Checking agent status in namespace $namespace..."
            local agent_logs=$(kubectl logs -n "$namespace" "$agent_pod" --tail=20 2>/dev/null || echo "")
            if echo "$agent_logs" | grep -q "couldn't send flow records"; then
                log_warn "  Agent appears to have connection issues with packet-counter"
            fi
            if echo "$agent_logs" | grep -q "connection error\|connection refused\|Unavailable"; then
                log_warn "  Agent may not be able to connect to packet-counter"
            fi
        fi
    fi
    
    local attempt=1
    while [[ $attempt -le $max_attempts ]]; do
        # Get recent packet-counter logs and look for rate statistics
        # Use larger window (100 lines) to catch rate statistics that may appear less frequently
        local recent_logs=$(kubectl logs -n default "$packet_counter_pod" --tail=100 2>/dev/null || echo "")
        
        if [[ -z "$recent_logs" ]]; then
            log_warn "  Attempt $attempt/$max_attempts: No logs from packet-counter yet, waiting ${wait_seconds}s..."
            sleep "$wait_seconds"
            ((attempt++))
            continue
        fi
        
        # Try to find rate statistics in either format:
        # Format 1: "2025/11/05 10:34:04 === TOTAL RATE: 6783.6 packets/s 335.0 flows/s 196510951.0 bytes/s"
        # Format 2: "2025/11/05 10:34:04 6783.6 packets/s. 335.0 flows/s"
        local latest_rate=$(echo "$recent_logs" | grep -E "(=== TOTAL RATE:|packets/s\.)" | tail -1)
        
        if [[ -z "$latest_rate" ]]; then
            # Check if we're at least seeing flow entries (even without rate stats)
            local flow_entries=$(echo "$recent_logs" | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:" | wc -l || echo "0")
            local iperf3_in_flows=$(echo "$recent_logs" | grep ":5201" | wc -l || echo "0")
            
            # Show some diagnostic info on first few attempts
            if [[ $attempt -le 3 ]]; then
                log_info "  Attempt $attempt/$max_attempts: No rate statistics found yet"
                log_info "  Flow entries in logs: $flow_entries (iperf3 flows: $iperf3_in_flows)"
                if [[ $flow_entries -gt 0 ]]; then
                    log_info "  Packet-counter is receiving flows but rate statistics not available yet"
                    log_info "  Packet-counter logs (last 3 lines):"
                    echo "$recent_logs" | tail -3 | sed 's/^/    /' || true
                else
                    log_info "  Packet-counter logs (last 3 lines):"
                    echo "$recent_logs" | tail -3 | sed 's/^/    /' || true
                fi
            elif [[ $attempt -eq 5 ]]; then
                log_warn "  Attempt $attempt/$max_attempts: No rate statistics found yet"
                log_warn "  Flow entries seen: $flow_entries (iperf3 flows: $iperf3_in_flows)"
                if [[ $iperf3_in_flows -gt 0 ]]; then
                    log_info "  iperf3 traffic detected in flows, but rate stats not logging yet"
                    log_info "  This may be normal - packet-counter logs rates every 5 seconds"
                fi
            else
                log_warn "  Attempt $attempt/$max_attempts: No rate statistics found yet, waiting ${wait_seconds}s..."
            fi
            sleep "$wait_seconds"
            ((attempt++))
            continue
        fi
        
        # Extract packets/s from the rate line (handle both formats)
        local packets_per_sec="0"
        if echo "$latest_rate" | grep -q "=== TOTAL RATE:"; then
            # Format 1: "=== TOTAL RATE: 6783.6 packets/s ..."
            packets_per_sec=$(echo "$latest_rate" | sed -n 's/.*TOTAL RATE: \([0-9.]*\) packets\/s.*/\1/p' || echo "0")
        elif echo "$latest_rate" | grep -q "packets/s\."; then
            # Format 2: "6783.6 packets/s. ..."
            packets_per_sec=$(echo "$latest_rate" | sed -n 's/.* \([0-9.]*\) packets\/s\..*/\1/p' || echo "0")
        fi
        
        # Convert to integer for comparison (using awk to handle floating point)
        local packets_int=$(echo "$packets_per_sec" | awk '{printf "%.0f", $1}' 2>/dev/null || echo "0")
        local min_int=$(echo "$min_packets_per_sec" | awk '{printf "%.0f", $1}' 2>/dev/null || echo "1000")
        
        if [[ -z "$packets_per_sec" ]] || [[ "$packets_per_sec" == "0" ]] || [[ "$packets_int" == "0" ]]; then
            log_warn "  Attempt $attempt/$max_attempts: Traffic rate is 0 packets/s, waiting ${wait_seconds}s..."
            if [[ $attempt -eq 5 ]]; then
                log_warn "  Showing packet-counter logs for diagnostics:"
                kubectl logs -n default "$packet_counter_pod" --tail=10 2>/dev/null | sed 's/^/    /' || true
            fi
            sleep "$wait_seconds"
            ((attempt++))
            continue
        fi
        
        if [[ $packets_int -ge $min_int ]]; then
            log_success "  Traffic verified: ${packets_per_sec} packets/s (threshold: ${min_packets_per_sec} packets/s)"
            return 0
        else
            # If we have some traffic but below threshold, check if iperf3 is actually flowing
            local iperf3_check=$(echo "$recent_logs" | grep ":5201" | head -1 || echo "")
            if [[ -n "$iperf3_check" ]]; then
                log_warn "  Attempt $attempt/$max_attempts: Traffic rate ${packets_per_sec} packets/s is below threshold ${min_packets_per_sec} packets/s"
                log_info "  iperf3 traffic detected in flows, but rate may be too low"
            else
                log_warn "  Attempt $attempt/$max_attempts: Traffic rate ${packets_per_sec} packets/s is below threshold ${min_packets_per_sec} packets/s"
                log_warn "  No iperf3 traffic (port 5201) detected in recent flows"
            fi
            sleep "$wait_seconds"
            ((attempt++))
        fi
    done
    
    log_error "  Traffic verification failed after $max_attempts attempts"
    log_error "  Last packet-counter logs:"
    kubectl logs -n default "$packet_counter_pod" --tail=10 2>/dev/null | sed 's/^/    /' || true
    
    # Final check: Only allow proceeding if we have significant traffic AND iperf3 flows
    # Check a larger window (500 lines) to account for flow accumulation over time
    local final_logs=$(kubectl logs -n default "$packet_counter_pod" --tail=500 2>/dev/null || echo "")
    local final_iperf3=$(echo "$final_logs" | grep ":5201" | wc -l || echo "0")
    local final_flows=$(echo "$final_logs" | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:" | wc -l || echo "0")
    
    # Require at least 20 iperf3 flows AND 200 total flows to ensure sufficient traffic
    # (Reduced thresholds to account for flow accumulation time and log window size)
    if [[ $final_iperf3 -ge 20 ]] && [[ $final_flows -ge 200 ]]; then
        log_warn "  However, detected $final_flows total flows ($final_iperf3 with iperf3) in packet-counter logs"
        log_warn "  Packet-counter may need more time to accumulate rate statistics (60s window)"
        log_warn "  Proceeding with benchmark - significant traffic detected"
        return 0  # Allow to proceed only with significant traffic
    else
        log_error "  Insufficient traffic detected: $final_flows total flows ($final_iperf3 with iperf3)"
        log_error "  Required: at least 20 iperf3 flows and 200 total flows (checked last 500 log lines)"
    fi
    
    log_error "  This may indicate:"
    log_error "    1. iperf3 traffic generators are not working properly"
    log_error "    2. Agent is not capturing/sending flows to packet-counter"
    log_error "    3. Network connectivity issues between agent and packet-counter"
    return 1
}

# Extract packet-counter stats from logs
extract_packet_counter_stats() {
    local log_file=$1
    local output_file=$2
    
    if [[ ! -f "$log_file" ]]; then
        return 1
    fi
    
    # Extract all rate lines and calculate averages
    # Format 1: "2025/11/05 10:34:04 === TOTAL RATE: 3.5 packets/s 2.2 flows/s 659.7 bytes/s"
    # Format 2: "2025/11/05 10:34:04 3.5 packets/s. 2.2 flows/s"
    local rates=$(grep -E "(=== TOTAL RATE:|packets/s\.)" "$log_file" | \
        sed -n -e 's/.*TOTAL RATE: \([0-9.]*\) packets\/s \([0-9.]*\) flows\/s \([0-9.]*\) bytes\/s.*/\1 \2 \3/p' \
               -e 's/.* \([0-9.]*\) packets\/s\. \([0-9.]*\) flows\/s.*/\1 \2 0/p' | \
        grep -v "^$" || echo "")
    
    if [[ -z "$rates" ]]; then
        log_warn "  No packet-counter stats found in logs"
        return 1
    fi
    
    # Calculate averages using awk
    local avg_packets=$(echo "$rates" | awk '{sum+=$1; count++} END {if(count>0) print sum/count; else print "0"}')
    local avg_flows=$(echo "$rates" | awk '{sum+=$2; count++} END {if(count>0) print sum/count; else print "0"}')
    local avg_bytes=$(echo "$rates" | awk '{sum+=$3; count++} END {if(count>0) print sum/count; else print "0"}')
    
    # Get min and max for range
    local min_packets=$(echo "$rates" | awk '{if(NR==1 || $1<min) min=$1} END {print min+0}')
    local max_packets=$(echo "$rates" | awk '{if(NR==1 || $1>max) max=$1} END {print max+0}')
    local min_flows=$(echo "$rates" | awk '{if(NR==1 || $2<min) min=$2} END {print min+0}')
    local max_flows=$(echo "$rates" | awk '{if(NR==1 || $2>max) max=$2} END {print max+0}')
    
    # Create JSON output
    cat > "$output_file" <<EOF
{
  "avg_packets_per_sec": $avg_packets,
  "avg_flows_per_sec": $avg_flows,
  "avg_bytes_per_sec": $avg_bytes,
  "min_packets_per_sec": $min_packets,
  "max_packets_per_sec": $max_packets,
  "min_flows_per_sec": $min_flows,
  "max_flows_per_sec": $max_flows,
  "sample_count": $(echo "$rates" | wc -l)
}
EOF
    
    log_info "  Packet-counter stats extracted: ${avg_packets} packets/s, ${avg_flows} flows/s, ${avg_bytes} bytes/s"
}

# Delete packet-counter collector
delete_packet_counter() {
    log_info "Cleaning up packet-counter collector..."
    kubectl delete deployment packet-counter -n default --ignore-not-found=true
    kubectl delete service packet-counter -n default --ignore-not-found=true
    sleep 2
}

# Deploy traffic generators (iperf3) to generate network traffic
deploy_traffic_generators() {
    log_info "Setting up iperf3 traffic generators in namespace: $IPERF3_NAMESPACE..."
    # Create namespace first
    kubectl create namespace "$IPERF3_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Wait for namespace to be ready before deploying resources
    log_info "Waiting for namespace $IPERF3_NAMESPACE to be ready..."
    local max_attempts=10
    local attempt=1
    while [[ $attempt -le $max_attempts ]]; do
        if kubectl get namespace "$IPERF3_NAMESPACE" &>/dev/null; then
            # Namespace exists, check if it's active (not terminating)
            local phase=$(kubectl get namespace "$IPERF3_NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
            if [[ "$phase" == "Active" ]]; then
                log_info "Namespace $IPERF3_NAMESPACE is ready"
                break
            fi
        fi
        if [[ $attempt -eq $max_attempts ]]; then
            log_error "Failed to create or verify namespace $IPERF3_NAMESPACE after $max_attempts attempts"
            return 1
        fi
        sleep 1
        ((attempt++))
    done
    
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: iperf3-server
  namespace: ${IPERF3_NAMESPACE}
  labels:
    app: iperf3-server
spec:
  ports:
    - port: 5201
      protocol: TCP
      targetPort: 5201
  selector:
    app: iperf3-server
---
apiVersion: v1
kind: Service
metadata:
  name: iperf3-server-headless
  namespace: ${IPERF3_NAMESPACE}
spec:
  clusterIP: None
  selector:
    app: iperf3-server
  ports:
    - port: 5201
      protocol: TCP
      targetPort: 5201
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: iperf3-server
  namespace: ${IPERF3_NAMESPACE}
spec:
  serviceName: iperf3-server-headless
  replicas: 2
  selector:
    matchLabels:
      app: iperf3-server
  template:
    metadata:
      labels:
        app: iperf3-server
    spec:
      containers:
        - name: iperf3-server
          image: mlabbe/iperf3:latest
          ports:
            - containerPort: 5201
          command:
            - iperf3
            - -s
          resources:
            requests:
              memory: "64Mi"
              cpu: "100m"
            limits:
              memory: "128Mi"
              cpu: "500m"
          livenessProbe:
            tcpSocket:
              port: 5201
            initialDelaySeconds: 10
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 3
          readinessProbe:
            tcpSocket:
              port: 5201
            initialDelaySeconds: 5
            periodSeconds: 5
            timeoutSeconds: 3
      restartPolicy: Always
      affinity:
        podAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchLabels:
                    k8s-app: netobserv-ebpf-agent
                topologyKey: kubernetes.io/hostname
      tolerations:
        - key: node-role.kubernetes.io/control-plane
          operator: Exists
          effect: NoSchedule
---
apiVersion: v1
kind: Service
metadata:
  name: iperf3-client-headless
  namespace: ${IPERF3_NAMESPACE}
spec:
  clusterIP: None
  selector:
    app: iperf3-client
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: iperf3-client
  namespace: ${IPERF3_NAMESPACE}
spec:
  serviceName: iperf3-client-headless
  replicas: 2
  selector:
    matchLabels:
      app: iperf3-client
  template:
    metadata:
      labels:
        app: iperf3-client
    spec:
      containers:
        - name: iperf3-client
          image: mlabbe/iperf3:latest
          command:
            - /bin/sh
            - -c
            - |
              # Wait for servers to be ready
              sleep 15
              
              # Get this pod's index from hostname (StatefulSet pods are named like iperf3-client-0, iperf3-client-1)
              POD_NAME=\$(hostname)
              POD_INDEX=\${POD_NAME##*-}
              
              # Map client pod to server pod (1:1 mapping to avoid conflicts)
              # Client pod-0 connects to server-0, client pod-1 to server-1, etc.
              # Use headless service DNS: iperf3-server-<index>.iperf3-server-headless.<namespace>.svc.cluster.local
              SERVER_HOST="iperf3-server-\${POD_INDEX}.iperf3-server-headless.${IPERF3_NAMESPACE}.svc.cluster.local"
              
              # Wait for specific server pod to be ready (check DNS resolution)
              echo "Waiting for server: \$SERVER_HOST"
              for i in \$(seq 1 30); do
                if nslookup \$SERVER_HOST &>/dev/null || ping -c 1 \$SERVER_HOST &>/dev/null; then
                  echo "Found server at \$SERVER_HOST"
                  break
                fi
                sleep 2
              done
              
              # Generate consistent traffic with fixed parameters
              # Use long test duration for steady, continuous traffic
              while true; do
                echo "Starting iperf3 test to \$SERVER_HOST - client-\${POD_INDEX} to server-\${POD_INDEX}"
                # Run continuous test - each client connects to its dedicated server
                iperf3 -c \$SERVER_HOST \
                    -t 3600 \
                    -P "${IPERF3_PARALLEL_STREAMS}" \
                    -b "${IPERF3_BANDWIDTH}" \
                    -w "${IPERF3_WINDOW_SIZE}" \
                    -M "${IPERF3_MSS}" \
                    --connect-timeout 10000 \
                    --no-delay \
                    --get-server-output || {
                  echo "iperf3 test failed, waiting before retry..."
                  sleep 10
                }
                # Small delay before restarting
                sleep 1
              done
          resources:
            requests:
              memory: "32Mi"
              cpu: "50m"
            limits:
              memory: "128Mi"
              cpu: "1000m"
      affinity:
        podAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchLabels:
                    app: iperf3-server
                topologyKey: kubernetes.io/hostname
      tolerations:
        - key: node-role.kubernetes.io/control-plane
          operator: Exists
          effect: NoSchedule
EOF
}

# Delete traffic generators
delete_traffic_generators() {
    log_info "Cleaning up traffic generators..."
    kubectl delete statefulset iperf3-server iperf3-client -n "$IPERF3_NAMESPACE" --ignore-not-found=true || true
    kubectl delete service iperf3-server iperf3-server-headless iperf3-client-headless -n "$IPERF3_NAMESPACE" --ignore-not-found=true || true
    kubectl delete namespace "$IPERF3_NAMESPACE" --ignore-not-found=true || true
    sleep 3
}

# Delete existing agent before deploying new one
delete_agent() {
    local namespace=$1
    log_info "[$namespace] Deleting existing agent deployment..."
    kubectl delete daemonset netobserv-ebpf-agent -n "$namespace" --ignore-not-found=true
    kubectl wait --for=delete pod -l k8s-app=netobserv-ebpf-agent -n "$namespace" --timeout=60s || true
    sleep 5
}

# Run benchmarks sequentially
OUTPUT_FILE1="${OUTPUT_DIR}/kernel-stats-image1.json"
OUTPUT_FILE2="${OUTPUT_DIR}/kernel-stats-image2.json"
CLUSTER_INFO_FILE="${OUTPUT_DIR}/cluster-info.json"

# Ensure output directory exists before writing log files
mkdir -p "$OUTPUT_DIR"

# Collect cluster information once (shared between both benchmarks)
log_info "Collecting cluster information..."
if ! collect_cluster_info "$CLUSTER_INFO_FILE"; then
    log_warn "Failed to collect cluster information, continuing without it..."
fi

# Run benchmarks sequentially in the same cluster
log_info "Starting sequential benchmarks in single cluster..."

# Run benchmark 1
log_info "=== Running benchmark for Image 1 (baseline) ==="
if ! run_benchmark "$IMAGE1" "Image 1 - baseline" "$OUTPUT_FILE1" "$NAMESPACE1" > "${OUTPUT_DIR}/benchmark-image1.log" 2>&1; then
    log_error "Benchmark for image 1 failed"
    log_info "Check logs: ${OUTPUT_DIR}/benchmark-image1.log"
    exit 1
fi
log_success "Benchmark for Image 1 completed successfully"

# Clean up agent 1 before starting agent 2
log_info "Cleaning up Image 1 agent before starting Image 2..."
delete_agent "$NAMESPACE1"
log_info "Waiting 30s for agent 1 to fully unload eBPF programs and cleanup..."
sleep 30  # Give time for eBPF programs to be unloaded and cleanup to complete

# Run benchmark 2
log_info "=== Running benchmark for Image 2 (comparison) ==="
if ! run_benchmark "$IMAGE2" "Image 2 - comparison" "$OUTPUT_FILE2" "$NAMESPACE2" > "${OUTPUT_DIR}/benchmark-image2.log" 2>&1; then
    log_error "Benchmark for image 2 failed"
    log_info "Check logs: ${OUTPUT_DIR}/benchmark-image2.log"
    exit 1
fi
log_success "Benchmark for Image 2 completed successfully"

log_success "Both benchmarks completed successfully"

# Generate comparison report
log_info "Generating comparison report..."
REPORT_GENERATED=false

if [[ ! -f "$OUTPUT_FILE1" ]]; then
    log_error "Cannot generate comparison report: Image 1 stats file missing: $OUTPUT_FILE1"
elif [[ ! -f "$OUTPUT_FILE2" ]]; then
    log_error "Cannot generate comparison report: Image 2 stats file missing: $OUTPUT_FILE2"
elif [[ ! -f "${SCRIPT_DIR}/compare-kernel-stats.py" ]]; then
    log_error "Comparison script not found: ${SCRIPT_DIR}/compare-kernel-stats.py"
else
    # Build packet stats arguments if files exist
    packet_stats_args=""
    if [[ -f "${OUTPUT_FILE1%.json}.packet-stats.json" ]]; then
        packet_stats_args="${packet_stats_args} --baseline-packet-stats ${OUTPUT_FILE1%.json}.packet-stats.json"
        log_info "  Including packet stats for image 1"
    fi
    if [[ -f "${OUTPUT_FILE2%.json}.packet-stats.json" ]]; then
        packet_stats_args="${packet_stats_args} --comparison-packet-stats ${OUTPUT_FILE2%.json}.packet-stats.json"
        log_info "  Including packet stats for image 2"
    fi
    
    # Use default labels if IMAGE1/IMAGE2 are not set (shouldn't happen, but safety check)
    baseline_label="${IMAGE1:-Image1}"
    comparison_label="${IMAGE2:-Image2}"
    if [[ "$baseline_label" != "Image1" ]] && [[ "$comparison_label" != "Image2" ]]; then
        baseline_label="$(basename "$IMAGE1")"
        comparison_label="$(basename "$IMAGE2")"
    fi
    
    log_info "  Generating report with baseline: $baseline_label, comparison: $comparison_label"
    
    if python3 "${SCRIPT_DIR}/compare-kernel-stats.py" \
        --baseline "$OUTPUT_FILE1" \
        --comparison "$OUTPUT_FILE2" \
        --output "${OUTPUT_DIR}/comparison-report.png" \
        --baseline-label "$baseline_label" \
        --comparison-label "$comparison_label" \
        $packet_stats_args 2>&1; then
        log_success "Comparison report generated successfully"
        REPORT_GENERATED=true
    else
        local exit_code=$?
        log_error "Comparison report generation failed with exit code: $exit_code"
        log_error "Attempting to run comparison script manually to see error:"
        python3 "${SCRIPT_DIR}/compare-kernel-stats.py" \
            --baseline "$OUTPUT_FILE1" \
            --comparison "$OUTPUT_FILE2" \
            --output "${OUTPUT_DIR}/comparison-report.png" \
            --baseline-label "$baseline_label" \
            --comparison-label "$comparison_label" \
            $packet_stats_args 2>&1 || true
    fi
fi

log_success "Benchmark completed!"
log_info "Results saved to: $OUTPUT_DIR"
log_info "  - Image 1 stats: $OUTPUT_FILE1"
log_info "  - Image 2 stats: $OUTPUT_FILE2"
if [[ -f "${OUTPUT_FILE1%.json}.packet-stats.json" ]]; then
    log_info "  - Image 1 packet stats: ${OUTPUT_FILE1%.json}.packet-stats.json"
fi
if [[ -f "${OUTPUT_FILE2%.json}.packet-stats.json" ]]; then
    log_info "  - Image 2 packet stats: ${OUTPUT_FILE2%.json}.packet-stats.json"
fi
if [[ -f "${OUTPUT_DIR}/comparison-report.png" ]]; then
    log_info "  - Comparison report: ${OUTPUT_DIR}/comparison-report.png"
else
    log_warn "  - Comparison report: NOT GENERATED (check errors above)"
fi

