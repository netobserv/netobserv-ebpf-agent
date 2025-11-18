#!/usr/bin/env bash
set +e

DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Default values
AGENT_IMAGE="${AGENT_IMAGE:-quay.io/netobserv/network-observability-ebpf-agent:latest}"
OPENSSL_PATH="${OPENSSL_PATH:-}"
CACHE_ACTIVE_TIMEOUT="${CACHE_ACTIVE_TIMEOUT:-5s}"
CACHE_MAX_FLOWS="${CACHE_MAX_FLOWS:-10000}"

# Function to detect OpenSSL path based on architecture
detect_openssl_path() {
  local ARCH=$(uname -m)
  
  if [ -n "$OPENSSL_PATH" ]; then
    echo "$OPENSSL_PATH"
    return
  fi
  
  # Default for OpenShift 4.20 / RHEL 9 is /usr/lib64/libssl.so.3
  # This works for both x86_64 and aarch64 architectures
  # For other distributions, set OPENSSL_PATH environment variable explicitly
  case $ARCH in
    x86_64|amd64)
      echo "/usr/lib64/libssl.so.3"
      ;;
    aarch64|arm64)
      echo "/usr/lib64/libssl.so.3"
      ;;
    *)
      echo "/usr/lib64/libssl.so.3"
      ;;
  esac
}

# Function to extract library directory from OpenSSL path
get_lib_dir() {
  local openssl_path=$1
  # Extract directory from path (e.g., /usr/lib64/libssl.so.3 -> /usr/lib64)
  dirname "$openssl_path"
}

# Function to check if running on OpenShift
is_openshift() {
  kubectl get securitycontextconstraints &>/dev/null
}

# Function to set up OpenShift permissions
setup_openshift_permissions() {
  local namespace="netobserv-privileged"
  local service_account="netobserv-ebpf-agent"
  
  echo "Setting up OpenShift Security Context Constraints..."
  
  # Ensure namespace exists (create if it doesn't)
  kubectl create namespace "$namespace" --dry-run=client -o yaml | kubectl apply -f -
  
  # Create service account if it doesn't exist
  kubectl create serviceaccount "$service_account" -n "$namespace" --dry-run=client -o yaml | kubectl apply -f -
  
  # Create ClusterRole for privileged SCC
  kubectl apply -f - <<EOF
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: netobserv-ebpf-agent-scc
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

  # Create RoleBinding
  kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: netobserv-ebpf-agent-scc
  namespace: $namespace
subjects:
  - kind: ServiceAccount
    name: $service_account
    namespace: $namespace
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: netobserv-ebpf-agent-scc
EOF

  # Update namespace to allow privileged pods
  kubectl label namespace "$namespace" \
    pod-security.kubernetes.io/enforce=privileged \
    pod-security.kubernetes.io/audit=privileged \
    --overwrite
  
  echo "OpenShift permissions configured successfully."
  echo ""
}

# Function to deploy the agent
deploy_agent() {
  local image=$1
  local openssl_path=$2
  local lib_dir=$(get_lib_dir "$openssl_path")
  local cache_timeout=$3
  local cache_max_flows=$4
  
  echo "Deploying NetObserv eBPF Agent"
  echo "  Image: $image"
  echo "  OpenSSL Path: $openssl_path"
  echo "  Library Directory: $lib_dir"
  echo "  Cache Active Timeout: $cache_timeout"
  echo "  Cache Max Flows: $cache_max_flows"
  echo ""
  
  # Create a temporary file with the modified agent.yml
  local temp_file=$(mktemp)
  trap "rm -f $temp_file" EXIT
  
  # Replace image, OpenSSL path, cache settings, and volume mount paths in agent.yml
  # Using | as delimiter in sed so / doesn't need escaping
  sed -e "s|^        image:.*|        image: $image|" \
      -e "s|value: \"/usr/lib.*libssl.so.*\"|value: \"$openssl_path\"|" \
      -e "/CACHE_ACTIVE_TIMEOUT/,/value:/s|value:.*|value: \"$cache_timeout\"|" \
      -e "s|mountPath: /usr/lib.*|mountPath: $lib_dir|" \
      -e "s|^            path: /usr/lib.*|            path: $lib_dir|" \
      "$DIR/agent.yml" > "$temp_file"
  
  # Handle CACHE_MAX_FLOWS - update if exists, add if not
  if grep -q "CACHE_MAX_FLOWS" "$temp_file"; then
    sed -i "/CACHE_MAX_FLOWS/,/value:/s|value:.*|value: \"$cache_max_flows\"|" "$temp_file"
  else
    # Add CACHE_MAX_FLOWS after CACHE_ACTIVE_TIMEOUT
    local temp_file2=$(mktemp)
    awk -v max_flows="$cache_max_flows" '/CACHE_ACTIVE_TIMEOUT/,/value:/ { print; if (/value:/) { print "          - name: CACHE_MAX_FLOWS"; print "            value: \"" max_flows "\"" } next }1' "$temp_file" > "$temp_file2"
    mv "$temp_file2" "$temp_file"
  fi
  
  # Add service account for OpenShift if needed
  if is_openshift; then
    # Add serviceAccountName to the pod spec if not already present
    if ! grep -q "serviceAccountName:" "$temp_file"; then
      # Insert serviceAccountName after dnsPolicy line (using a temporary file for portability)
      local temp_file2=$(mktemp)
      awk '/dnsPolicy: ClusterFirstWithHostNet/ { print; print "      serviceAccountName: netobserv-ebpf-agent"; next }1' "$temp_file" > "$temp_file2"
      mv "$temp_file2" "$temp_file"
    fi
  fi
  
  # Apply the configuration
  kubectl apply -f "$temp_file"
  
  echo ""
  echo "Waiting for agent pods to be ready..."
  kubectl wait --for=condition=ready pod \
    -l k8s-app=netobserv-ebpf-agent \
    -n netobserv-privileged \
    --timeout=120s || true
  
  echo ""
  echo "Agent deployment status:"
  kubectl get pods -n netobserv-privileged -l k8s-app=netobserv-ebpf-agent
}

# Function to deploy the collector
deploy_collector() {
  echo "Deploying NetObserv Collector (FlowLogs Pipeline)..."
  echo ""
  
  # Create a temporary file with the modified collector.yml
  local temp_file=$(mktemp)
  trap "rm -f $temp_file" EXIT
  
  # Copy collector.yml to temp file
  cp "$DIR/collector.yml" "$temp_file"
  
  # Add service account for OpenShift if needed
  if is_openshift; then
    # Add serviceAccountName to the pod spec if not already present
    if ! grep -q "serviceAccountName:" "$temp_file"; then
      # Insert serviceAccountName after dnsPolicy line (using awk for portability)
      local temp_file2=$(mktemp)
      awk '/dnsPolicy: ClusterFirstWithHostNet/ { print; print "      serviceAccountName: netobserv-ebpf-agent"; next }1' "$temp_file" > "$temp_file2"
      mv "$temp_file2" "$temp_file"
    fi
  fi
  
  # Apply the collector configuration
  kubectl apply -f "$temp_file"
  
  echo ""
  echo "Waiting for collector pods to be ready..."
  kubectl wait --for=condition=ready pod \
    -l k8s-app=netobserv-collector \
    -n netobserv-privileged \
    --timeout=120s || true
  
  echo ""
  echo "Collector deployment status:"
  kubectl get pods -n netobserv-privileged -l k8s-app=netobserv-collector
}

# Main execution
echo "========================================="
echo "NetObserv eBPF Agent Deployment Script"
echo "========================================="
echo ""

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
  echo "Error: kubectl is not installed or not in PATH"
  exit 1
fi

# Check if we can connect to the cluster
if ! kubectl cluster-info &> /dev/null; then
  echo "Error: Cannot connect to Kubernetes cluster"
  echo "Please ensure your kubeconfig is set correctly"
  exit 1
fi

# Check if running on OpenShift and set up permissions if needed
if is_openshift; then
  echo "OpenShift cluster detected."
  setup_openshift_permissions
fi

# Detect OpenSSL path
DETECTED_OPENSSL_PATH=$(detect_openssl_path)

if [ -z "$OPENSSL_PATH" ]; then
  OPENSSL_PATH="$DETECTED_OPENSSL_PATH"
  echo "Using default OpenSSL path for OpenShift 4.20/RHEL 9: $OPENSSL_PATH"
  echo "(Set OPENSSL_PATH environment variable to override)"
  echo ""
fi

# Deploy the collector first (agent needs it to be ready)
deploy_collector

echo ""

# Deploy the agent
deploy_agent "$AGENT_IMAGE" "$OPENSSL_PATH" "$CACHE_ACTIVE_TIMEOUT" "$CACHE_MAX_FLOWS"

echo ""
echo "========================================="
echo "Deployment completed successfully!"
echo "========================================="
echo ""
echo "To view agent logs:"
echo "  kubectl logs -n netobserv-privileged -l k8s-app=netobserv-ebpf-agent"
echo ""
echo "To view collector logs:"
echo "  kubectl logs -n netobserv-privileged -l k8s-app=netobserv-collector"
echo ""
echo "To check status:"
echo "  kubectl get pods -n netobserv-privileged"
echo ""

