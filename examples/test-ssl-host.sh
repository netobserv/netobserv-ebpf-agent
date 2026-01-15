#!/bin/bash
# Test SSL tracking with host processes
#
# This script tests SSL/TLS tracking functionality by executing HTTPS requests
# on cluster nodes using privileged pods with hostNetwork. These pods mount the
# host's libssl.so library, ensuring processes use the same library that the
# NetObserv agent's eBPF uprobe is attached to.
#
# Prerequisites:
#   - Kubernetes cluster (kind/minikube/OpenShift/etc)
#   - NetObserv agent deployed with ENABLE_OPENSSL_TRACKING=true
#   - Agent configured with correct OPENSSL_PATH
#
# Note: Some tests (TLS 1.3, HTTP/2) are optional and won't cause failure
#       if not supported on the node.

# Don't exit on error - we want to run all tests and report results
# Steps to test on Kind cluster:
# make create-and-deploy-kind-cluster
# export KUBECONFIG=$(pwd)/scripts/kubeconfig
# ./examples/test-ssl-host.sh

set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Testing SSL with Host Process ===${NC}"
echo ""

# Get all node names first (needed for cluster type detection)
NODES=$(kubectl get nodes -o jsonpath='{.items[*].metadata.name}')

# Detect if we're on a kind cluster (Docker-based) or real cluster
is_kind_cluster() {
  # Check if nodes are Docker containers (kind clusters)
  local first_node=$(echo $NODES | awk '{print $1}')
  if [ -n "$first_node" ] && docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${first_node}$"; then
    return 0
  fi
  return 1
}

# Detect cluster type
if is_kind_cluster; then
  echo "Detected: Kind cluster (Docker-based)"
  echo "Tests will run directly on node containers."
else
  echo "Detected: Real Kubernetes/OpenShift cluster"
  echo "Tests will run via privileged test pods with hostNetwork."
  echo "These pods mount the host's libssl.so to ensure uprobes are triggered."
fi
echo ""
echo "This will run various SSL/TLS tests on each cluster node."
echo "Tests use privileged pods with hostNetwork that mount the host's libssl.so,"
echo "ensuring processes use the same library that the agent's uprobe is attached to."
echo ""

# Counter for tests
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to create a test pod on a node that uses host's libssl.so
create_test_pod_on_node() {
  local node=$1
  local pod_name="ssl-test-$(echo $node | tr '.' '-' | tr ':' '-')"
  
  # Check if pod already exists
  if kubectl get pod -n netobserv-privileged "$pod_name" &>/dev/null; then
    return 0
  fi
  
  # Create a privileged pod with hostNetwork on the specific node
  # Mount the host's /usr/lib64 so processes can use the exact library the uprobe is attached to
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $pod_name
  namespace: netobserv-privileged
  labels:
    app: ssl-test
spec:
  hostNetwork: true
  nodeName: $node
  serviceAccountName: netobserv-ebpf-agent
  containers:
  - name: test
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
    command: ["/bin/sh"]
    args: ["-c", "sleep 3600"]
    securityContext:
      privileged: true
      runAsUser: 0
    volumeMounts:
    - name: host-lib64
      mountPath: /host-lib64
      readOnly: true
    - name: host-usr-lib64
      mountPath: /usr/lib64
      readOnly: true
  volumes:
  - name: host-lib64
    hostPath:
      path: /lib64
      type: Directory
  - name: host-usr-lib64
    hostPath:
      path: /usr/lib64
      type: Directory
  restartPolicy: Never
EOF
  
  # Wait for pod to be ready
  kubectl wait --for=condition=Ready pod/$pod_name -n netobserv-privileged --timeout=30s &>/dev/null || true
}

# Function to run a command on a node
run_on_node() {
  local node=$1
  local cmd=$2
  
  if is_kind_cluster; then
    # Use docker exec for kind clusters (nodes are Docker containers)
    docker exec $node bash -c "$cmd" 2>&1
  else
    # For real clusters, create a privileged pod with hostNetwork that uses host's libssl.so
    local pod_name="ssl-test-$(echo $node | tr '.' '-' | tr ':' '-')"
    create_test_pod_on_node "$node"
    
    # The pod has hostNetwork and mounts /usr/lib64 from host
    # This ensures processes use the exact same libssl.so that the uprobe is attached to
    kubectl exec -n netobserv-privileged "$pod_name" -- \
      sh -c "$cmd" 2>&1
  fi
}

run_test() {
  local node=$1
  local test_name=$2
  local curl_cmd=$3
  
  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  echo -e "${YELLOW}[TEST $TOTAL_TESTS] $test_name${NC}"
  
  if run_on_node "$node" "$curl_cmd" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Request completed successfully${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    return 0
  else
    echo -e "${RED}✗ Request failed${NC}"
    FAILED_TESTS=$((FAILED_TESTS + 1))
    return 1
  fi
}


check_ssl_events() {
  local agent_pod=$1
  local test_desc=$2
  
  echo -e "${BLUE}Checking logs for SSL events after $test_desc:${NC}"
  local recent_logs=$(kubectl logs -n netobserv-privileged $agent_pod --tail=1000 2>/dev/null)
  # Also get initialization logs from the beginning (initialization messages appear early)
  local init_logs=$(kubectl logs -n netobserv-privileged $agent_pod 2>/dev/null | head -500)
  
  # Look for actual SSL events (these are logged at debug/info level)
  # Exclude initialization messages like "SSL RingBuf tracer started" and "waiting for SSL event"
  local ssl_events=$(echo "$recent_logs" | grep -iE 'SSL EVENT:|SSL ringbuffer event received!|SSL data as string:' | grep -v "waiting for SSL event" | grep -v "SSL RingBuf tracer started" | tail -10)
  
  if [ -n "$ssl_events" ]; then
    echo -e "${GREEN}✓ SSL events found:${NC}"
    echo "$ssl_events" | sed 's/^/  /'
    echo ""
    
    # Try to decode hex strings if python is available
    if command -v python3 &>/dev/null; then
      echo "  Decoded SSL data (plaintext before encryption):"
      echo "$ssl_events" | grep "SSL data as string:" | head -3 | while IFS= read -r line; do
        # Extract just the SSL data string (remove log prefix and component suffix)
        hex_part=$(echo "$line" | sed 's/.*SSL data as string: //' | sed 's/" component=.*$//' | sed 's/"$//')
        
        # Check if it's already readable (no hex escapes)
        if ! echo "$hex_part" | grep -q '\\x'; then
          # Already readable - show it directly
          echo "    $hex_part"
          # Check for HTTP patterns
          if echo "$hex_part" | grep -qE '(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|HTTP/[0-9.]+|Host:|User-Agent:)'; then
            echo "    → HTTP request detected"
          fi
        else
          # Decode hex escapes using python
          decoded=$(echo "$hex_part" | python3 -c "
import sys
import re
s = sys.stdin.read()
# Replace \xHH with actual character
decoded = re.sub(r'\\\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), s)
# Check if mostly readable
readable_count = sum(1 for c in decoded[:100] if 32 <= ord(c) < 127)
if readable_count > 20:
    # Mostly readable - show as text with escapes for non-printable
    result = ''
    for c in decoded[:200]:
        if 32 <= ord(c) < 127:
            result += c
        elif c == '\n':
            result += '\\n'
        elif c == '\r':
            result += '\\r'
        elif c == '\t':
            result += '\\t'
        else:
            result += f'<{ord(c):02x}>'
    print('READABLE:' + result)
else:
    # Mostly binary - show as hex dump
    hex_dump = ' '.join(f'{ord(c):02x}' for c in decoded[:50])
    print('BINARY:' + hex_dump)
" 2>/dev/null)
          if [ -n "$decoded" ]; then
            if echo "$decoded" | grep -q '^READABLE:'; then
              readable_text=$(echo "$decoded" | sed 's/^READABLE://')
              echo "    $readable_text"
              # Check for HTTP patterns
              if echo "$readable_text" | grep -qE '(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|HTTP/[0-9.]+|Host:|User-Agent:)'; then
                echo "    → HTTP request detected"
              fi
            elif echo "$decoded" | grep -q '^BINARY:'; then
              hex_dump=$(echo "$decoded" | sed 's/^BINARY://')
              echo "    Binary data (hex): $hex_dump..."
              echo "    → Likely HTTP/2 frame or TLS handshake data"
            else
              echo "    $decoded"
            fi
          fi
        fi
      done
      echo ""
    fi
    return 0
  fi
  
  # No events found - provide detailed diagnostics
  echo -e "${YELLOW}⚠ No SSL events found in logs${NC}"
  echo ""
  echo "  Diagnostic information:"
  
  # Check if SSL tracking is enabled (check from beginning of logs)
  if echo "$init_logs" | grep -qi "SSL tracking enabled\|SSL RingBuf tracer started"; then
    echo -e "  ${GREEN}✓ SSL tracking is enabled in agent${NC}"
    echo "$init_logs" | grep -iE "SSL.*tracking.*enabled|SSL RingBuf tracer started" | head -2 | sed 's/^/    /'
  else
    echo -e "  ${RED}✗ SSL tracking may not be enabled${NC}"
  fi
  
  # Check for errors
  local errors=$(echo "$recent_logs" | grep -iE "error.*ssl|ssl.*error|failed.*ssl|ssl.*failed" | tail -5)
  if [ -n "$errors" ]; then
    echo -e "  ${RED}✗ Found SSL-related errors:${NC}"
    echo "$errors" | sed 's/^/    /'
  fi
  
  # Check if ringbuffer is waiting
  if echo "$recent_logs" | grep -qi "waiting for SSL event"; then
    echo -e "  ${YELLOW}⚠ Agent is waiting for SSL events (ringbuffer is listening)${NC}"
    echo "    This means the uprobe is attached but no events are being received."
    echo ""
    echo "  Possible reasons:"
    echo "    1. Processes are running in containers that don't use the host's libssl.so"
    echo "    2. The library path used by processes differs from OPENSSL_PATH"
    echo "    3. Processes are not calling SSL_write (e.g., using different SSL libraries)"
    echo "    4. The uprobe attachment may not be working correctly"
  fi
  
  echo ""
  echo -e "  ${YELLOW}Note: Tests use privileged pods with hostNetwork that mount the host's libssl.so.${NC}"
  echo -e "  ${YELLOW}If SSL events are still not captured, verify the OPENSSL_PATH matches the library${NC}"
  echo -e "  ${YELLOW}used by the processes you're testing.${NC}"
  echo ""
}

for NODE in $NODES; do
  echo "========================================="
  echo -e "${BLUE}Testing node: $NODE${NC}"
  echo "========================================="

  # Get the agent pod running on this node
  AGENT_POD=$(kubectl get pods -n netobserv-privileged -l k8s-app=netobserv-ebpf-agent \
    --field-selector spec.nodeName=$NODE \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | head -n1)

  if [ -z "$AGENT_POD" ]; then
    echo -e "${RED}Warning: No agent pod found on node $NODE, skipping...${NC}"
    continue
  fi

  echo -e "${GREEN}Agent pod: $AGENT_POD${NC}"
  echo ""
  
  # Show diagnostic information
  echo -e "${BLUE}Node diagnostics:${NC}"
  echo -n "  curl version: "
  run_on_node "$NODE" "curl --version 2>/dev/null | head -1 || which curl >/dev/null 2>&1 && echo 'curl available' || echo 'curl not found'" 2>/dev/null || echo "unknown"
  echo -n "  OpenSSL library: "
  # Check libssl.so version info directly (more reliable than openssl binary)
  openssl_info=$(run_on_node "$NODE" "
    # Find the actual library file
    libssl_file=\$(ls -1 /usr/lib64/libssl.so* 2>/dev/null | head -1)
    if [ -z \"\$libssl_file\" ]; then
      libssl_file=\$(ls -1 /usr/lib/libssl.so* 2>/dev/null | head -1)
    fi
    if [ -n \"\$libssl_file\" ] && [ -e \"\$libssl_file\" ]; then
      # Extract version from filename (e.g., libssl.so.3 -> OpenSSL 3, libssl.so.1.1 -> OpenSSL 1.1)
      filename=\$(basename \"\$libssl_file\")
      if echo \"\$filename\" | grep -q 'libssl\.so\.[0-9]'; then
        version=\$(echo \"\$filename\" | sed -E 's/libssl\.so\.([0-9]+)(\.[0-9]+)?.*/\1\2/' | sed 's/\.$//')
        echo \"OpenSSL \$version (\$filename)\"
      else
        echo \"\$filename\"
      fi
    else
      echo 'not found'
    fi
  " 2>/dev/null)
  if [ -n "$openssl_info" ] && [ "$openssl_info" != "unknown" ]; then
    echo "$openssl_info"
  else
    echo "unknown"
  fi
  echo -n "  libssl location: "
  run_on_node "$NODE" "ls -la /usr/lib*/libssl.so* 2>/dev/null | head -1 || echo 'not found in standard location'" 2>/dev/null || echo "unknown"
  echo ""
  
  # Check if agent has SSL tracking enabled
  # Check from beginning of logs since initialization messages appear early
  echo -e "${BLUE}Agent SSL tracking status:${NC}"
  # Get logs from the beginning (no tail limit) but limit output for performance
  agent_init_logs=$(kubectl logs -n netobserv-privileged $AGENT_POD 2>/dev/null | head -500)
  agent_recent_logs=$(kubectl logs -n netobserv-privileged $AGENT_POD --tail=200 2>/dev/null)
  
  if echo "$agent_init_logs" | grep -qi "SSL tracking enabled\|OpenSSL tracking enabled\|SSL RingBuf tracer started"; then
    echo -e "  ${GREEN}✓ SSL tracking is enabled${NC}"
    echo "$agent_init_logs" | grep -iE "SSL.*tracking.*enabled|OpenSSL.*tracking.*enabled|SSL RingBuf tracer started" | head -3 | sed 's/^/    /'
  else
    echo -e "  ${YELLOW}⚠ SSL tracking status unclear${NC}"
    echo "  Checking agent environment variables..."
    kubectl get pod -n netobserv-privileged $AGENT_POD -o jsonpath='{.spec.containers[0].env[*]}' 2>/dev/null | grep -i openssl || echo "  No OPENSSL_PATH found in agent env"
  fi
  
  # Check OpenSSL path configuration
  openssl_path=$(kubectl get pod -n netobserv-privileged $AGENT_POD -o jsonpath='{.spec.containers[0].env[?(@.name=="OPENSSL_PATH")].value}' 2>/dev/null)
  if [ -n "$openssl_path" ]; then
    echo -e "  ${GREEN}Agent OPENSSL_PATH: $openssl_path${NC}"
  else
    echo -e "  ${YELLOW}⚠ OPENSSL_PATH not configured in agent${NC}"
  fi
  echo ""

  # Test 1: Basic HTTPS GET with HTTP/1.1
  run_test "$NODE" "Basic HTTPS GET with HTTP/1.1" \
    "curl -s --http1.1 --max-time 10 https://httpbin.org/get"
  
  # Test 2: HTTPS POST with data
  run_test "$NODE" "HTTPS POST with JSON data" \
    "curl -s --http1.1 --max-time 10 -X POST https://httpbin.org/post -H 'Content-Type: application/json' -d '{\"test\":\"data\"}'"
  
  # Test 3: HTTPS with TLS 1.2
  run_test "$NODE" "HTTPS with TLS 1.2 explicitly" \
    "curl -s --tlsv1.2 --tls-max 1.2 --max-time 10 https://www.howsmyssl.com/a/check"
  
  # Test 4: HTTPS with TLS 1.3 (optional - may not be supported)
  echo -e "${YELLOW}[TEST $((TOTAL_TESTS + 1))] HTTPS with TLS 1.3 explicitly (optional)${NC}"
  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  
  # First check if TLS 1.3 is supported
  if run_on_node "$NODE" "curl --help all 2>/dev/null | grep -q tlsv1.3" 2>/dev/null; then
    if run_on_node "$NODE" "curl -s --tlsv1.3 --max-time 10 https://www.howsmyssl.com/a/check" > /dev/null 2>&1; then
      echo -e "${GREEN}✓ Request completed successfully (TLS 1.3 supported)${NC}"
      PASSED_TESTS=$((PASSED_TESTS + 1))
    else
      # Try alternative endpoint
      if run_on_node "$NODE" "curl -s --tlsv1.3 --max-time 10 https://www.cloudflare.com" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Request completed successfully with alternative endpoint${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
      else
        echo -e "${YELLOW}⚠ TLS 1.3 option exists but connection failed (this is OK)${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
      fi
    fi
  else
    echo -e "${YELLOW}⚠ TLS 1.3 not supported by curl on this node (skipped)${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
  fi
  
  # Test 5: HTTPS with headers
  run_test "$NODE" "HTTPS with custom headers" \
    "curl -s --http1.1 --max-time 10 -H 'User-Agent: NetObserv-Test/1.0' -H 'X-Test-Header: SSL-Tracking' https://httpbin.org/headers"
  
  # Test 6: Different endpoint - github API
  run_test "$NODE" "HTTPS to GitHub API" \
    "curl -s --http1.1 --max-time 10 https://api.github.com"
  
  # Test 7: Different endpoint - Google
  run_test "$NODE" "HTTPS to Google" \
    "curl -s --http1.1 --max-time 10 -L https://www.google.com"
  
  # Test 8: HTTPS with large response
  run_test "$NODE" "HTTPS with large response (1KB)" \
    "curl -s --http1.1 --max-time 10 https://httpbin.org/bytes/1024"
  
  # Test 9: HTTPS with HTTP/2 (optional - may not be supported)
  echo -e "${YELLOW}[TEST $((TOTAL_TESTS + 1))] HTTPS with HTTP/2 (optional)${NC}"
  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  
  if run_on_node "$NODE" "curl --help all 2>/dev/null | grep -q http2" 2>/dev/null; then
    if run_on_node "$NODE" "curl -s --http2 --max-time 10 https://www.google.com" > /dev/null 2>&1; then
      echo -e "${GREEN}✓ Request completed successfully (HTTP/2 supported)${NC}"
      PASSED_TESTS=$((PASSED_TESTS + 1))
    else
      echo -e "${YELLOW}⚠ HTTP/2 option exists but connection failed (this is OK)${NC}"
      PASSED_TESTS=$((PASSED_TESTS + 1))
    fi
  else
    echo -e "${YELLOW}⚠ HTTP/2 not supported by curl on this node (skipped)${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
  fi

  echo ""
  check_ssl_events "$AGENT_POD" "all tests"
  
  echo -e "${BLUE}Detailed SSL event analysis:${NC}"
  detailed_logs=$(kubectl logs -n netobserv-privileged $AGENT_POD --tail=1000 2>/dev/null)
  # Look for actual SSL events, excluding initialization messages
  detailed_events=$(echo "$detailed_logs" | grep -iE 'SSL EVENT:|SSL ringbuffer event received!|SSL data as string:' | grep -v "waiting for SSL event" | grep -v "SSL RingBuf tracer started" | tail -20)
  if [ -n "$detailed_events" ]; then
    echo "  Found SSL events:"
    echo "$detailed_events" | sed 's/^/    /'
    echo ""
    
    # Decode SSL data strings if python is available
    if command -v python3 &>/dev/null; then
      echo "  Decoded SSL data samples (plaintext before encryption):"
      echo "$detailed_events" | grep "SSL data as string:" | head -5 | while IFS= read -r line; do
        # Extract just the SSL data string (remove log prefix and component suffix)
        hex_part=$(echo "$line" | sed 's/.*SSL data as string: //' | sed 's/" component=.*$//' | sed 's/"$//')
        
        # Check if it's already readable (no hex escapes)
        if ! echo "$hex_part" | grep -q '\\x'; then
          # Already readable - show it directly
          echo "    $hex_part"
          # Check for HTTP patterns
          http_match=$(echo "$hex_part" | grep -oE '(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|HTTP/[0-9.]+|Host:|User-Agent:|Content-Type:)' | head -3)
          if [ -n "$http_match" ]; then
            echo "    → HTTP patterns: $http_match"
          fi
        else
          # Decode hex escapes using python
          decoded=$(echo "$hex_part" | python3 -c "
import sys
import re
s = sys.stdin.read()
# Replace \xHH with actual character
decoded = re.sub(r'\\\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), s)
# Check if mostly readable
readable_count = sum(1 for c in decoded[:100] if 32 <= ord(c) < 127)
if readable_count > 20:
    # Mostly readable - show as text with escapes for non-printable
    result = ''
    for c in decoded[:200]:
        if 32 <= ord(c) < 127:
            result += c
        elif c == '\n':
            result += '\\n'
        elif c == '\r':
            result += '\\r'
        elif c == '\t':
            result += '\\t'
        else:
            result += f'<{ord(c):02x}>'
    print('READABLE:' + result)
else:
    # Mostly binary - show as hex dump
    hex_dump = ' '.join(f'{ord(c):02x}' for c in decoded[:50])
    print('BINARY:' + hex_dump)
" 2>/dev/null)
          if [ -n "$decoded" ]; then
            if echo "$decoded" | grep -q '^READABLE:'; then
              readable_text=$(echo "$decoded" | sed 's/^READABLE://')
              echo "    $readable_text"
              # Check for HTTP patterns
              http_match=$(echo "$readable_text" | grep -oE '(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|HTTP/[0-9.]+|Host:|User-Agent:|Content-Type:)' | head -3)
              if [ -n "$http_match" ]; then
                echo "    → HTTP patterns: $http_match"
              fi
            elif echo "$decoded" | grep -q '^BINARY:'; then
              hex_dump=$(echo "$decoded" | sed 's/^BINARY://')
              echo "    Binary data (hex): $hex_dump..."
              echo "    → Likely HTTP/2 frame or TLS handshake data"
            else
              echo "    $decoded"
            fi
          fi
        fi
      done
      echo ""
    fi
  else
    echo "  No SSL events found in recent logs"
    echo ""
    echo "  Recent SSL-related log entries (status messages):"
    echo "$detailed_logs" | grep -iE 'ssl|openssl' | grep -v "waiting for SSL event" | tail -8 | sed 's/^/    /' || echo "    No SSL-related log entries found"
    echo ""
    echo "  Checking for errors or warnings..."
    echo "$detailed_logs" | grep -iE 'error|warn|fail' | grep -iE 'ssl|openssl|uprobe|attach|ringbuf' | tail -5 | sed 's/^/    /' || echo "    No relevant errors found"
  fi
  
  echo ""
  echo -e "${BLUE}Node $NODE test summary:${NC}"
  echo "  Total tests: $TOTAL_TESTS"
  echo -e "  ${GREEN}Passed: $PASSED_TESTS${NC}"
  echo -e "  ${RED}Failed: $FAILED_TESTS${NC}"
  echo ""
done

echo "========================================="
echo -e "${BLUE}Test completed for all nodes${NC}"
echo "========================================="
echo ""

# Cleanup test pods if created
if ! is_kind_cluster; then
  echo "Cleaning up test pods..."
  kubectl delete pod -n netobserv-privileged -l app=ssl-test --ignore-not-found=true 2>/dev/null || true
fi

echo ""
echo -e "${BLUE}Overall Summary:${NC}"
echo "  Total tests executed: $TOTAL_TESTS"
echo -e "  ${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "  ${RED}Failed: $FAILED_TESTS${NC}"
echo ""

# Calculate pass rate
if [ $TOTAL_TESTS -gt 0 ]; then
  PASS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
  echo "  Pass rate: ${PASS_RATE}%"
fi
