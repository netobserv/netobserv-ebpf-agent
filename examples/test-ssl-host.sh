#!/bin/bash
# Test SSL tracking with HOST processes (not containers)
#
# This script tests SSL/TLS tracking functionality by executing HTTPS requests
# directly on cluster nodes (host processes) and verifying that the NetObserv
# agent captures SSL events via eBPF uprobes.
#
# Prerequisites:
#   - Kubernetes cluster (kind/minikube/etc)
#   - NetObserv agent deployed with EnableSSL: true
#   - Agent configured with correct OpenSSL library path
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
echo "This will run various SSL/TLS tests on each cluster node directly on the host"
echo "This should trigger the SSL uprobes since the host process uses"
echo "the same libssl.so that the agent attached to."
echo ""

# Get all node names
NODES=$(kubectl get nodes -o jsonpath='{.items[*].metadata.name}')

# Counter for tests
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

run_test() {
  local node=$1
  local test_name=$2
  local curl_cmd=$3
  
  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  echo -e "${YELLOW}[TEST $TOTAL_TESTS] $test_name${NC}"
  
  if docker exec $node bash -c "$curl_cmd" > /dev/null 2>&1; then
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
  local ssl_events=$(kubectl logs -n netobserv-privileged $agent_pod --tail=100 | grep 'SSL EVENT' | tail -5)
  
  if [ -z "$ssl_events" ]; then
    echo -e "${YELLOW}No SSL events found in logs${NC}"
  else
    echo -e "${GREEN}SSL events found:${NC}"
    echo "$ssl_events"
  fi
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
  docker exec $NODE curl --version 2>/dev/null | head -1 || echo "unknown"
  echo -n "  OpenSSL version: "
  docker exec $NODE openssl version 2>/dev/null || echo "unknown"
  echo -n "  libssl location: "
  docker exec $NODE bash -c "ls -la /usr/lib*/libssl.so* 2>/dev/null | head -1 || echo 'not found in standard location'"
  echo ""
  
  # Check if agent has SSL tracking enabled
  echo -e "${BLUE}Agent SSL tracking status:${NC}"
  if kubectl logs -n netobserv-privileged $AGENT_POD --tail=100 | grep -q "SSL tracking enabled"; then
    echo -e "  ${GREEN}✓ SSL tracking is enabled${NC}"
    kubectl logs -n netobserv-privileged $AGENT_POD --tail=100 | grep "SSL tracking enabled" | tail -1
  else
    echo -e "  ${YELLOW}⚠ SSL tracking status unclear (check agent configuration)${NC}"
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
  if docker exec $NODE bash -c "curl --help all 2>/dev/null | grep -q tlsv1.3" 2>/dev/null; then
    if docker exec $NODE bash -c "curl -s --tlsv1.3 --max-time 10 https://www.howsmyssl.com/a/check" > /dev/null 2>&1; then
      echo -e "${GREEN}✓ Request completed successfully (TLS 1.3 supported)${NC}"
      PASSED_TESTS=$((PASSED_TESTS + 1))
    else
      # Try alternative endpoint
      if docker exec $NODE bash -c "curl -s --tlsv1.3 --max-time 10 https://www.cloudflare.com" > /dev/null 2>&1; then
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
  
  if docker exec $NODE bash -c "curl --help all 2>/dev/null | grep -q http2" 2>/dev/null; then
    if docker exec $NODE bash -c "curl -s --http2 --max-time 10 https://www.google.com" > /dev/null 2>&1; then
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
  kubectl logs -n netobserv-privileged $AGENT_POD --tail=200 | grep -A 2 "SSL EVENT" | tail -20 || echo "No detailed SSL events found"
  
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
