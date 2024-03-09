#!/usr/bin/env bash
set -eux

DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

KIND_IMAGE="kindest/node:v1.27.3"

# deploy_kind installs the kind cluster
deploy_kind() {
  cat <<EOF | kind create cluster --image ${KIND_IMAGE} --config=- --kubeconfig=${DIR}/kubeconfig
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
    podSubnet: $NET_CIDR_IPV4,$NET_CIDR_IPV6
    serviceSubnet: $SVC_CIDR_IPV4,$SVC_CIDR_IPV6
    ipFamily: $IP_FAMILY
nodes:
- role: control-plane
  extraMounts:
  - hostPath: /var/run/netns
    containerPath: /var/run/netns
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
        extraArgs:
            v: "5"
    controllerManager:
        extraArgs:
            v: "5"
    scheduler:
        extraArgs:
            v: "5"
- role: worker
  extraMounts:
  - hostPath: /var/run/netns
    containerPath: /var/run/netns
- role: worker
  extraMounts:
  - hostPath: /var/run/netns
    containerPath: /var/run/netns
EOF
}

# install_netobserv-agent will install the daemonset
# into each kind docker container
install_netobserv-agent() {
docker build . -t localhost/ebpf-agent:test
kind load docker-image localhost/ebpf-agent:test
kubectl apply -f ${DIR}/agent.yml
}

# print_success prints a little success message at the end of the script
print_success() {
  set +x
  echo "Your kind cluster was created successfully"
  echo "Run the following to load the kubeconfig:"
  echo "export KUBECONFIG=${DIR}/kubeconfig"
  set -x
}

KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kind}"
IP_FAMILY=${IP_FAMILY:-dual}
NET_CIDR_IPV4=${NET_CIDR_IPV4:-10.244.0.0/16}
SVC_CIDR_IPV4=${SVC_CIDR_IPV4:-10.96.0.0/16}
NET_CIDR_IPV6=${NET_CIDR_IPV6:-fd00:10:244::/48}
SVC_CIDR_IPV6=${SVC_CIDR_IPV6:-fd00:10:96::/112}

# At the minimum, deploy the kind cluster
deploy_kind
export KUBECONFIG=${DIR}/kubeconfig
oc label node kind-worker node-role.kubernetes.io/worker=
oc label node kind-worker2 node-role.kubernetes.io/worker=

install_netobserv-agent

# Print success at the end of this script
print_success
