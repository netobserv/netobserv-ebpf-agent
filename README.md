# Network Observability eBPF Agent

[![Go Report Card](https://goreportcard.com/badge/github.com/netobserv/netobserv-ebpf-agent)](https://goreportcard.com/report/github.com/netobserv/netobserv-ebpf-agent)

The Network Observability eBPF Agent allows collecting and aggregating all the ingress and
egress flows on a Linux host (required a Kernel 5.8+ with eBPF enabled).

* [How to build](#how-to-build)
* [How to configure](#how-to-configure)
* [How to run](#how-to-run)
* [Development receipts](#development-receipts)
* [Known issues](#known-issues)
* [Frequently-asked questions](#frequently-asked-questions)
* [Troubleshooting](#troubleshooting)

## How to build

To build the agent image and push it to your Docker / Quay repository, run:
```bash
# compile project
make build

# build the default image (quay.io/netobserv/netobserv-ebpf-agent:main):
make image-build

# push the default image (quay.io/netobserv/netobserv-ebpf-agent:main):
make image-push

# build and push on your own quay.io account (quay.io/myuser/netobserv-ebpf-agent:dev):
IMAGE_ORG=myuser VERSION=dev make images

# build and push on a different registry
IMAGE=dockerhub.io/myuser/plugin:tag make images
```

## How to configure

The eBPF Agent is configured by means of environment variables. Check the
[configuration documentation](./docs/config.md) for more details.

## How to run

The NetObserv eBPF Agent is designed to run as a DaemonSet in OpenShift/K8s. It is triggered and
configured by our [Network Observability Operator](https://github.com/netobserv/network-observability-operator).

Anyway you can run it directly as an executable from your command line:

```bash
export TARGET_HOST=...
export TARGET_PORT=...
sudo -E bin/netobserv-ebpf-agent
```

We don't recommend using the agent's IPFIX exporter mode as it is not actively maintained (if you're interested in maintaining it, let us know!). Note that flowlogs-pipeline can also generate IPFIX exports, so a valid way to get IPFIX data is to export to flowlogs-pipeline (via GRPC, Kafka or direct-flp) and then configure IPFIX within flowlogs-pipeline.

A simple way to try the agent is using the `direct-flp` export mode, printing directly to stdout:

Given the following file `flp-config.json`:

```json
{
	"pipeline":[
		{"name": "writer","follows": "preset-ingester"}
	],
	"parameters":[
		{"name": "writer","write": {"type": "stdout"}}
	]
}
```
Run:

```bash
export FLP_CONFIG=$(cat flp-config.json)
export EXPORT="direct-flp"
sudo -E bin/netobserv-ebpf-agent
```

For more information about configuring flowlogs-pipeline, please refer to [its documentation](https://github.com/netobserv/flowlogs-pipeline).

To deploy locally, use instructions from [flowlogs-dump (like tcpdump)](./examples/flowlogs-dump/README.md).    
To deploy it as a Pod, you can check the [deployment examples](./deployments).

The Agent needs to be executed either with:

1. The following [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html):
   - `BPF`: Needed to use eBPF programs and maps.
   - `PERFMON`: Needed to access perf monitoring and profiling features.
   - `NET_ADMIN`: Needed for TC programs to attach/detach to/from qdisc and for TCX hooks.

   If you [deploy it in Kubernetes or OpenShift](./deployments/flp-daemonset-cap.yml),
   the container running the Agent needs to define the following `securityContext`:
   ```yaml
   securityContext:
     runAsUser: 0
     capabilities:
       add:
         - BPF
         - PERFMON
         - NET_ADMIN
   ```
   (Please notice that the `runAsUser: 0` is still needed).
2. Or full administrative privileges. If you
   [deploy it in Kubernetes or OpenShift](./deployments/flp-daemonset.yml),
   the container running the Agent needs to define the following `securityContext`:
   ```yaml
   securityContext:
     privileged: true
     runAsUser: 0
   ```

While the first option is safer (principle of least privilege), it also has its drawbacks, notably that you can't monitor all secondary interfaces. Full privileged mode may also be needed if running on a Linux kernel that does not recognize some of the above capabilities (some older Kubernetes distributions might not recognize the `BPF` and `PERFMON` capabilities).

Here is a list of distributions where we tested both full privileges and capability approaches,
and whether they worked (✅) or did not (❌):

| Distribution                  | K8s Server version | Capabilities | Privileged |
|-------------------------------|--------------------|--------------|------------|
| Amazon EKS (Bottlerocket AMI) | 1.22.6             | ✅            | ✅          |
| K3s (Rancher Desktop)         | 1.23.5             | ❌            | ✅          |
| Kind                          | 1.23.5             | ❌            | ✅          |
| OpenShift                     | 1.23.3             | ✅            | ✅          |

## Running on KinD cluster

### How to run on kind cluster

Install KinD and the ebpf agent and export KUBECONFIG
```sh
make create-and-deploy-kind-cluster
export KUBECONFIG=$(pwd)/scripts/kubeconfig
```

### Deleting the kind cluster

In order to delete the kind cluster:
```sh
make destroy-kind-cluster
```

## Development receipts

### How to regenerate the eBPF Kernel binaries

The eBPF program is embedded into the `pkg/ebpf/bpf_*` generated files.
This step is generally not needed unless you change the C code in the `bpf` folder.

If you have Docker installed, you just need to run:

```bash
make docker-generate
```

If you can't install docker, you can install locally the following packages, then run `make generate`:

```bash
dnf install -y kernel-devel make llvm clang glibc-devel.i686
make generate
```

Regularly tested on Fedora.

### Running end-to-end tests

Refer to the specific documentation: [e2e readme](./e2e/README.md)

## Known issues

### Extrenal Traffic in Openshift (OVN-Kubernetes CNI)

For egress traffic, you can see the source Pod metadata. For ingress traffic (e.g. an HTTP response),
you see the destination **Host** metadata.

## Frequently-asked questions

### Where is the collector?

As part of our Network Observability solution, the eBPF Agent is designed to send the traced
flows to our [Flowlogs Pipeline](https://github.com/netobserv/flowlogs-pipeline) component.

In addition, we provide a simple GRPC+Protobuf library to allow implementing your own collector.
Check the [packet counter code](./examples/performance/server/packet-counter-collector.go)
for an example of a simple collector using our library.

## Troubleshooting

### Deployed as a Kubernetes Pod, the agent shows permission errors in the logs and can't start

In your [deployment file](./deployments/flp-daemonset-cap.yml), make sure that the container runs as
the root user (`runAsUser: 0`) and with the granted capabilities or privileges (see [how to run](#how-to-run) section).

### The Agent doesn't work in my Amazon EKS puzzle

Despite Amazon Linux 2 enables eBPF by default in EC2, the
[EKS images are shipped with disabled eBPF](https://github.com/awslabs/amazon-eks-ami/issues/728).

You'd need either:

1. Provide your own AMI configured to work with eBPF
2. Use other Linux distributions that are shipped with eBPF enabled by default. We have successfully
   tested the eBPF Agent in EKS with the [Bottlerocket](https://aws.amazon.com/es/bottlerocket/)
   Linux distribution, without requiring any extra configuration.

## Licenses

Two licenses are used for the source code in this repository:

- [GPL v2](./bpf/LICENSE) covers the eBPF code in `./bpf` directory.
- [Apache v2](./LICENSE) covers everything else.

## Discussions and contributions

Discussions related to NetObserv are welcome on [GitHub discussions](https://github.com/orgs/netobserv/discussions) as well as on the [#netobserv-project](http://cloud-native.slack.com/) channel from CNCF slack.

If you'd like to reach out because you've found a security issue, please do not share sensitive details publicly. Please follow the instructions described on the [Red Hat Customer Portal](https://access.redhat.com/security/team/contact/?extIdCarryOver=true&sc_cid=701f2000001Css5AAC).

Refer to the [NetObserv projects contribution guide](https://github.com/netobserv/documents/blob/main/CONTRIBUTING.md) for more details on contributions.
