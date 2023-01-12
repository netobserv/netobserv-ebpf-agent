# Network Observability eBPF Agent

[![Go Report Card](https://goreportcard.com/badge/github.com/netobserv/netobserv-ebpf-agent)](https://goreportcard.com/report/github.com/netobserv/netobserv-ebpf-agent)

The Network Observability eBPF Agent allows collecting and aggregating all the ingress and
egress flows on a Linux host (required a Kernel 4.18+ with eBPF enabled).

* [How to compile](#how-to-compile)
* [Hot to configure](#how-to-configure)
* [How to run](#how-to-run)
* [Development receipts](#development-receipts)
* [Known issues](#known-issues)
* [Frequently-asked questions](#frequently-asked-questions)
* [Troubleshooting](#troubleshooting)

## How to compile

```
make build
```

To build the agent image and push it to your Docker / Quay repository, run:

```bash
IMG=quay.io/myaccount/netobserv-ebpf-agent:dev make image-build image-push
```

## How to configure

The eBPF Agent is configured by means of environment variables. Check the
[configuration documentation](./docs/config.md) for more details.

## How to run

The NetObserv eBPF Agent is designed to run as a DaemonSet in OpenShift/K8s. It is triggered and
configured by our [Network Observability Operator](https://github.com/netobserv/network-observability-operator).

Anyway you can run it directly as an executable from your command line:

```
export FLOWS_TARGET_HOST=...
export FLOWS_TARGET_PORT=...
sudo -E bin/netobserv-ebpf-agent
```

To deploy locally, use instructions from [flowlogs-dump (like tcpdump)](./examples/flowlogs-dump/README.md).    
To deploy it as a Pod, you can check the [deployment examples](./deployments).

The Agent needs to be executed either with:

1. The following [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
   (recommended way): `BPF`, `PERFMON`, `NET_ADMIN`, `SYS_RESOURCE`. If you
   [deploy it in Kubernetes or OpenShift](./deployments/flp-daemonset-cap.yml),
   the container running the Agent needs to define the following `securityContext`:
   ```yaml
   securityContext:
     runAsUser: 0
     capabilities:
       add:
         - BPF
         - PERFMON
         - NET_ADMIN
         - SYS_RESOURCE
   ```
   (Please notice that the `runAsUser: 0` is still needed).
2. Administrative privileges. If you
   [deploy it in Kubernetes or OpenShift](./deployments/flp-daemonset.yml),
   the container running the Agent needs to define the following `securityContext`:
   ```yaml
   securityContext:
     privileged: true
     runAsUser: 0
   ```
   This option is only recommended if your Kernel does not recognize some of the above capabilities.
   We found some Kubernetes distributions (e.g. K3s) that do not recognize the `BPF` and
   `PERFMON` capabilities.

Here is a list of distributions where we tested both full privileges and capability approaches,
and whether they worked (✅) or did not (❌):

| Distribution                  | K8s Server version | Capabilities | Privileged |
|-------------------------------|--------------------|--------------|------------|
| Amazon EKS (Bottlerocket AMI) | 1.22.6             | ✅            | ✅          |
| K3s (Rancher Desktop)         | 1.23.5             | ❌            | ✅          |
| Kind                          | 1.23.5             | ❌            | ✅          |
| OpenShift                     | 1.23.3             | ✅            | ✅          |


## Development receipts

### How to regenerate the eBPF Kernel binaries

The eBPF program is embedded into the `pkg/ebpf/bpf_*` generated files.
This step is generally not needed unless you change the C code in the `bpf` folder.

If you have Docker installed, you just need to run:

```
make docker-generate
```

If you can't install docker, you should locally install the following required packages:

```
dnf install -y kernel-devel make llvm clang glibc-devel.i686
make generate
```

Tested in Fedora 35 and Red Hat Enterprise Linux 8.

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

