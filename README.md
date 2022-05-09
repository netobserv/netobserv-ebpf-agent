# Network Observability eBPF Agent

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

## How to configure

The eBPF Agent is configured by means of environment variables. Check the
[configuration documentation](./docs/config.md) for more details.

## How to run

The NetObserv eBPF Agent is designed to run as a DaemonSet in OpenShift/K8s. It is triggered and
configured by our [Network Observability Operator](https://github.com/netobserv/network-observability-operator).

Anyway you can run it directly as an executable with administrative privileges:

```
export FLOWS_TARGET_HOST=...
export FLOWS_TARGET_PORT=...
sudo -E bin/netobserv-ebpf-agent
```
To deploy locally, use instructions from [flowlogs-dump (like tcpdump)](./examples/flowlogs-dump/README.md).    
To deploy it as a Pod, you can check the [deployment example](./examples/performance/deployment.yml).

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

In your [deployment file](./deployments/flp-daemonset.yml), make sure that the container runs both
in privileged mode and as root user:

```yaml
      containers:
      - name: netobserv-ebpf-agent
        image: quay.io/netobserv/netobserv-ebpf-agent:main
        securityContext:
          privileged: true
          runAsUser: 0
```

### The Agent doesn't work in my Amazon EKS puzzle

Despite Amazon Linux 2 enables eBPF by default in EC2, the
[EKS images are shipped with disabled eBPF](https://github.com/awslabs/amazon-eks-ami/issues/728).

You'd need either:

1. Provide your own AMI configured to work with eBPF
2. Use other Linux distributions that are shipped with eBPF enabled by default. We have successfully
   tested the eBPF Agent in EKS with the [Bottlerocket](https://aws.amazon.com/es/bottlerocket/)
   Linux distribution, without requiring any extra configuration.

