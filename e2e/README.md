## eBPF Agent e2e tests

e2e tests can be run with:

```bash
make tests-e2e
```

If you use podman, you may need to run it as root instead:

```bash
sudo make tests-e2e
```

### What it does

It builds an image with the current code, including pre-generated BPF bytecode, starts a KIND cluster and deploys the agent on it. It also deploys a typical NetObserv stack, that includes flowlogs-pipeline, Loki and/or Kafka.

It then runs smoke tests on that cluster, such as sending pings between pods and verifying that the expected flows are created. Test packages live under `e2e/flows/` (flow mode) and `e2e/packets/` (packet capture mode).

The tests leverage Kube's [e2e-framework](https://github.com/kubernetes-sigs/e2e-framework). They are based on manifest files that you can find in [this directory](./cluster/base/).

### Endpoint dictionary kernel tests

The `integration` tests in `pkg/tracer/flows` exercise drops-only interning,
dictionary saturation, and verifier loading of the tracing programs. They require
a kernel supporting those hooks and the drop-reason field in `kfree_skb`, BPF and
network administration privileges, and tracefs. Load the host's `psample` module
before testing network-event tracking (for example, `sudo modprobe psample`).

Run them in an isolated privileged container: the drops test creates temporary
veth links and a network namespace. After `make docker-generate` has built the
generator image and refreshed the bytecode:

```bash
go test -mod vendor -tags integration -c -o /tmp/netobserv-endpoints.test ./pkg/tracer/flows
docker run --rm --privileged \
  -v /tmp/netobserv-endpoints.test:/endpoints.test:ro \
  --entrypoint bash ebpf-generator:latest -c \
  'mount -t tracefs tracefs /sys/kernel/tracing && /endpoints.test -test.v -test.run "Test(EndpointDictionarySaturation|EndpointTracingProgramsLoad|DropsOnlyInternsUnseenEndpoints)$"'
```

The saturation test records a **remaining limitation**: evicting flows does not
reclaim dictionary entries, so new addresses stop producing flows at capacity.
A passing test does not mean that endpoint reclamation has been implemented.

### How to troubleshoot

During the tests, you can run any `kubectl` command to the KIND cluster.

If you use podman/root and don't want to open a root session you can simply copy the root kube config:

```bash
sudo cp /root/.kube/config /tmp/agent-kind-kubeconfig
sudo -E chown $USER:$USER /tmp/agent-kind-kubeconfig
export KUBECONFIG=/tmp/agent-kind-kubeconfig
```

Then:

```bash
$ kubectl get pods
NAME                    READY   STATUS    RESTARTS   AGE
flp-29bmd               1/1     Running   0          6s
loki-7c98dfd6d4-c8q9m   1/1     Running   0          56s
```

### Cleanup

The KIND cluster should be cleaned up after tests. Sometimes it won't, like with forced exit or for some kinds of failures.
When that's the case, you should see a message telling you to manually cleanup the cluster:

```
^CSIGTERM received, cluster might still be running
To clean up, run: kind delete cluster --name basic-test-cluster20241212-125815
FAIL	github.com/netobserv/netobserv-ebpf-agent/e2e/flows	172.852s
```

If that's not the case, you can manually retrieve the cluster name to delete:

```bash
$ kind get clusters
basic-test-cluster20241212-125815

$ kind delete cluster --name=basic-test-cluster20241212-125815
Deleting cluster "basic-test-cluster20241212-125815" ...
Deleted nodes: ["basic-test-cluster20241212-125815-control-plane"]
```

If not cleaned up, a subsequent run of e2e tests will fail due to addresses (ports) already in use.
