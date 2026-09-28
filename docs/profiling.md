# Profiling guide

1. Run the agent with the `PPROF_ADDR` variable set to a listening address. For security, prefer using the local loop ("127.0.0.1:6060") rather than a broader exposition ("0.0.0.0:6060" or ":6060"), or make sure to restrict who has access to this address, as it can leak sensitive data.
   - If you are executing the agent from the NetObserv Operator, you can do it by
     adding the following section to your `ebpf` spec:

   ```yaml
   apiVersion: flows.netobserv.io/v1alpha1
   kind: FlowCollector
   metadata:
     name: cluster
   spec:
     agent:
       ebpf:
         advanced:
           env:
             PPROF_ADDR: "127.0.0.1:6060"
    ```

2. If you are running Kubernetes, port-forward the pod that you want to profile.

    ```
    kubectl -n netobserv-privileged port-forward <netobserv-ebpf-agent pod name> 6060
    ```
   
3. Download the required profiles:

   ```
   curl -o <profile> http://localhost:6060/debug/pprof/<profile>
   ```
   
   Where `<profile>` can be:

* `allocs`: A sampling of all past memory allocations
* `block`: Stack traces that led to blocking on synchronization primitives
* `cmdline`: The command line invocation of the current program
* `goroutine`: Stack traces of all current goroutines
* `heap`: A sampling of memory allocations of live objects.
  * You can specify the `gc` GET parameter to run GC before taking the heap sample.
* `mutex`: Stack traces of holders of contended mutexes
* `profile`: CPU profile.
  * You can specify the `duration` in the seconds GET parameter.
* `threadcreate`: Stack traces that led to the creation of new OS threads
* `trace`: A trace of execution of the current program.
  * You can specify the `duration` in the seconds GET parameter.

Example:

```
curl "http://localhost:6060/debug/pprof/trace?seconds=20" -o trace20s
curl "http://localhost:6060/debug/pprof/profile?duration=20" -o profile20s
curl "http://localhost:6060/debug/pprof/heap?gc" -o heap
curl "http://localhost:6060/debug/pprof/allocs" -o allocs
curl "http://localhost:6060/debug/pprof/goroutine" -o goroutine
```

4. Use `go tool pprof` to dig into the profiles (`go tool trace` for the `trace` profile)

## Endpoint indexing experiment

Compare a build using full IP addresses in flow keys with the indexed build under
the same workload, sampling, flow-map capacity, timeout, feature set, and CPU count.
Record `ENDPOINT_MAP_MAX_ENTRIES` explicitly. Run both with the default dictionary
capacity and a smaller capacity sized for the experiment's **cumulative** distinct
addresses. Do not infer production memory savings from an artificially small map.

Include these workloads:

| Workload | Purpose |
| --- | --- |
| Idle, then default 5,000-flow capacity | Measure fixed dictionary overhead against small flow maps |
| Many flows sharing few addresses | Measure the intended benefit from address reuse |
| Many distinct addresses and sustained churn | Measure dictionary growth, insertion cost, and saturation |
| Multiple sending CPUs | Exercise contention on endpoint allocation |
| Drops-only filtering and optional tracing features | Check telemetry correctness independently of accepted TC packets |

Measure throughput, agent CPU, export duration, allocations/GC, peak process and
cgroup memory, and kernel map memory. Account for both dictionaries, their counter,
all enabled flow maps, and userspace records; Go heap profiles alone exclude BPF
map memory. Verify exported IPs and packet/byte counts, and check the
`CannotAssignEndpointID` dropped-flow and `CannotResolveEndpoint` error metrics alongside resource
usage. A lower resource count caused by missing flows is not an improvement.

The eviction microbenchmark uses valid endpoint mappings but an in-memory fetcher:

```bash
go test -mod vendor -run '^$' -bench BenchmarkEvictFlows -benchmem ./pkg/flow
```

It measures userspace batch conversion, not BPF insertion, map syscalls, or packet
throughput. Kernel regression test instructions are in [e2e/README.md](../e2e/README.md#endpoint-dictionary-kernel-tests).
Endpoint reclamation remains unresolved; a successful performance experiment alone
does not make the current dictionary lifecycle safe for production.
