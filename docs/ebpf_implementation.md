## Flows v2: An improved version of Netobserv eBPF Agent

### What Changed?
At the eBPF/TC code, the v1 used a ringbuffer to export flow records to the userspace program.
Based on our measurements, ringbuffer can lead to a bottleneck since each a record for each packet in the data-path needs to be sent to the userspace, which eventually results in loss of records.
Additionally, this leads to high CPU utilization since the userspace program would be constantly active to handle callback events on a per-packet basis.  
Refer to the [Measurements slide-deck](./measurements.pptx) for performance measurements.  
To tackle this and achieve 100% monitoring coverage, the v2 eBPF/TC code uses a Per-CPU Hash Map to aggregate flow-based records in the eBPF data-path, and pro-actively send the records to userspace upon flow termination. The detailed logic is below:

#### eBPF Data-path Logic:
1) Store flow information in a per-cpu hash map. The key of such map is the flow identification
(addresses/ports, protocols, etc...) and the value are the flow metrics (packets, bytes and start/end time).
On a higher level note, need to check if increasing the map size (hash computation part) affect throughput.  
2) Upon Packet Arrival, a lookup is performed on the map.  
  * If the lookup is successful, then update the packet count, byte count, and the current timestamp.  
  * If the lookup is unsuccessful, then try creating a new entry in the map.
3) If entry creation failed due to a full map, then send the entry to userspace program via ringbuffer.  

##### Flow collisions
A downside of the eBPF PerCPU HashMap implementation is that memory is not zeroed when an entry is
removed. That causes that, after one entry is removed, if it is re-added again (or any other flow
that goes into the same HashTable bucket), the new flow metrics would be added to the slot
corresponding to the CPU that captured it, but the consecutive slots from other CPUs might contain
data from old flows. 

To deal with it, we need to discard old flow entries (whose endTime is previous to the last
flow eviction time) when we aggregate them at the userspace.

#### User-space program Logic: (Refer [pkg/tracer/tracer.go](../pkg/tracer/tracer.go) and [pkg/flow/](../pkg/flow/))

The userspace program has two active threads:  

* **Periodically evict aggregated flows' map**. Every period (defined by the `CACHE_ACTIVE_TIMEOUT`
  configuration variable), the eBPF map that is updated from the kernel space is completely read
  and its entries are removed, then sent to FlowLogs-Pipeline (or any other ingestion service).

* **Listen for flows ringbuffer**. When flows are received from the RingBuffer, they are aggregated
  at the user space before forwarding them periodically to the ingestion service.
  - Receiving a flow from the ringbuffer means that the eBPF aggregated map is full, so it also
    automatically triggers the eviction of the eBPF map to leave free space and minimize the usage
    of the ringbuffer (which, as explained before, is slower).

##### Flow Collision handling in user-space

Since the PerCPU HashMap stores one aggregated flow per each CPU, we need to aggregate all the
partial flow entries in the user space before sending the complete flow, discarding the flow entries
that might belong to old flow measurements (as explained in the kernel-side
[flow collisions](#flow-collisions) section).

#### Interface attribution across network namespaces

The flow identifier (5-tuple, etc.) intentionally excludes the interface index so that the same flow
observed on several interfaces (e.g. the two ends of a veth pair, which legitimately span two
namespaces) is aggregated into a single record carrying a list of observed interfaces. The interface
index alone is therefore not enough to name an interface: indexes are unique only within a network
namespace and collide across namespaces when secondary networks are used.

To disambiguate, each interface identity in `flow_metrics_t` (`if_index_first_seen` and each entry of
`observed_intf`) is paired with the network namespace cookie
([`bpf_get_netns_cookie`](https://docs.ebpf.io/linux/helper-function/bpf_get_netns_cookie/)) of the
namespace where it was seen (`netns_cookie_first_seen` and `observed_netns_cookie`). Userspace reads
the same value per namespace via the `SO_NETNS_COOKIE` socket option (they are guaranteed equal) and
keys the interface-name cache on `(netns_cookie, index)`.

The helper was only enabled for TC programs (`sched_cls`/`sched_act`) in kernel 6.13
([commit eb62f49](https://github.com/torvalds/linux/commit/eb62f49de7eca5917be8cebb3ad8aa3710af7021)),
so it is gated at load time by the `enable_netns_cookie` `.rodata` constant (dead-code-eliminated on
older kernels, where the helper needn't exist). The agent probes the running kernel for the helper
(`features.HaveProgramHelper`) instead of comparing kernel versions, so distro backports are detected automatically. The
same resolver decides both the eBPF gate and the userspace cookie computation so they never disagree. When disabled, cookies are 0 everywhere and attribution falls
back to the historical MAC-based heuristic. The cookie stays internal to the agent (not exported on
the wire). Genuine cross-namespace 5-tuple collisions (same 5-tuple in two namespaces at the same
time, rare and transient due to ephemeral ports) remain merged: this is inherent to keeping the
namespace out of the flow key so that veth-crossing deduplication keeps working.
