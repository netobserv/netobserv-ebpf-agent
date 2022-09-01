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

#### User-space program Logic: (Refer [tracer.go](../pkg/ebpf/tracer.go))

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