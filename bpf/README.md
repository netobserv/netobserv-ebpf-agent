## Flows v2: An improved version of Netobserv eBPF Agent

### What Changed?
At the eBPF/TC code, the v1 used a ringbuffer to export flow records to the userspace program.
Based on our measurements, ringbuffer can lead to a bottleneck since each a record for each packet in the data-path needs to be sent to the userspace, which eventually results in loss of records.
Additionally, this leads to high CPU utilization since the userspace program would be constantly active to handle callback events on a per-packet basis.  
Refer to the [Measurements slide-deck](../docs/measurements.pptx) for performance measurements.  
To tackle this and achieve 100% monitoring coverage, the v2 eBPF/TC code uses a Per-CPU Hash Map to aggregate flow-based records in the eBPF data-path, and pro-actively send the records to userspace upon flow termination. The detailed logic is below:

#### eBPF Data-path Logic:
1) Store flow information in a per-cpu hash map. A separate per-cpu hash map is maintained for ingress and egress to avoid performance bottlenecks.
One design choice that needs to be concretized with performance measurements is to whether v4 and v6 IPs need to be maintained in the same map or a different one.  
On a higher level note, need to check if increasing the map size (hash computation part) affect throughput.  
2) Upon Packet Arrival, a lookup is performed on the map.  
  * If the lookup is successful, then update the packet count, byte count, and the current timestamp.  
  * If the lookup is unsuccessful, then try creating a new entry in the map.  

3) If entry creation failed due to a full map, then send the entry to userspace program via ringbuffer.  
4) Upon flow completion (tcp->fin/rst event), send the flow-id to userspace via ringbuffer.

##### Hash collisions
One downside of using hash-based map is, When flows are hashed to the per-cpu map, there is a possibility of hash collisions occuring which would make multiple different flows map into the same entry. As a result, it might lead to inaccurate flow entries. To handle hash collisions we do the following :
1) In each flow entry, we additionally maintain the full key/id.
2) Before a packet's id is updated to map, the key is additionally compared to check if there is another flow residing in the map.
3) If there is another flow, we do want to update the entry wrongly. Hence, we send the new packet entry directly to userspace via ringbuffer after updating a flag to inform of collision.

To detect and handle
#### User-space program Logic: (Refer [tracer.go](../pkg/ebpf/tracer.go))
The userspace program has three active threads:  

1) **Trace** :     
a) If the received flow-id is a flow completion (indicated via the flags) from eBPF data-path via ringbuffer and does the following:  
* ScrubFlow : Performs lookup of the flow-id in the ingress/egress map and aggregates the metrics from different CPU specific counters. Then deletes the entry corresponding to the flow-id from the map.  
* Exports the aggregated flow record to the accounter pipeline.  
b) If the received flow-id is not a flow completion event, then just forward this record to accounter pipeline. It will be aggregated in future by accounter upon flow completion.

2) **MonitorIngress** :
This is a periodic thread which wakes up every n seconds and does the following :  
a) Create a map iterator, and iterates over each entry in the map.  
b) Evict an entry if the condition is met :
  * If the timestamp of the last seen packet in the flow is more than m seconds ago.  
  * There are other options for eviction that can be implemented, either based on the packets/bytes observed. Or a more aggressive eviction if the map is k% full. These are further improvements that can be performed to fine-tune the map usage based on the scenario and use-case.

c) The evicted entry is aggregated into a flow-record and forwarded to the accounter pipeline.

3) **MonitorEgress** :  
This is a period thread, which does the same task as MonitorIngress, but only the map is egress.

##### Hash Collision handling in user-space
Inspite of handling hash collisions in the eBPF datapath, there is still a chance of multiple flows mapping to the same map, since per-cpu map maintains a separate entries per-cpu. Hence, its possible that multiple flows from different CPUs can map into the same entry, but are in different buckets. Hence, during aggregation of entries, we check the key before aggregating the entries per-flow. Upon detection of such entries, we export the entry to accounter. Now since the flow key is stored along with each entry, we can recover such collided entries and send to accounter.
