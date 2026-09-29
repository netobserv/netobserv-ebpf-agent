# Empty BPF map memory

This diagnostic allocates selected maps from an existing BPF ELF, then reports
JSON snapshots before allocation, after allocation, and after closing the maps.
It does not load programs, attach hooks, pin maps, or modify a running agent.

Use a fresh, otherwise idle cgroup v2 for every run. For example, from the
repository root on Linux with Docker and a locally built `ebpf-generator:latest`:

```sh
CGO_ENABLED=0 go build -o /tmp/map-memory ./tools/map-memory
mkdir -p /tmp/map-memory-results
for capacity in 0 1; do
  for repeat in 1 2 3 4 5; do
    docker run --rm --privileged --cgroupns=private \
      --security-opt label=disable \
      -v /tmp/map-memory:/measure:ro \
      -v "$PWD/pkg/ebpf/flows/bpf_x86_bpfel.o:/object.o:ro" \
      --entrypoint /measure ebpf-generator:latest \
      -object /object.o \
      -maps quic_flows,ssl_read_active_map,ssl_fd_map \
      -max-entries "$capacity" \
      > "/tmp/map-memory-results/flows-$capacity-$repeat.jsonl"
  done
done
```

`-max-entries 0` preserves ELF capacities; `1` models the disabled feature maps.
For packet mode, use `pkg/ebpf/packets/packets_x86_bpfel.o` and select only
`ssl_read_active_map,ssl_fd_map`. Use the ELF matching your architecture.
The OpenSSL ring buffer is excluded because it was already minimized when
tracking was disabled. A ring buffer cannot use capacity 1.

Compare `allocated.cgroup_current - before.cgroup_current` across repeated runs,
and inspect `cgroup_stat` (especially `kernel`, `slab`, and `anon`). Record the
kernel version and `possible_cpus`. Cgroup deltas include allocator noise and the
measurement process; use medians and ranges rather than a single run. The
`closed` snapshot helps identify unrelated growth or delayed kernel reclamation.
`reported_bytes` is the kernel's approximate per-map accounting, not a substitute
for the cgroup measurement. This test measures empty-map allocation, not occupied
maps, agent RSS, throughput, or cluster-wide memory savings.

## Example: disabled QUIC and OpenSSL maps

On Linux `7.2.7-200.fc44.x86_64`, with 16 possible CPUs and five fresh-container
runs per configuration, the median allocation deltas were:

| Object / selected maps | Original maps | Minimized maps | Reduction |
| --- | ---: | ---: | ---: |
| Flow / QUIC + two OpenSSL state maps | 4.035 MiB | 0.148 MiB | 3.887 MiB |
| Packet / two OpenSSL state maps | 3.352 MiB | 0.492 MiB | 2.860 MiB |

These are `memory.current` deltas for the selected empty maps and the measurement
process, not total agent memory. The corresponding median `memory.stat` kernel
deltas decreased by 3.887 MiB and 2.887 MiB. Across runs, `memory.current` deltas
ranged from 3.824–4.266 MiB / 0.117–0.637 MiB for flow maps and
3.090–3.559 MiB / 0.215–0.703 MiB for packet maps (ELF / one-entry capacities).
Savings depend on kernel allocation details and CPU count; enabled maps retain
their full capacity.
