# Kernel-Space eBPF Statistics Collector

This tool collects kernel-space performance statistics for running eBPF programs, similar to [bpftop](https://github.com/Netflix/bpftop). It uses the `BPF_ENABLE_STATS` syscall to gather runtime statistics directly from the kernel.

## Overview

Unlike user-space metrics (CPU, memory usage of the userspace agent), kernel-space metrics capture the actual performance of eBPF programs running in the kernel:

- **Runtime**: Total time spent executing eBPF programs
- **Run Count**: Number of times programs executed
- **Events Per Second**: Rate of program executions
- **Average Runtime**: Average execution time per program run
- **Estimated CPU %**: Estimated CPU percentage used by eBPF programs
- **Recursion Misses**: Number of times programs couldn't run due to recursion limits

## Building

```bash
go build -o collect-kernel-stats ./cmd/collect-kernel-stats
```

Or using make (add to Makefile):

```bash
make collect-kernel-stats
```

## Usage

### Basic Usage

Collect statistics for 60 seconds (default):

```bash
sudo ./collect-kernel-stats
```

### Options

```bash
./collect-kernel-stats [OPTIONS]

Options:
  -duration duration    Duration to collect statistics (default: 60s)
  -output string         Output JSON file (default: stdout)
  -verbose               Enable verbose logging
```

### Examples

```bash
# Collect for 5 minutes and save to file
sudo ./collect-kernel-stats -duration 5m -output kernel-stats.json

# Collect for 30 seconds and print to stdout
sudo ./collect-kernel-stats -duration 30s

# Verbose output
sudo ./collect-kernel-stats -duration 2m -verbose
```

## Requirements

- **Root privileges**: Must run with `sudo` (required for `BPF_ENABLE_STATS` syscall)
- **Linux kernel 5.8+**: Required for eBPF statistics support
- **eBPF programs loaded**: The tool will only collect stats if eBPF programs are currently loaded

## Output Format

The tool outputs JSON with the following structure:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "program_stats": {
    "tc_ingress_flow_parse": {
      "name": "tc_ingress_flow_parse",
      "type": "SchedCLS",
      "id": 42,
      "runtime_ns": 1234567890,
      "run_count": 1000000,
      "events_per_sec": 16666.67,
      "avg_runtime_ns": 1234,
      "estimated_cpu_percent": 1.23,
      "recursion_misses": 0
    },
    ...
  },
  "total_runtime_ns": 9876543210,
  "total_run_count": 5000000,
  "total_events_per_sec": 83333.33,
  "total_estimated_cpu_percent": 9.88,
  "num_programs": 8
}
```

## Integration with Performance Tests

### Automatic Collection During e2e Tests

Kernel stats are **automatically collected** during e2e tests when you run:

```bash
make tests-e2e
```

The kernel stats will be saved to `e2e-logs/{cluster-name}/kernel-stats.json` after the tests complete.

### Manual Collection

To collect kernel-space metrics manually during performance tests:

1. **Start the eBPF agent** (which loads the eBPF programs)
2. **Run the performance test** (generate traffic)
3. **Collect kernel stats** in parallel:

```bash
sudo ./bin/collect-kernel-stats -duration 5m -output kernel-stats-$(date +%s).json
```

### Baseline Comparison

You can automatically compare kernel stats against the main branch:

```bash
make tests-e2e BASELINE=true
```

This will:
- Run e2e tests with main branch image and collect baseline stats
- Run e2e tests with your branch image and collect current stats
- Generate a comparison visualization at `perf/kernel-comparison-main.png`

See [e2e/README.md](../../e2e/README.md) for more details.

## Integration with Visualization

The kernel stats can be integrated into the performance visualization by:

1. Collecting kernel stats during performance runs (automatically during e2e tests)
2. Storing the JSON output alongside CSV performance data
3. Using the visualization script with kernel stats support (see `scripts/visualize_ebpf_performance.py`)

**Examples:**

```bash
# Visualize kernel stats only
python3 scripts/visualize_ebpf_performance.py --kernel-stats e2e-logs/*/kernel-stats.json

# Compare with baseline (main branch)
python3 scripts/visualize_ebpf_performance.py \
  --kernel-stats perf/kernel-stats-current.json \
  --kernel-stats-baseline perf/kernel-stats-main.json \
  --output perf/comparison.png
```

## How It Works

1. **Enable Statistics**: Uses `ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)` to enable kernel statistics collection
2. **Discover Programs**: Iterates through all loaded eBPF programs using `ebpf.ProgramGetNextID()` - captures all program IDs
3. **Collect Baseline**: Records initial stats for each program
4. **Wait**: Collects statistics for the specified duration
5. **Collect Final**: Records final stats and calculates deltas (runtime, run count, etc.)
6. **Calculate Metrics**: Computes events/sec, average runtime, and estimated CPU usage
7. **Generate Report**: Outputs JSON with statistics for all collected programs

## Program IDs

The tool collects statistics for **all** loaded eBPF programs in the system. Each eBPF program has a unique **program ID** assigned by the kernel when loaded.

### How Program IDs Work

- Each eBPF program gets a unique **program ID** assigned by the kernel when loaded
- Program IDs are assigned sequentially as programs are loaded
- The tool captures all program IDs during collection and includes them in the output

### Viewing Program IDs

To see all program IDs collected:

```bash
# Quick 1-second collection to see all program IDs
sudo ./collect-kernel-stats -duration 1s | jq '.program_stats[].id'

# Or extract min/max IDs
MIN_ID=$(sudo ./collect-kernel-stats -duration 1s | jq '[.program_stats[].id] | min')
MAX_ID=$(sudo ./collect-kernel-stats -duration 1s | jq '[.program_stats[].id] | max')
```

### Multiple Agents in Same Cluster

When multiple eBPF agents run in the same cluster (e.g., for benchmark comparisons), the tool collects statistics for **all** loaded programs from all agents. This allows for comprehensive comparison of performance across different agent versions running simultaneously.

## Comparison with bpftop

This tool is similar to Netflix's `bpftop` but:
- **Outputs JSON** for easy integration with automation
- **Non-interactive** by default (suitable for CI/CD)
- **Built with Go** using the same cilium/ebpf library as the agent
- **Focuses on aggregation** over a collection period rather than real-time display

## Troubleshooting

**"No eBPF programs found"**
- Ensure the eBPF agent is running and has loaded programs
- Check that programs are loaded: `sudo bpftool prog list`

**"Failed to enable BPF stats"**
- Requires Linux kernel 5.8+ with `CONFIG_BPF_STATS` enabled
- Must run with root privileges

**"Permission denied"**
- The tool requires `sudo` to access kernel eBPF statistics

## References

- [bpftop](https://github.com/Netflix/bpftop) - Netflix's interactive eBPF monitoring tool
- [BPF_ENABLE_STATS documentation](https://www.kernel.org/doc/html/latest/bpf/bpf_stats.html)
- [cilium/ebpf library](https://github.com/cilium/ebpf)

