// map-memory measures empty BPF maps in an isolated cgroup, without loading or
// attaching programs. Run once per fresh cgroup for comparable measurements.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

type mapReport struct {
	Name          string  `json:"name"`
	Type          string  `json:"type"`
	KeyBytes      uint32  `json:"key_bytes"`
	ValueBytes    uint32  `json:"value_bytes"`
	Capacity      uint32  `json:"capacity"`
	ReportedBytes *uint64 `json:"reported_bytes,omitempty"`
}

type snapshot struct {
	Stage         string            `json:"stage"`
	PossibleCPUs  int               `json:"possible_cpus"`
	CgroupCurrent uint64            `json:"cgroup_current"`
	CgroupStat    map[string]uint64 `json:"cgroup_stat"`
	Maps          []mapReport       `json:"maps,omitempty"`
}

func main() {
	object := flag.String("object", "", "BPF ELF to read map definitions from")
	names := flag.String("maps", "", "comma-separated map names to allocate")
	capacity := flag.Uint64("max-entries", 0, "override all selected map capacities (0 preserves ELF values)")
	cgroup := flag.String("cgroup", "/sys/fs/cgroup", "isolated cgroup v2 directory for this process")
	settle := flag.Duration("settle", time.Second, "wait before each memory snapshot")
	flag.Parse()
	if err := run(*object, *names, *capacity, *cgroup, *settle); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(object, names string, capacity uint64, cgroup string, settle time.Duration) error {
	if object == "" || names == "" || capacity > 1<<32-1 || settle < 0 {
		return fmt.Errorf("require object, map names, uint32 capacity, and nonnegative settle")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock limit: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		return err
	}
	// Keep ELF parsing allocations alive across snapshots so their collection does
	// not conceal the kernel allocation we are measuring.
	defer runtime.KeepAlive(spec)
	selected := strings.Split(names, ",")
	seen := map[string]bool{}
	for _, name := range selected {
		if spec.Maps[name] == nil || seen[name] {
			return fmt.Errorf("unknown or duplicate map %q", name)
		}
		seen[name] = true
	}
	maps := make(map[string]*ebpf.Map, len(selected))
	defer func() {
		for _, m := range maps {
			_ = m.Close()
		}
	}()
	if err := report("before", cgroup, settle, maps); err != nil {
		return err
	}
	for _, name := range selected {
		m := spec.Maps[name].Copy()
		m.Pinning = ebpf.PinNone
		if capacity != 0 {
			m.MaxEntries = uint32(capacity)
		}
		maps[name], err = ebpf.NewMap(m)
		if err != nil {
			delete(maps, name)
			return fmt.Errorf("allocate %s: %w", name, err)
		}
	}
	if err := report("allocated", cgroup, settle, maps); err != nil {
		return err
	}
	for name, m := range maps {
		if err := m.Close(); err != nil {
			return err
		}
		delete(maps, name)
	}
	return report("closed", cgroup, settle, maps)
}

func report(stage, cgroup string, settle time.Duration, maps map[string]*ebpf.Map) error {
	debug.FreeOSMemory()
	time.Sleep(settle)
	current, err := os.ReadFile(filepath.Join(cgroup, "memory.current"))
	if err != nil {
		return err
	}
	bytes, err := strconv.ParseUint(strings.TrimSpace(string(current)), 10, 64)
	if err != nil {
		return err
	}
	stat, err := os.ReadFile(filepath.Join(cgroup, "memory.stat"))
	if err != nil {
		return err
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return err
	}
	s := snapshot{Stage: stage, PossibleCPUs: cpus, CgroupCurrent: bytes, CgroupStat: map[string]uint64{}}
	fields := strings.Fields(string(stat))
	for i := 0; i+1 < len(fields); i += 2 {
		value, err := strconv.ParseUint(fields[i+1], 10, 64)
		if err != nil {
			return err
		}
		s.CgroupStat[fields[i]] = value
	}
	for name, m := range maps {
		info, err := m.Info()
		if err != nil {
			return err
		}
		entry := mapReport{Name: name, Type: info.Type.String(), KeyBytes: info.KeySize, ValueBytes: info.ValueSize, Capacity: info.MaxEntries}
		if n, ok := info.Memlock(); ok {
			entry.ReportedBytes = &n
		}
		s.Maps = append(s.Maps, entry)
	}
	return json.NewEncoder(os.Stdout).Encode(s)
}
