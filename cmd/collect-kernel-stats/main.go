//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type KernelStats struct {
	Timestamp            time.Time                     `json:"timestamp"`
	CollectionDuration   time.Duration                 `json:"collection_duration_ns"`
	ProgramStats         map[string]ProgramKernelStats `json:"program_stats"`
	TotalRuntime         time.Duration                 `json:"total_runtime_ns"`
	TotalRunCount        uint64                        `json:"total_run_count"`
	TotalEventsPerSec    float64                       `json:"total_events_per_sec"`
	TotalEstimatedCPU    float64                       `json:"total_estimated_cpu_percent"`
	TotalRecursionMisses uint64                        `json:"total_recursion_misses"`
	NumPrograms          int                           `json:"num_programs"`
}

type ProgramKernelStats struct {
	Name            string         `json:"name"`
	Type            string         `json:"type"`
	ID              ebpf.ProgramID `json:"id"`
	Runtime         time.Duration  `json:"runtime_ns"`
	RunCount        uint64         `json:"run_count"`
	EventsPerSec    float64        `json:"events_per_sec"`
	AvgRuntime      time.Duration  `json:"avg_runtime_ns"`
	EstimatedCPU    float64        `json:"estimated_cpu_percent"`
	RecursionMisses uint64         `json:"recursion_misses"`
}

func collectKernelStats(duration time.Duration) (*KernelStats, error) {
	// Enable BPF statistics collection
	closer, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
	if err != nil {
		return nil, fmt.Errorf("failed to enable BPF stats: %w", err)
	}
	defer closer.Close()

	logrus.Infof("Collecting kernel-space eBPF statistics for %v", duration)

	// Collect initial stats for all programs
	initialStats := make(map[ebpf.ProgramID]ProgramKernelStats)
	programInfo := make(map[ebpf.ProgramID]*ebpf.ProgramInfo)

	// Iterate over all loaded programs
	var progID ebpf.ProgramID = 0
	for {
		nextID, err := ebpf.ProgramGetNextID(progID)
		if err != nil {
			// ErrNotExist means no more programs, which is expected
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, ebpf.ErrNotSupported) {
				break
			}
			// Other errors are logged but we continue
			logrus.WithError(err).Warn("error getting next program ID")
			break
		}
		progID = nextID

		// Collect stats for all programs
		prog, err := ebpf.NewProgramFromID(progID)
		if err != nil {
			logrus.WithError(err).WithField("program_id", progID).Warn("failed to open program")
			continue
		}

		info, err := prog.Info()
		if err != nil {
			prog.Close()
			logrus.WithError(err).WithField("program_id", progID).Warn("failed to get program info")
			continue
		}

		stats, err := prog.Stats()
		if err != nil {
			prog.Close()
			logrus.WithError(err).WithField("program_id", progID).Warn("failed to get program stats")
			continue
		}

		programInfo[progID] = info
		initialStats[progID] = ProgramKernelStats{
			Name:            info.Name,
			Type:            info.Type.String(),
			ID:              progID,
			Runtime:         stats.Runtime,
			RunCount:        stats.RunCount,
			RecursionMisses: stats.RecursionMisses,
		}

		prog.Close()
	}

	if len(initialStats) == 0 {
		return nil, fmt.Errorf("no eBPF programs found")
	}

	logrus.Infof("Found %d eBPF programs, collecting stats for %v", len(initialStats), duration)

	// Wait for collection duration
	time.Sleep(duration)

	// Collect final stats and calculate metrics
	finalStats := make(map[string]ProgramKernelStats)
	var totalRuntime time.Duration
	var totalRunCount uint64
	var totalRecursionMisses uint64

	for progID, initialStat := range initialStats {
		prog, err := ebpf.NewProgramFromID(progID)
		if err != nil {
			continue
		}

		stats, err := prog.Stats()
		if err != nil {
			prog.Close()
			continue
		}

		info := programInfo[progID]
		deltaRuntime := stats.Runtime - initialStat.Runtime
		deltaRunCount := stats.RunCount - initialStat.RunCount
		deltaRecursionMisses := stats.RecursionMisses - initialStat.RecursionMisses

		var eventsPerSec float64
		var avgRuntime time.Duration
		var estimatedCPU float64

		if duration > 0 {
			eventsPerSec = float64(deltaRunCount) / duration.Seconds()
			if deltaRunCount > 0 && deltaRuntime >= 0 {
				avgRuntime = deltaRuntime / time.Duration(deltaRunCount)
				// Estimated CPU % = (total runtime / collection duration) * 100
				// deltaRuntime is in nanoseconds, duration.Seconds() is in seconds
				// Divide by 1e9 to convert ns to seconds, then multiply by 100 for percentage
				estimatedCPU = (float64(deltaRuntime) / duration.Seconds()) / 1e9 * 100
			}
		}

		finalStats[info.Name] = ProgramKernelStats{
			Name:            info.Name,
			Type:            info.Type.String(),
			ID:              progID,
			Runtime:         deltaRuntime,
			RunCount:        deltaRunCount,
			EventsPerSec:    eventsPerSec,
			AvgRuntime:      avgRuntime,
			EstimatedCPU:    estimatedCPU,
			RecursionMisses: deltaRecursionMisses,
		}

		totalRuntime += deltaRuntime
		totalRunCount += deltaRunCount
		totalRecursionMisses += deltaRecursionMisses

		prog.Close()
	}

	var totalEventsPerSec float64
	var totalEstimatedCPU float64
	if duration > 0 {
		totalEventsPerSec = float64(totalRunCount) / duration.Seconds()
		// Only calculate CPU if we have positive runtime (negative would indicate counter issues)
		if totalRuntime >= 0 {
			totalEstimatedCPU = (float64(totalRuntime) / duration.Seconds()) / 1e9 * 100
		}
	}

	return &KernelStats{
		Timestamp:            time.Now(),
		CollectionDuration:   duration,
		ProgramStats:         finalStats,
		TotalRuntime:         totalRuntime,
		TotalRunCount:        totalRunCount,
		TotalEventsPerSec:    totalEventsPerSec,
		TotalEstimatedCPU:    totalEstimatedCPU,
		TotalRecursionMisses: totalRecursionMisses,
		NumPrograms:          len(finalStats),
	}, nil
}

func main() {
	var (
		duration = flag.Duration("duration", 60*time.Second, "Duration to collect statistics")
		output   = flag.String("output", "", "Output JSON file (default: stdout)")
		verbose  = flag.Bool("verbose", false, "Enable verbose logging")
	)
	flag.Parse()

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	stats, err := collectKernelStats(*duration)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to collect kernel statistics")
	}

	jsonData, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		logrus.WithError(err).Fatal("Failed to marshal statistics to JSON")
	}

	if *output != "" {
		if err := os.WriteFile(*output, jsonData, 0644); err != nil {
			logrus.WithError(err).Fatal("Failed to write output file")
		}
		logrus.Infof("Kernel statistics saved to %s", *output)
	} else {
		fmt.Println(string(jsonData))
	}
}
