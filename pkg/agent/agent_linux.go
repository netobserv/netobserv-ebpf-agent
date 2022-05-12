package agent

import (
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
)

var slog = logrus.WithField("component", "systemSetup")

// systemSetup holds some system-dependant initialization processes
func systemSetup() {
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.WithError(err).
			Warn("can't remove mem lock. The agent could not be able to start eBPF programs")
	}
}
