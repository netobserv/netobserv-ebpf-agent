package ebpf

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type event_t -type ident_t BpfSock ../../bpf/sock-agent/tcp_sockets.c -- -I../../bpf/headers

func NewSockFetcher() (*FlowFetcher, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.WithError(err).
			Warn("can't remove mem lock. The agent could not be able to start eBPF programs")
	}

	objects := BpfSockObjects{}
	spec, err := LoadBpfSock()
	if err != nil {
		return nil, fmt.Errorf("loading BPF socket data: %w", err)
	}

	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// Using %+v will print the whole verifier error, not just the last
			// few lines.
			log.Infof("Verifier error: %+v", ve)
		}
		return nil, fmt.Errorf("loading and assigning BPF socket objects: %w", err)
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	tp, err := link.Tracepoint("sock", "inet_sock_set_state", objects.BpfSockPrograms.InetSockSetState, nil)
	if err != nil {
		log.Printf("failed to attach the BPF program to inet_sock_set_state tracepoint: %v", err)
		return nil, err
	}
	// defined in the BPF C program.
	rd, err := perf.NewReader(objects.Events, os.Getpagesize())
	if err != nil {
		log.Printf("failed to create perf event reader: %v", err)
		return nil, err
	}

	go func() {
		<-stopper
		rd.Close()
		tp.Close()
	}()

	return &FlowFetcher{
		perfobjects:   &objects,
		perfbufReader: rd,
	}, nil
}

func (m *FlowFetcher) ReadPerfBuf() (perf.Record, error) {
	return m.perfbufReader.Read()
}
