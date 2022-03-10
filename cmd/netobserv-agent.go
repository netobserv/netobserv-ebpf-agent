//go:build linux

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/netobserv/netobserv-agent/pkg/connect"
)

var (
	interfaceName = flag.String("iface", "eth0", "interface to attach to")
	reportFreq    = flag.Duration("freq", 5*time.Second, "frequency of on-screen reporting")
)

func main() {
	flag.Parse()

	monitor := connect.NewMonitor(*interfaceName)
	if err := monitor.Start(); err != nil {
		log.Fatalf("starting monitor: %s", err)
	}

	go func() {
		for {
			time.Sleep(*reportFreq)
			fmt.Println("PROTOCOL SOURCE                DESTINATION           PACKETS BYTES")
			stats := monitor.Stats()
			sort.SliceStable(stats, func(i, j int) bool {
				return stats[i].Bytes > stats[j].Bytes
			})
			for _, egress := range stats {
				fmt.Printf("%-8s %-21s %-21s %-7d %-7s\n",
					egress.Protocol,
					fmt.Sprintf("%s:%d", egress.SrcIP, egress.SrcPort),
					fmt.Sprintf("%s:%d", egress.DstIP, egress.DstPort),
					egress.Packets, egress.Bytes)
			}
		}
	}()

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
	log.Println("stopping server and closing resources")
	if err := monitor.Stop(); err != nil {
		log.Printf("error stopping server: %s", err)
	}
}
