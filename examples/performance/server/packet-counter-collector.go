package main

import (
	"flag"
	"log"
	"time"

	grpc "github.com/netobserv/netobserv-ebpf-agent/pkg/grpc/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"github.com/paulbellamy/ratecounter"
)

var (
	port = flag.Int("port", 9999, "TCP port to listen for flows")
)

// Simple Flow collector that just counts the rate of packets and flows that are received
func main() {
	flag.Parse()

	packets := ratecounter.NewRateCounter(60 * time.Second)
	flows := ratecounter.NewRateCounter(60 * time.Second)
	go func() {
		ticker := time.Tick(5 * time.Second)
		for {
			<-ticker
			log.Printf("%.1f packets/s. %.1f flows/s",
				float64(packets.Rate())/60.0, float64(flows.Rate())/60.0)
		}
	}()
	receivedRecords := make(chan *pbflow.Records, 100)
	log.Println("starting flow collector in port", *port)
	go func() {
		_, err := grpc.StartCollector(*port, receivedRecords)
		if err != nil {
			panic(err)
		}
	}()
	for records := range receivedRecords {
		for _, record := range records.Entries {
			flows.Incr(1)
			packets.Incr(int64(record.Packets))
		}
	}
}
