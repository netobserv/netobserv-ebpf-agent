package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	ipfixCollector "github.com/vmware/go-ipfix/pkg/collector"
	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
)

const (
	hostPortIPv4 = "127.0.0.1:9999"
	hostPortIPv6 = "[::1]:0"
)

var (
	transportType = flag.String("transport", "tcp", "transport type :tcp/udp")
)

func printIPFIXMessage(msg *entities.Message) {
	var buf bytes.Buffer
	fmt.Fprint(&buf, "\nIPFIX-HDR:\n")
	fmt.Fprintf(&buf, "  version: %v,  Message Length: %v\n", msg.GetVersion(), msg.GetMessageLen())
	fmt.Fprintf(&buf, "  Exported Time: %v (%v)\n", msg.GetExportTime(), time.Unix(int64(msg.GetExportTime()), 0))
	fmt.Fprintf(&buf, "  Sequence No.: %v,  Observation Domain ID: %v\n", msg.GetSequenceNum(), msg.GetObsDomainID())

	set := msg.GetSet()
	if set.GetSetType() == entities.Template {
		fmt.Fprint(&buf, "TEMPLATE SET:\n")
		for i, record := range set.GetRecords() {
			fmt.Fprintf(&buf, "  TEMPLATE RECORD-%d:\n", i)
			for _, ie := range record.GetOrderedElementList() {
				elem := ie.GetInfoElement()
				fmt.Fprintf(&buf, "    %s: len=%d (enterprise ID = %d) \n", elem.Name, elem.Len, elem.EnterpriseId)
			}
		}
	} else {
		fmt.Fprint(&buf, "DATA SET:\n")
		for i, record := range set.GetRecords() {
			fmt.Fprintf(&buf, "  DATA RECORD-%d:\n", i)
			for _, ie := range record.GetOrderedElementList() {
				elem := ie.GetInfoElement()
				switch elem.DataType {
				case entities.Unsigned8:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetUnsigned8Value())
				case entities.Unsigned16:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetUnsigned16Value())
				case entities.Unsigned32:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetUnsigned32Value())
				case entities.Unsigned64:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetUnsigned64Value())
				case entities.Signed8:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetSigned8Value())
				case entities.Signed16:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetSigned16Value())
				case entities.Signed32:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetSigned32Value())
				case entities.Signed64:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetSigned64Value())
				case entities.Float32:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetFloat32Value())
				case entities.Float64:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetFloat64Value())
				case entities.Boolean:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetBooleanValue())
				case entities.DateTimeSeconds:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetUnsigned32Value())
				case entities.DateTimeMilliseconds:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetUnsigned64Value())
				case entities.DateTimeMicroseconds, entities.DateTimeNanoseconds:
					err := fmt.Errorf("API does not support micro and nano seconds types yet")
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, err)
				case entities.MacAddress:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetMacAddressValue())
				case entities.Ipv4Address, entities.Ipv6Address:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetIPAddressValue())
				case entities.String:
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, ie.GetStringValue())
				default:
					err := fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, err)
				}
			}
		}
	}
	log.Printf(buf.String())
}

func signalHandler(stopCh chan struct{}, messageReceived chan *entities.Message) {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	for {
		select {
		case msg := <-messageReceived:
			printIPFIXMessage(msg)
		case <-signalCh:
			close(stopCh)
			return
		}
	}
}

func main() {
	log.SetFlags(0)
	flag.Parse()

	// Create exporter using local server info
	var input = ipfixCollector.CollectorInput{
		Address:       hostPortIPv4,
		Protocol:      *transportType,
		MaxBufferSize: 1024,
	}
	registry.LoadRegistry()
	cp, err := ipfixCollector.InitCollectingProcess(input)
	if err != nil {
		log.Fatalf("UDP Collecting Process does not start correctly: %v", err)
	}
	// Start listening to connections and receiving messages.
	messageReceived := make(chan *entities.Message)
	go func() {
		go cp.Start()
		msgChan := cp.GetMsgChan()
		for message := range msgChan {
			messageReceived <- message
		}
	}()

	stopCh := make(chan struct{})
	go signalHandler(stopCh, messageReceived)

	<-stopCh
	// Stop the collector process
	cp.Stop()
	log.Printf("Stopping IPFIX collector")
}
