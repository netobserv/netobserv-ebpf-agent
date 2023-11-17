package exporter

import (
	"encoding/json"
	"net"

	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/decode"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
)

type FlowStream struct {
	hostPort   string
	clientConn net.Conn
}

// WriteFlow writes the given flow data out to the file.
func writeFlow(record *config.GenericMap, conn net.Conn) error {
	b, err := json.Marshal(record)
	if err != nil {
		plog.Fatal(err)
	}
	// append new line between each record to split on client side
	b = append(b, []byte("\n")...)
	_, err = conn.Write(b)
	if err != nil {
		plog.Fatal(err)
	}
	return err
}

// FIXME: Only after client connects to it, the agent starts collecting and sending flows.
// This behavior needs to be fixed.
func StartFlowSend(hostPort string) (*FlowStream, error) {
	PORT := ":" + hostPort
	l, err := net.Listen("tcp", PORT)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	clientConn, err := l.Accept()

	if err != nil {
		return nil, err
	}

	return &FlowStream{
		hostPort:   hostPort,
		clientConn: clientConn,
	}, nil
}

func (p *FlowStream) ExportFlows(in <-chan []*flow.Record) {
	//Create handler by opening Flow stream
	for flowRecord := range in {
		if len(flowRecord) > 0 {
			for _, record := range flowRecord {
				genericMap := decode.PBFlowToMap(flowToPB(record))
				err := writeFlow(&genericMap, p.clientConn)
				if err != nil {
					plog.Fatal(err)
				}
			}
		}
	}
}
