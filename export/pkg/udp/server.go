package udp

import (
	"net"

	"github.com/netobserv/netobserv-agent/export/pkg/pbflow"
	"google.golang.org/protobuf/proto"
)

const internalBufferLength = 1024

type Server struct {
	port    int
	conn    *net.UDPConn
	closeCh chan struct{}
}

func NewServer(port int) Server {
	return Server{
		port: port,
	}
}

// todo benchmark whether it's faster to use an instance channel (less allocations?)
func (s *Server) Listen(chLen int) (<-chan *pbflow.Record, error) {
	var err error
	// TODO: support IPv6 addresses?
	s.conn, err = net.ListenUDP("udp", &net.UDPAddr{IP: []byte{0, 0, 0, 0}, Port: s.port, Zone: ""})
	if err != nil {
		return nil, err
	}
	s.closeCh = make(chan struct{})
	out := make(chan *pbflow.Record, chLen)
	go func() {
		payload := make([]byte, internalBufferLength)
		for {
			select {
			case <-s.closeCh:
				return
			default:
				read, _, err := s.conn.ReadFromUDP(payload)
				if err != nil {
					// TODO: inject logger and log
					continue
				}
				var msg pbflow.Record
				if err := proto.Unmarshal(payload[:read], &msg); err != nil {
					// todo: inject logger and log
					continue
				}
				out <- &msg
			}
		}
	}()
	return out, nil
}

func (s *Server) Stop() error {
	close(s.closeCh)
	return s.conn.Close()
}
