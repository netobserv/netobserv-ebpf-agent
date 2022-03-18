package udp

import (
	"net"

	"github.com/netobserv/netobserv-agent/export/pkg/pbflow"
	"google.golang.org/protobuf/proto"
)

type Client struct {
	address string
	conn    *net.UDPConn
}

// TODO: set UDP configuration parameters
func NewClient(address string) Client {
	return Client{
		address: address,
	}
}

func (c *Client) Start() error {
	addr, err := net.ResolveUDPAddr("udp", c.address)
	if err != nil {
		return err
	}
	c.conn, err = net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) Send(record *pbflow.Record) error {
	bytes, err := proto.Marshal(record)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(bytes)
	return err
}

func (c *Client) Close() error {
	return c.conn.Close()
}
