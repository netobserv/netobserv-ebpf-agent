package pktgrpc

import (
	"context"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbpacket"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
)

const timeout = 5 * time.Second

func TestGRPCCommunication(t *testing.T) {
	port, err := test.FreeTCPPort()
	require.NoError(t, err)
	serverOut := make(chan *pbpacket.Packet)
	_, err = StartCollector(port, serverOut)
	require.NoError(t, err)
	cc, err := ConnectClient("127.0.0.1", port)
	require.NoError(t, err)
	client := cc.Client()

	value := []byte("test")
	go func() {
		_, err = client.Send(context.Background(),
			&pbpacket.Packet{
				Pcap: &anypb.Any{
					Value: value,
				},
			})
		require.NoError(t, err)
	}()

	var rs *pbpacket.Packet
	select {
	case rs = <-serverOut:
	case <-time.After(timeout):
		require.Fail(t, "timeout waiting for packet")
	}
	assert.NotNil(t, rs.Pcap)
	assert.EqualValues(t, value, rs.Pcap.Value)
	select {
	case rs = <-serverOut:
		assert.Failf(t, "shouldn't have received any packet", "Got: %#v", rs)
	default:
		// ok!
	}
}

func TestConstructorOptions(t *testing.T) {
	port, err := test.FreeTCPPort()
	require.NoError(t, err)
	intercepted := make(chan struct{})
	// Override the default GRPC collector to verify that StartCollector is applying the
	// passed options
	_, err = StartCollector(port, make(chan *pbpacket.Packet),
		WithGRPCServerOptions(grpc.UnaryInterceptor(func(
			ctx context.Context,
			req interface{},
			_ *grpc.UnaryServerInfo,
			handler grpc.UnaryHandler,
		) (resp interface{}, err error) {
			close(intercepted)
			return handler(ctx, req)
		})))
	require.NoError(t, err)
	cc, err := ConnectClient("127.0.0.1", port)
	require.NoError(t, err)
	client := cc.Client()

	go func() {
		_, err = client.Send(context.Background(),
			&pbpacket.Packet{Pcap: &anypb.Any{}})
		require.NoError(t, err)
	}()

	select {
	case <-intercepted:
	case <-time.After(timeout):
		require.Fail(t, "timeout waiting for unary interceptor to work")
	}
}
