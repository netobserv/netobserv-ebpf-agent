package grpc

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const timeout = 5 * time.Second

func TestGRPCCommunication(t *testing.T) {
	port, err := test.FreeTCPPort()
	require.NoError(t, err)
	serverOut := make(chan *pbflow.Records)
	_, err = StartCollector(port, serverOut)
	require.NoError(t, err)
	cc, err := ConnectClient(fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)
	client := cc.Client()

	go func() {
		_, err = client.Send(context.Background(),
			&pbflow.Records{Entries: []*pbflow.Record{{
				EthProtocol: 123, Flags: 1, Bytes: 456, Network: &pbflow.Network{
					SrcAddr: &pbflow.IP{
						IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x11223344},
					},
					DstAddr: &pbflow.IP{
						IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x55667788},
					},
				}, AgentIp: &pbflow.IP{
					IpFamily: &pbflow.IP_Ipv4{Ipv4: 0xaabbccdd},
				}}},
			})
		require.NoError(t, err)
		_, err = client.Send(context.Background(),
			&pbflow.Records{Entries: []*pbflow.Record{{
				EthProtocol: 789, Flags: 1, Bytes: 101, Network: &pbflow.Network{
					SrcAddr: &pbflow.IP{
						IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x44332211},
					},
					DstAddr: &pbflow.IP{
						IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x88776655},
					},
				}, AgentIp: &pbflow.IP{
					IpFamily: &pbflow.IP_Ipv4{Ipv4: 0xddccbbaa},
				}}},
			})
		require.NoError(t, err)
	}()

	var rs *pbflow.Records
	select {
	case rs = <-serverOut:
	case <-time.After(timeout):
		require.Fail(t, "timeout waiting for flows")
	}
	assert.Len(t, rs.Entries, 1)
	r := rs.Entries[0]
	assert.EqualValues(t, 123, r.EthProtocol)
	assert.EqualValues(t, 1, r.Flags)
	assert.EqualValues(t, 456, r.Bytes)
	assert.EqualValues(t, 0x11223344, r.GetNetwork().GetSrcAddr().GetIpv4())
	assert.EqualValues(t, 0x55667788, r.GetNetwork().GetDstAddr().GetIpv4())
	assert.EqualValues(t, 0xaabbccdd, r.GetAgentIp().GetIpv4())
	select {
	case rs = <-serverOut:
	case <-time.After(timeout):
		require.Fail(t, "timeout waiting for flows")
	}
	assert.Len(t, rs.Entries, 1)
	r = rs.Entries[0]
	assert.EqualValues(t, 789, r.EthProtocol)
	assert.EqualValues(t, 1, r.Flags)
	assert.EqualValues(t, 101, r.Bytes)
	assert.EqualValues(t, 0x44332211, r.GetNetwork().GetSrcAddr().GetIpv4())
	assert.EqualValues(t, 0x88776655, r.GetNetwork().GetDstAddr().GetIpv4())
	assert.EqualValues(t, 0xddccbbaa, r.GetAgentIp().GetIpv4())

	select {
	case rs = <-serverOut:
		assert.Failf(t, "shouldn't have received any flow", "Got: %#v", rs)
	default:
		//ok!
	}
}

func TestConstructorOptions(t *testing.T) {
	port, err := test.FreeTCPPort()
	require.NoError(t, err)
	intercepted := make(chan struct{})
	// Override the default GRPC collector to verify that StartCollector is applying the
	// passed options
	_, err = StartCollector(port, make(chan *pbflow.Records),
		WithGRPCServerOptions(grpc.UnaryInterceptor(func(
			ctx context.Context,
			req interface{},
			info *grpc.UnaryServerInfo,
			handler grpc.UnaryHandler,
		) (resp interface{}, err error) {
			close(intercepted)
			return handler(ctx, req)
		})))
	require.NoError(t, err)
	cc, err := ConnectClient(fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)
	client := cc.Client()

	go func() {
		_, err = client.Send(context.Background(),
			&pbflow.Records{Entries: []*pbflow.Record{{EthProtocol: 123, Bytes: 456, Flags: 1}}})
		require.NoError(t, err)
	}()

	select {
	case <-intercepted:
	case <-time.After(timeout):
		require.Fail(t, "timeout waiting for unary interceptor to work")
	}
}

func BenchmarkGRPCCommunication(b *testing.B) {
	port, err := test.FreeTCPPort()
	require.NoError(b, err)
	serverOut := make(chan *pbflow.Records, 1000)
	collector, err := StartCollector(port, serverOut)
	require.NoError(b, err)
	defer collector.Close()
	cc, err := ConnectClient(fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(b, err)
	defer cc.Close()
	client := cc.Client()

	f := &pbflow.Record{
		EthProtocol:   2048,
		Bytes:         456,
		Flags:         1,
		Direction:     pbflow.Direction_EGRESS,
		TimeFlowStart: timestamppb.Now(),
		TimeFlowEnd:   timestamppb.Now(),
		Network: &pbflow.Network{
			SrcAddr: &pbflow.IP{
				IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x11223344},
			},
			DstAddr: &pbflow.IP{
				IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x55667788},
			},
		},
		DataLink: &pbflow.DataLink{
			DstMac: 0x112233445566,
			SrcMac: 0x665544332211,
		},
		Transport: &pbflow.Transport{
			Protocol: 1,
			SrcPort:  23000,
			DstPort:  443,
		},
	}
	records := &pbflow.Records{}
	for i := 0; i < 100; i++ {
		records.Entries = append(records.Entries, f)
	}
	for i := 0; i < b.N; i++ {
		if _, err := client.Send(context.Background(), records); err != nil {
			require.Fail(b, "error", err)
		}
		<-serverOut
	}
}
