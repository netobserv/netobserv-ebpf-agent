package agent

import (
	"errors"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	"github.com/stretchr/testify/require"
)

var (
	localIP4    = net.ParseIP("10.0.0.10")
	localIP6    = net.ParseIP("2001:0db8::1111")
	externalIP4 = net.ParseIP("84.88.89.90")
	externalIP6 = net.ParseIP("2001:0db8::eeee")
	testIFName  = "teth1"
	testIfIP4   = net.ParseIP("10.1.2.3")
	testIfIP6   = net.ParseIP("2001:0db8::6666")
	testIFName2 = "teth2"
	testIf2IP6  = net.ParseIP("2001:0db8::6262")
)

func TestAgentIP_Any(t *testing.T) {
	mockIfaces()
	type testCase struct {
		dsc    string
		cfg    config.Agent
		expect net.IP
	}

	for _, tc := range []testCase{
		{dsc: "hardcoding IPv4 address",
			cfg:    config.Agent{AgentIP: "192.168.1.13"},
			expect: net.IPv4(192, 168, 1, 13)},
		{dsc: "hardcoding IPv6 address",
			cfg:    config.Agent{AgentIP: "2002:0db9::7336"},
			expect: net.ParseIP("2002:0db9::7336")},
		{dsc: "any local address",
			cfg:    config.Agent{AgentIPIface: "local", AgentIPType: "any"},
			expect: localIP4},
		{dsc: "local IPv4 address",
			cfg:    config.Agent{AgentIPIface: "local", AgentIPType: "ipv4"},
			expect: localIP4},
		{dsc: "local IPv6 address",
			cfg:    config.Agent{AgentIPIface: "local", AgentIPType: "ipv6"},
			expect: localIP6},
		{dsc: "any external address",
			cfg:    config.Agent{AgentIPIface: "external", AgentIPType: "any"},
			expect: externalIP4},
		{dsc: "external IPv4 address",
			cfg:    config.Agent{AgentIPIface: "external", AgentIPType: "ipv4"},
			expect: externalIP4},
		{dsc: "external IPv6 address",
			cfg:    config.Agent{AgentIPIface: "external", AgentIPType: "ipv6"},
			expect: externalIP6},
		{dsc: "any IP given an interface name",
			cfg:    config.Agent{AgentIPIface: "name:" + testIFName, AgentIPType: "any"},
			expect: testIfIP4},
		{dsc: "IPv4 address given an interface name",
			cfg:    config.Agent{AgentIPIface: "name:" + testIFName, AgentIPType: "ipv4"},
			expect: testIfIP4},
		{dsc: "IPv6 address given an interface name",
			cfg:    config.Agent{AgentIPIface: "name:" + testIFName, AgentIPType: "ipv6"},
			expect: testIfIP6},
		{dsc: "any IP given an IPV6-only interface name",
			cfg:    config.Agent{AgentIPIface: "name:" + testIFName2, AgentIPType: "any"},
			expect: testIf2IP6},
		{dsc: "IPv6 address given an IPV6-only interface name",
			cfg:    config.Agent{AgentIPIface: "name:" + testIFName2, AgentIPType: "ipv6"},
			expect: testIf2IP6},
	} {
		t.Run(tc.dsc, func(t *testing.T) {
			ip, err := fetchAgentIP(&tc.cfg)
			require.NoError(t, err)
			require.Truef(t, tc.expect.Equal(ip), "expected: %s. Got: %s", tc.expect, ip)
		})
	}
}

func mockIfaces() {
	// mock local addresses retrieval
	interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("127.0.0.1")},
			&net.IPNet{IP: localIP4},
			&net.IPNet{IP: localIP6},
		}, nil
	}
	// mock external address retrieval
	dial = func(_, address string) (net.Conn, error) {
		// IPv4 address
		if regexp.MustCompile(`^\d+(\.\d+){3}(:\d+)?$`).MatchString(address) {
			return &connMock{ip: externalIP4}, nil
		}
		return &connMock{ip: externalIP6}, nil
	}
	// mock interface retrieval by name
	interfaceByName = func(name string) (*net.Interface, error) {
		if name != testIFName && name != testIFName2 {
			return nil, errors.New("unknown interface " + name)
		}
		return &net.Interface{
			Name: name,
		}, nil
	}
	// mock test interface address retrieval
	ifaceAddrs = func(iface *net.Interface) ([]net.Addr, error) {
		switch iface.Name {
		case testIFName:
			return []net.Addr{
				&net.IPNet{IP: testIfIP4},
				&net.IPNet{IP: testIfIP6},
			}, nil
		case testIFName2:
			return []net.Addr{
				&net.IPNet{IP: testIf2IP6},
			}, nil
		}
		return iface.Addrs()
	}
}

type connMock struct {
	ip net.IP
}

func (c *connMock) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: c.ip}
}

func (c *connMock) Read(_ []byte) (n int, err error)   { panic("unexpected call") }
func (c *connMock) Write(_ []byte) (n int, err error)  { panic("unexpected call") }
func (c *connMock) Close() error                       { panic("unexpected call") }
func (c *connMock) RemoteAddr() net.Addr               { panic("unexpected call") }
func (c *connMock) SetDeadline(_ time.Time) error      { panic("unexpected call") }
func (c *connMock) SetReadDeadline(_ time.Time) error  { panic("unexpected call") }
func (c *connMock) SetWriteDeadline(_ time.Time) error { panic("unexpected call") }
