package config

import (
	"time"

	"github.com/sirupsen/logrus"
)

var clog = logrus.WithField("component", "config")

const (
	ListenPoll       = "poll"
	ListenWatch      = "watch"
	DirectionIngress = "ingress"
	DirectionEgress  = "egress"
	DirectionBoth    = "both"

	IPTypeAny  = "any"
	IPTypeIPV4 = "ipv4"
	IPTypeIPV6 = "ipv6"

	IPIfaceExternal    = "external"
	IPIfaceLocal       = "local"
	IPIfaceNamedPrefix = "name:"
)

// FlowFilter describes a single flow filter rule (shared by flow and packet modes).
type FlowFilter struct {
	// Direction is the direction of the flow filter.
	// Possible values are "Ingress" or "Egress".
	Direction string `json:"direction,omitempty"`
	// IPCIDR is the IP CIDR to filter flows.
	// Example: 10.10.10.0/24 or 100:100:100:100::/64, default is 0.0.0.0/0
	IPCIDR string `json:"ip_cidr,omitempty"`
	// Protocol is the protocol to filter flows.
	// supported protocols: TCP, UDP, SCTP, ICMP, ICMPv6
	Protocol string `json:"protocol,omitempty"`
	// SourcePort is the source port to filter flows.
	SourcePort int32 `json:"source_port,omitempty"`
	// DestinationPort is the destination port to filter flows.
	DestinationPort int32 `json:"destination_port,omitempty"`
	// Port is the port to filter flows, can be use for either source or destination port.
	Port int32 `json:"port,omitempty"`
	// SourcePortRange is the source port range to filter flows.
	// Example: 8000-8010
	SourcePortRange string `json:"source_port_range,omitempty"`
	// SourcePorts is two source ports to filter flows.
	// Example: 8000,8010
	SourcePorts string `json:"source_ports,omitempty"`
	// DestinationPortRange is the destination port range to filter flows.
	// Example: 8000-8010
	DestinationPortRange string `json:"destination_port_range,omitempty"`
	// DestinationPorts is two destination ports to filter flows.
	// Example: 8000,8010
	DestinationPorts string `json:"destination_ports,omitempty"`
	// PortRange is the port range to filter flows, can be used for either source or destination port.
	// Example: 8000-8010
	PortRange string `json:"port_range,omitempty"`
	// Ports is two ports option to filter flows, can be used for either source or destination port.
	// Example: 8000,8010
	Ports string `json:"ports,omitempty"`
	// ICMPType is the ICMP type to filter flows.
	ICMPType int `json:"icmp_type,omitempty"`
	// ICMPCode is the ICMP code to filter flows.
	ICMPCode int `json:"icmp_code,omitempty"`
	// PeerIP is the IP to filter flows.
	// Example: 10.10.10.10
	PeerIP string `json:"peer_ip,omitempty"`
	// Action is the action to filter flows.
	// Possible values are "Accept" or "Reject".
	Action string `json:"action,omitempty"`
	// TCPFlags is the TCP flags to filter flows.
	// possible values are: SYN, SYN-ACK, ACK, FIN, RST, PSH, URG, ECE, CWR, FIN-ACK, RST-ACK
	TCPFlags string `json:"tcp_flags,omitempty"`
	// Drops allow filtering flows with packet drops, default is false.
	Drops bool `json:"drops,omitempty"`
	// Sample is the sample rate this matching flow will use
	Sample uint32 `json:"sample,omitempty"`
	// PeerCIDR is the PeerIP CIDR to filter flows.
	// Example: 10.10.10.0/24 or 100:100:100:100::/64, default is 0.0.0.0/0
	PeerCIDR string `json:"peer_cidr,omitempty"`
}

// Common holds configuration shared by flow and packet capture modes.
type Common struct {
	// AgentIP allows overriding the reported Agent IP address on each flow.
	AgentIP string `env:"AGENT_IP"`
	// AgentIPIface specifies which interface should the agent pick the IP address from in order to
	// report it in the AgentIP field on each flow. Accepted values are: external (default), local,
	// or name:<interface name> (e.g. name:eth0).
	// If the AgentIP configuration property is set, this property has no effect.
	AgentIPIface string `env:"AGENT_IP_IFACE" envDefault:"external"`
	// AgentIPType specifies which type of IP address (IPv4 or IPv6 or any) should the agent report
	// in the AgentID field of each flow. Accepted values are: any (default), ipv4, ipv6.
	// If the AgentIP configuration property is set, this property has no effect.
	AgentIPType string `env:"AGENT_IP_TYPE" envDefault:"any"`
	// Export selects the exporter protocol.
	// Accepted values for Flows are: grpc (default), kafka, ipfix+udp, ipfix+tcp or direct-flp.
	// Accepted values for Packets are: grpc (default) or direct-flp
	Export string `env:"EXPORT" envDefault:"grpc"`
	// Host is the host name or IP of the flow or packet collector, when the EXPORT variable is
	// set to "grpc"
	TargetHost string `env:"TARGET_HOST"`
	// Port is the port the flow or packet collector, when the EXPORT variable is set to "grpc"
	TargetPort int `env:"TARGET_PORT"`
	// CA certificate path of the target, when TLS is used. Empty by default (no TLS).
	TargetTLSCACertPath string `env:"TARGET_TLS_CA_CERT_PATH"`
	// User certificate path, when mTLS is used. Empty by default (no mTLS).
	TargetTLSUserCertPath string `env:"TARGET_TLS_USER_CERT_PATH"`
	// User certificate key path, when mTLS is used. Empty by default (no mTLS).
	TargetTLSUserKeyPath string `env:"TARGET_TLS_USER_KEY_PATH"`
	// Interfaces contains the interface names from where flows will be collected. If empty, the agent
	// will fetch all the interfaces in the system, excepting the ones listed in ExcludeInterfaces.
	// If an entry is enclosed by slashes (e.g. `/br-/`), it will match as regular expression,
	// otherwise it will be matched as a case-sensitive string.
	Interfaces []string `env:"INTERFACES" envSeparator:","`
	// ExcludeInterfaces contains the interface names that will be excluded from flow tracing. Default:
	// "lo" (loopback).
	// If an entry is enclosed by slashes (e.g. `/br-/`), it will match as regular expression,
	// otherwise it will be matched as a case-sensitive string.
	ExcludeInterfaces []string `env:"EXCLUDE_INTERFACES" envSeparator:"," envDefault:"lo"`
	// BuffersLength establishes the length of communication channels between the different processing
	// stages
	BuffersLength int `env:"BUFFERS_LENGTH" envDefault:"50"`
	// InterfaceIPs is a list of CIDR-notation IPs/Subnets where any interface containing an IP in the given ranges
	// should be listened on. This allows users to specify interfaces without knowing the OS-assigned interface names.
	// Exclusive with Interfaces/ExcludeInterfaces.
	InterfaceIPs []string `env:"INTERFACE_IPS" envSeparator:","`
	// ExporterBufferLength establishes the length of the buffer of flow batches (not individual flows)
	// that can be accumulated before the Kafka or GRPC exporter. When this buffer is full (e.g.
	// because the Kafka or GRPC endpoint is slow), incoming flow batches will be dropped. If unset,
	// its value is the same as the BUFFERS_LENGTH property.
	ExporterBufferLength int `env:"EXPORTER_BUFFER_LENGTH"`
	// CacheMaxFlows specifies how many flows can be accumulated in the accounting cache before
	// being flushed for its later export
	CacheMaxFlows int `env:"CACHE_MAX_FLOWS" envDefault:"5000"`
	// CacheActiveTimeout specifies the maximum duration that flows are kept in the accounting
	// cache before being flushed for its later export
	CacheActiveTimeout time.Duration `env:"CACHE_ACTIVE_TIMEOUT" envDefault:"5s"`
	// Direction allows selecting which flows to trace according to its direction. Accepted values
	// are "ingress", "egress" or "both" (default).
	Direction string `env:"DIRECTION" envDefault:"both"`
	// Logger level. From more to less verbose: trace, debug, info, warn, error, fatal, panic.
	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`
	// Sampling holds the interval at which packets should be sampled and sent to the target collector.
	// E.g. if set to 100, one out of 100 packets, on average, will be sent to the target collector.
	Sampling int `env:"SAMPLING" envDefault:"0"`
	// TCAttachMode defines the eBPF attach mode on traffic controller: tcx (default), tc or any.
	// 'tcx' is recommended but may not be available on older linux kernels.
	// 'any' will try 'tcx' and fall back on 'tc' without retries.
	TCAttachMode string `env:"TC_ATTACH_MODE" envDefault:"tcx"`
	// TCAttachRetries defines the number of retries in case of attach/detach failures.
	// Valid only for 'tc' and 'tcx' attach modes.
	TCAttachRetries int `env:"TC_ATTACH_RETRIES" envDefault:"4"`
	// TCXAttachAnchorIngress defines the anchor to use when attaching eBPF programs to interfaces using tcx mode for
	// ingress.
	// none (default): no specific anchor is used and the eBPF program is generally inserted at the end.
	// head: eBPF program is inserted at the head.
	// tail: eBPF program is inserted at the tail.
	TCXAttachAnchorIngress string `env:"TCX_ATTACH_ANCHOR_INGRESS" envDefault:"none"`
	// TCXAttachAnchorEgress defines the anchor to use when attaching eBPF programs to interfaces using tcx mode for
	// egress.
	// none (default): no specific anchor is used and the eBPF program is generally inserted at the end.
	// head: eBPF program is inserted at the head.
	// tail: eBPF program is inserted at the tail.
	TCXAttachAnchorEgress string `env:"TCX_ATTACH_ANCHOR_EGRESS" envDefault:"none"`
	// ListenInterfaces specifies the mechanism used by the agent to listen for added or removed
	// network interfaces. Accepted values are "watch" (default) or "poll".
	// If the value is "watch", interfaces are traced immediately after they are created. This is
	// the recommended setting for most configurations. "poll" value is a fallback mechanism that
	// periodically queries the current network interfaces (frequency specified by ListenPollPeriod).
	ListenInterfaces string `env:"LISTEN_INTERFACES" envDefault:"watch"`
	// ListenPollPeriod specifies the periodicity to query the network interfaces when the
	// ListenInterfaces value is set to "poll".
	ListenPollPeriod time.Duration `env:"LISTEN_POLL_PERIOD" envDefault:"10s"`
	// PPROF_ADDR sets the listening address (such as 127.0.0.1:6060) for Go's Pprof tool. Do not expose publicly. If it is not set, profiling is disabled.
	PprofAddr string `env:"PPROF_ADDR"`
	// Flowlogs-pipeline configuration as YAML or JSON, used when export is "direct-flp". Cf https://github.com/netobserv/flowlogs-pipeline
	// The "ingest" stage must be omitted from this configuration, since it is handled internally by the agent. The first stage should follow "preset-ingester".
	// E.g: {"pipeline":[{"name": "writer","follows": "preset-ingester"}],"parameters":[{"name": "writer","write": {"type": "stdout"}}]}.
	FLPConfig string `env:"FLP_CONFIG"`
	// MetricsEnable enables http server to collect ebpf agent metrics, default is false.
	MetricsEnable bool `env:"METRICS_ENABLE" envDefault:"false"`
	// Metrics verbosity level. From more to less verbose: trace!, debug, info (default).
	// Warning: 'trace!' level generates unbounded metrics cardinality, which increases memory
	// and CPU usage of the eBPF Agent and the Prometheus server.
	MetricsLevel string `env:"METRICS_LEVEL" envDefault:"info"`
	// MetricsServerAddress is the address of the server that collects ebpf agent metrics.
	MetricsServerAddress string `env:"METRICS_SERVER_ADDRESS"`
	// MetricsPort is the port of the server that collects ebpf agent metrics.
	MetricsPort int `env:"METRICS_SERVER_PORT" envDefault:"9090"`
	// MetricsTLSCertPath is the path to the server certificate for TLS connections
	MetricsTLSCertPath string `env:"METRICS_TLS_CERT_PATH"`
	// MetricsTLSKeyPath is the path to the server private key for TLS connections
	MetricsTLSKeyPath string `env:"METRICS_TLS_KEY_PATH"`
	// MetricsPrefix is the prefix of the metrics that are sent to the server.
	MetricsPrefix string `env:"METRICS_PREFIX" envDefault:"ebpf_agent_"`
	// FlowFilterRules list of flow filter rules
	FlowFilterRules string `env:"FLOW_FILTER_RULES"`
	// EbpfProgramManagerMode is enabled when eBPF manager is handling netobserv ebpf programs life cycle, default is false.
	EbpfProgramManagerMode bool `env:"EBPF_PROGRAM_MANAGER_MODE" envDefault:"false"`
	// BpfManBpfFSPath user configurable ebpf manager mount path
	BpfManBpfFSPath string `env:"BPFMAN_BPF_FS_PATH" envDefault:"/run/netobserv/maps"`
	// PreferredInterfaceForMACPrefix is a comma-separated list of key=value pairs.
	// It allows to specify a preference when retrieving interface names per flow in case of index collision, when using multiple network namespaces are used.
	// This setting is only used when the interface name could not be found for a given index and MAC.
	// E.g. "0a:58=eth0" (used for ovn-kubernetes)
	PreferredInterfaceForMACPrefix string `env:"PREFERRED_INTERFACE_FOR_MAC_PREFIX"`

	/* Deprecated configs are listed below this line
	 * See manageDeprecatedConfigs function for details
	 */

	// Deprecated FlowsTargetHost replaced by TargetHost
	FlowsTargetHost string `env:"FLOWS_TARGET_HOST"`
	// Deprecated FlowsTargetPort replaced by TargetPort
	FlowsTargetPort int `env:"FLOWS_TARGET_PORT"`
	// Deprecated PCAServerPort replaced by TargetPort
	PCAServerPort int `env:"PCA_SERVER_PORT"`
}
