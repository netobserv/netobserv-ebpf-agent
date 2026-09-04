package flows

import "time"

// Features holds flow-only configuration options.
type Features struct {
	// GRPCMessageMaxFlows specifies the limit, in number of flows, of each GRPC message. Messages
	// larger than that number will be split and submitted sequentially.
	GRPCMessageMaxFlows int `env:"GRPC_MESSAGE_MAX_FLOWS" envDefault:"10000"`
	// GRPCReconnectTimer specifies a period after which the GRPC connection is re-established. This is
	// useful for load rebalancing across receivers. Disabled by default, which means
	// connections are not actively re-established.
	GRPCReconnectTimer time.Duration `env:"GRPC_RECONNECT_TIMER"`
	// GRPCReconnectTimerRandomization specifies how much GRPCReconnectTimer should be randomized,
	// to avoid several agents reconnecting all at the same time. The value must be lower than GRPCReconnectTimer.
	// For instance, if GRPCReconnectTimer is 5m and GRPCReconnectTimerRandomization is 30s,
	// the randomization yields a value between 4m30s and 5m30s.
	GRPCReconnectTimerRandomization time.Duration `env:"GRPC_RECONNECT_TIMER_RANDOMIZATION"`
	// KafkaBrokers is a comma-separated list of tha addresses of the brokers of the Kafka cluster
	// that this agent is configured to send messages to.
	KafkaBrokers []string `env:"KAFKA_BROKERS" envSeparator:","`
	// KafkaTopic is the name of the topic where the flows' processor will receive the flows from.
	KafkaTopic string `env:"KAFKA_TOPIC" envDefault:"network-flows"`
	// KafkaBatchMessages sets the limit on how many messages will be buffered before being sent to a
	// partition.
	KafkaBatchMessages int `env:"KAFKA_BATCH_MESSAGES" envDefault:"1000"`
	// KafkaBatchSize sets the limit, in bytes, of the maximum size of a request before being sent
	// to a partition.
	KafkaBatchSize int `env:"KAFKA_BATCH_SIZE" envDefault:"1048576"`
	// KafkaAsync. If it's true, the message writing process will never block. It also means that
	// errors are ignored since the caller will not receive the returned value.
	KafkaAsync bool `env:"KAFKA_ASYNC" envDefault:"true"`
	// KafkaCompression sets the compression codec to be used to compress messages. The accepted
	// values are: none (default), gzip, snappy, lz4, zstd.
	KafkaCompression string `env:"KAFKA_COMPRESSION" envDefault:"none"`
	// KafkaEnableTLS set true to enable TLS
	KafkaEnableTLS bool `env:"KAFKA_ENABLE_TLS" envDefault:"false"`
	// KafkaTLSInsecureSkipVerify skips server certificate verification in TLS connections
	KafkaTLSInsecureSkipVerify bool `env:"KAFKA_TLS_INSECURE_SKIP_VERIFY" envDefault:"false"`
	// KafkaTLSCACertPath is the path to the Kafka server certificate for TLS connections
	KafkaTLSCACertPath string `env:"KAFKA_TLS_CA_CERT_PATH"`
	// KafkaTLSUserCertPath is the path to the user (client) certificate for mTLS connections
	KafkaTLSUserCertPath string `env:"KAFKA_TLS_USER_CERT_PATH"`
	// KafkaTLSUserKeyPath is the path to the user (client) private key for mTLS connections
	KafkaTLSUserKeyPath string `env:"KAFKA_TLS_USER_KEY_PATH"`
	// KafkaEnableSASL set true to enable SASL auth
	KafkaEnableSASL bool `env:"KAFKA_ENABLE_SASL" envDefault:"false"`
	// KafkaSASLType type of SASL mechanism: plain or scramSHA512
	KafkaSASLType string `env:"KAFKA_SASL_TYPE" envDefault:"plain"`
	// KafkaSASLClientIDPath is the path to the client ID (username) for SASL auth
	KafkaSASLClientIDPath string `env:"KAFKA_SASL_CLIENT_ID_PATH"`
	// KafkaSASLClientSecretPath is the path to the client secret (password) for SASL auth
	KafkaSASLClientSecretPath string `env:"KAFKA_SASL_CLIENT_SECRET_PATH"`
	// Enable RTT calculations for the flows, default is false (disabled), set to true to enable.
	// This feature requires the flows agent to attach at both Ingress and Egress hookpoints.
	// If both Ingress and Egress are not enabled then this feature will not be enabled even if set to true via env.
	EnableRTT bool `env:"ENABLE_RTT" envDefault:"false"`
	// ForceGC enables forcing golang garbage collection run at the end of every map eviction, default is true
	ForceGC bool `env:"FORCE_GARBAGE_COLLECTION" envDefault:"true"`
	// EnablePktDrops enable Packet drops eBPF hook to account for dropped flows
	EnablePktDrops bool `env:"ENABLE_PKT_DROPS" envDefault:"false"`
	// EnableDNSTracking enable DNS tracking eBPF hook to track dns query/response flows
	EnableDNSTracking bool `env:"ENABLE_DNS_TRACKING" envDefault:"false"`
	// DNSTrackingPort used to define which port the DNS service is mapped to at the pod level,
	// so we can track DNS at the pod level
	DNSTrackingPort uint16 `env:"DNS_TRACKING_PORT" envDefault:"53"`
	// StaleEntriesEvictTimeout specifies the maximum duration that stale entries are kept
	// before being deleted, default is 5 seconds.
	StaleEntriesEvictTimeout time.Duration `env:"STALE_ENTRIES_EVICT_TIMEOUT" envDefault:"5s"`
	// EnableNetworkEventsMonitoring enables monitoring network plugin events, default is false.
	EnableNetworkEventsMonitoring bool `env:"ENABLE_NETWORK_EVENTS_MONITORING" envDefault:"false"`
	// NetworkEventsMonitoringGroupID to allow ebpf hook to process samples for specific groupID and ignore the rest
	NetworkEventsMonitoringGroupID int `env:"NETWORK_EVENTS_MONITORING_GROUP_ID" envDefault:"10"`
	// EnablePktTranslationTracking allow tracking packets after translation - for example, NAT, default is false.
	EnablePktTranslationTracking bool `env:"ENABLE_PKT_TRANSLATION" envDefault:"false"`
	// EnableUDNMapping to allow mapping pod's interface to udn label
	EnableUDNMapping bool `env:"ENABLE_UDN_MAPPING" envDefault:"false"`
	// EnableIPsecTracking enable tracking IPsec flows encryption
	EnableIPsecTracking bool `env:"ENABLE_IPSEC_TRACKING" envDefault:"false"`
	// EnableOpenSSLTracking enable tracking OpenSSL flows encryption
	EnableOpenSSLTracking bool `env:"ENABLE_OPENSSL_TRACKING" envDefault:"false"`
	// OpenSSLPath path to the openssl binary
	OpenSSLPath string `env:"OPENSSL_PATH" envDefault:"/usr/bin/openssl"`
	// EnableFlowsRingbufFallback enable the "direct_flows" ring buffer, which is a fallback method to get flows from the kernel space, used when the main map is full or busy.
	// See also: https://github.com/netobserv/netobserv-ebpf-agent/blob/main/docs/architecture.md
	EnableFlowsRingbufFallback bool `env:"ENABLE_FLOWS_RINGBUF_FALLBACK" envDefault:"false"`
	// EnableTLSTracking allow tracking TLS usage per flow (version, cipher suite, ...)
	EnableTLSTracking bool `env:"ENABLE_TLS_TRACKING" envDefault:"false"`
	// QUICTrackingMode configures QUIC parsing in eBPF:
	// -  0: disabled
	// -  1: enabled (UDP/443 only)
	// -  2: enabled (any UDP port)
	QUICTrackingMode int `env:"QUIC_TRACKING_MODE" envDefault:"0"`
}
