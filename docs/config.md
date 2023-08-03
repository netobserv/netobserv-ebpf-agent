# eBPF Agent configuration environment variables

The following environment variables are available to configure the NetObserv eBFP Agent:

* `EXPORT` (default: `grpc`). Flows' exporter protocol. Accepted values are: `grpc` or `kafka` or `ipfix+tcp` or `ipfix+udp`.
* `FLOWS_TARGET_HOST` (required if `EXPORT` is `grpc` or `ipfix+[tcp/udp]`). Host name or IP of the target Flow collector.
* `FLOWS_TARGET_PORT` (required if `EXPORT` is `grpc` or `ipfix+[tcp/udp]`). Port of the target flow collector.
* `GRPC_MESSAGE_MAX_FLOWS` (default: `10000`). Specifies the limit, in number of flows, of each GRPC
  message. Messages larger than that number will be split and submitted sequentially.
* `AGENT_IP` (optional). Allows overriding the reported Agent IP address on each flow.
* `AGENT_IP_IFACE` (default: `external`). Specifies which interface should the agent pick the IP
  address from in order to report it in the AgentIP field on each flow. Accepted values are:
  `external` (default), `local`, or `name:<interface name>` (e.g. `name:eth0`). If the `AGENT_IP`
  configuration property is set, this property has no effect.
* `AGENT_IP_TYPE` (default: `any`). Specifies which type of IP address (IPv4 or IPv6 or any) should
  the agent report in the AgentID field of each flow. Accepted values are: `any` (default), `ipv4`,
  `ipv6`. If the `AGENT_IP` configuration property is set, this property has no effect.
* `INTERFACES` (optional). Comma-separated list of the interface names from where flows will be collected. If 
  empty, the agent will use all the interfaces in the system, excepting the ones listed in
  the `EXCLUDE_INTERFACES` variable.
  If an entry is enclosed by slashes (e.g. `/br-/`), it will match as regular expression,
  otherwise it will be matched as a case-sensitive string.
* `EXCLUDE_INTERFACES` (default: `lo`). Comma-separated list of the interface names that will be
  excluded from flow tracing. It takes priority over `INTERFACES` values.
  If an entry is enclosed by slashes (e.g. `/br-/`), it will match as regular expression,
  otherwise it will be matched as a case-sensitive string.
* `SAMPLING` (default: disabled). Rate at which packets should be sampled and sent to the target
  collector. E.g. if set to 10, one out of 10 packets, on average, will be sent to the target
  collector.
* `CACHE_MAX_FLOWS` (default: `5000`). Number of flows that can be accumulated in the accounting
  cache. If the accounter reaches the max number of flows, it flushes them to the collector.
* `CACHE_ACTIVE_TIMEOUT` (default: `5s`). Duration string that specifies the maximum duration
  that flows are kept in the accounting cache before being flushed to the collector.
* `DEDUPER` (default: `none`, disabled). Accepted values are `none` (disabled) and `firstCome`.
  When enabled, it will detect duplicate flows (flows that have been detected e.g. through
  both the physical and a virtual interface).
  `firstCome` will forward only flows from the first interface the flows are received from.
* `DEDUPER_FC_EXPIRY` (default: `2 * CACHE_ACTIVE_TIMEOUT`). Specifies the expiry duration of the `firstCome`
  deduplicator. After a flow hasn't been received for that expiry time, the deduplicator forgets it.
  That means that a flow from a connection that has been inactive during that period could be
  forwarded again from a different interface.
* `DEDUPER_JUST_MARK` (default: `false`) will mark duplicates (adding an extra boolean field)
  instead of dropping them.
* `DIRECTION` (default: `both`). Allows selecting which flows to trace according to its direction.
  Accepted values are `ingress`, `egress` or `both`.
* `LOG_LEVEL` (default: `info`). From more to less verbose: `trace`, `debug`, `info`, `warn`,
  `error`, `fatal`, `panic`.
* `KAFKA_BROKERS` (required if `EXPORT` is `kafka`). Comma-separated list of tha addresses of the
  brokers of the Kafka cluster that this agent is configured to send messages to.
* `KAFKA_TOPIC`(default: `network-flows`). Name of the topic where the flows' processor will receive
  the flows from.
* `KAFKA_BATCH_MESSAGES` (default: `1000`). Limit on how many messages will be buffered before being sent
  to a Kafka partition.
  you actually need to set the `CACHE_MAX_FLOWS` and/or `MESSAGE_MAX_FLOW_ENTRIES`
* `KAFKA_BATCH_SIZE` (default: `1048576`). Limit of the maximum size of a request in bytes before
  being sent to a Kafka partition.
* `KAFKA_COMPRESSION` (default: `none`). Compression codec to be used to compress messages. Accepted
  values: `none`, `gzip`, `snappy`, `lz4`, `zstd`.
* `KAFKA_ENABLE_TLS` (default: false). If `true`, enable TLS encryption for Kafka messages. The following settings are used only when TLS is enabled:
  * `KAFKA_TLS_INSECURE_SKIP_VERIFY` (default: false). Skips server certificate verification in TLS connections.
  * `KAFKA_TLS_CA_CERT_PATH` (default: unset). Path to the Kafka server certificate for TLS connections.
  * `KAFKA_TLS_USER_CERT_PATH` (default: unset). Path to the user (client) certificate for mutual TLS connections.
  * `KAFKA_TLS_USER_KEY_PATH` (default: unset). Path to the user (client) private key for mutual TLS connections.
* `PROFILE_PORT` (default: unset). Sets the listening port for [Go's Pprof tool](https://pkg.go.dev/net/http/pprof).
  If it is not set, profile is disabled.
* `ENABLE_RTT` (default: `false` disabled). If `true` enables RTT calculations for the captured flows in the ebpf agent.
  See [docs](./rtt_calculations.md) for more details on this feature.
* `ENABLE_PCA` (default: `false` disabled). If `true` enables Packet Capture Agent. 
* `PCA_FILTER` (default: `none`). Works only when `ENABLE_PCA` is set. Accepted format <protocol,portnumber>. Example 
  `PCA_FILTER=tcp,22`.
* `PCA_SERVER_PORT` (default: 0). Works only when `ENABLE_PCA` is set. Agent opens PCA Server at this port. A collector can connect to it and recieve filtered packets as pcap stream. The filter is set using `PCA_FILTER`.

## Development-only variables

The following configuration variables are mostly used for development and fine-grained debugging,
so no user should need to change them.

* `BUFFERS_LENGTH` (default: `50`). Length of the internal communication channels between the different
  processing stages.
* `EXPORTER_BUFFER_LENGTH` (default: value of `BUFFERS_LENGTH`) establishes the length of the buffer
  of flow batches (not individual flows) that can be accumulated before the Kafka or GRPC exporter.
  When this buffer is full (e.g. because the Kafka or GRPC endpoint is slow), incoming flow batches
  will be dropped. If unset, its value is the same as the BUFFERS_LENGTH property.
* `KAFKA_ASYNC` (default: `true`). If `true`, the message writing process will never block. It also
  means that errors are ignored since the caller will not receive the returned value.
* `LISTEN_INTERFACES` (default: `watch`). Mechanism used by the agent to listen for added or removed
  network interfaces. Accepted values are:
  - `watch`: interfaces are traced immediately after they are created. This is
    the recommended setting for most configurations.
  - `poll`: recommended mostly as a fallback mechanism if `watch` misbehaves. It periodically
    queries the current network interfaces. The poll frequency is specified by the
    `LISTEN_POLL_PERIOD` variable.
* `LISTEN_POLL_PERIOD` (default: `10s`). When `LISTEN_INTERFACES` value is `poll`, this duration
  string specifies the frequency in which the current network interfaces are polled.

