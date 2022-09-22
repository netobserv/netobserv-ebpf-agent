# eBPF Agent configuration environment variables

The following environment variables are available to configure the NetObserv eBFP Agent:

* `EXPORT` (default: `grpc`). Flows' exporter protocol. Accepted values are: `grpc` or `kafka`.
* `FLOWS_TARGET_HOST` (required if `EXPORT` is `grpc`). Host name or IP of the target Flow collector.
* `FLOWS_TARGET_PORT` (required if `EXPORT` is `grpc`). Port of the target flow collector.
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
* `LOG_LEVEL` (default: `info`). From more to less verbose: `trace`, `debug`, `info`, `warn`,
  `error`, `fatal`, `panic`.
* `MESSAGE_MAX_FLOW_ENTRIES` (default: unset). Number of flows to be grouped in a single
  message as sent to the Flow Collector. If `0` (or unset), each message will contain the
  number of flows determined by `CACHE_MAX_FLOWS`, at most. If this value is set to a number
  lower than `CACHE_MAX_FLOWS`, each message with more than `MESSAGE_MAX_FLOW_ENTRIES` will be
  split in multiple messages having at most the number of flows specified by this variable.
* `KAFKA_BROKERS` (required if `EXPORT` is `kafka`). Comma-separated list of tha addresses of the
  brokers of the Kafka cluster that this agent is configured to send messages to.
* `KAFKA_TOPIC`(default: `network-flows`). Name of the topic where the flows' processor will receive
  the flows from.
* `KAFKA_BATCH_SIZE` (default: `1048576`). Limit of the maximum size of a request in bytes before
  being sent to a Kafka partition.
* `KAFKA_ASYNC` (default: `true`). If `true`, the message writing process will never block. It also
  means that errors are ignored since the caller will not receive the returned value.
* `KAFKA_COMPRESSION` (default: `none`). Compression codec to be used to compress messages. Accepted
  values: `none`, `gzip`, `snappy`, `lz4`, `zstd`.
* `KAFKA_ENABLE_TLS` (default: false). If `true`, enable TLS encryption for Kafka messages. The following settings are used only when TLS is enabled:
  * `KAFKA_TLS_INSECURE_SKIP_VERIFY` (default: false). Skips server certificate verification in TLS connections.
  * `KAFKA_TLS_CA_CERT_PATH` (default: unset). Path to the Kafka server certificate for TLS connections.
  * `KAFKA_TLS_USER_CERT_PATH` (default: unset). Path to the user (client) certificate for mutual TLS connections.
  * `KAFKA_TLS_USER_KEY_PATH` (default: unset). Path to the user (client) private key for mutual TLS connections.
* `PROFILE_PORT` (default: unset). Sets the listening port for [Go's Pprof tool](https://pkg.go.dev/net/http/pprof).
  If it is not set, profile is disabled.

## Development-only variables

The following configuration variables are mostly used for development and fine-grained debugging,
so any user should need to change them.

* `BUFFERS_LENGTH` (default: `50`). Length of the internal communication channels between the different
  processing stages.
* `KAFKA_BATCH_MESSAGES` (default: `100`). Exposes an internal value from the used Kafka library.
  It sets the limit on how many messages will be buffered before being sent to a partition. A
  "message" is not a flow but a group of many flows. If you are thinking on setting this value,
  you actually need to set the `CACHE_MAX_FLOWS` and/or `MESSAGE_MAX_FLOW_ENTRIES`
* `LISTEN_INTERFACES` (default: `watch`). Mechanism used by the agent to listen for added or removed
  network interfaces. Accepted values are:
  - `watch`: interfaces are traced immediately after they are created. This is
    the recommended setting for most configurations.
  - `poll`: recommended mostly as a fallback mechanism if `watch` misbehaves. It periodically
    queries the current network interfaces. The poll frequency is specified by the
    `LISTEN_POLL_PERIOD` variable.
* `LISTEN_POLL_PERIOD` (default: `10s`). When `LISTEN_INTERFACES` value is `poll`, this duration
  string specifies the frequency in which the current network interfaces are polled.

