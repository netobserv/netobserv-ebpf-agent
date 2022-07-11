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
* `CACHE_MAX_FLOWS` (default: `1000`). Number of flows that can be accumulated in the accounting
  cache. If the accounter reaches the max number of flows, it flushes them to the collector.
* `CACHE_ACTIVE_TIMEOUT` (default: `5s`). Duration string that specifies the maximum duration
  that flows are kept in the accounting cache before being flushed to the collector.
* `LOG_LEVEL` (default: `info`). From more to less verbose: `trace`, `debug`, `info`, `warn`,
  `error`, `fatal`, `panic`.
* `BUFFERS_LENGTH` (default: `50`). Length of the internal communication channels between the different
  processing stages. Most probably you won't need to change this value.
* `LISTEN_INTERFACES` (default: `watch`). Mechanism used by the agent to listen for added or removed
  network interfaces. Accepted values are:
  - `watch`: interfaces are traced immediately after they are created. This is
    the recommended setting for most configurations.
  - `poll`: recommended mostly as a fallback mechanism if `watch` misbehaves. It periodically 
    queries the current network interfaces. The poll frequency is specified by the
    `LISTEN_POLL_PERIOD` variable.
* `LISTEN_POLL_PERIOD` (default: `10s`). When `LISTEN_INTERFACES` value is `poll`, this duration
  string specifies the frequency in which the current network interfaces are polled.
* `KAFKA_BROKERS` (required if `EXPORT` is `kafka`). Comma-separated list of tha addresses of the
  brokers of the Kafka cluster that this agent is configured to send messages to.
* `KAFKA_TOPIC`(default: `network-flows`). Name of the topic where the flows' processor will receive
  the flows from.
* `KAFKA_BATCH_SIZE` (default: `100`). Limit on how many messages will be buffered before being sent
  to a Kafka partition.
* `KAFKA_BATCH_BYTES` (default: `1048576`). Limit of the maximum size of a request in bytes before
  being sent to a Kafka partition.
* `KAFKA_ASYNC` (default: `true`). If `true`, the message writing process will never block. It also
  means that errors are ignored since the caller will not receive the returned value.
* `KAFKA_COMPRESSION` (default: `none`). Compression codec to be used to compress messages. Accepted
  values: `none`, `gzip`, `snappy`, `lz4`, `zstd`.
* `PROFILE_PORT` (default: unset). Sets the listening port for [Go's Pprof tool](https://pkg.go.dev/net/http/pprof).
  If it is not set, profile is disabled.
