# eBPF Agent configuration environment variables

The following environment variables are available to configure the NetObserv eBFP Agent:

* `FLOWS_TARGET_HOST` (required). Host name or IP of the target Flow collector.
* `FLOWS_TARGET_PORT` (required). Port of the target flow collector.
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
