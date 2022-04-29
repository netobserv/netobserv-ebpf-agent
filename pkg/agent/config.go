package agent

import (
	"time"
)

const (
	ListenPoll  = "poll"
	ListenWatch = "watch"
)

type Config struct {
	// TargetHost is the host name or IP of the target Flow collector
	TargetHost string `env:"FLOWS_TARGET_HOST,notEmpty"`
	// TargetPort is the port the target Flow collector
	TargetPort int `env:"FLOWS_TARGET_PORT,notEmpty"`
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
	// CacheMaxFlows specifies how many flows can be accumulated in the accounting cache before
	// being flushed for its later export
	CacheMaxFlows int `env:"CACHE_MAX_FLOWS" envDefault:"1000"`
	// CacheActiveTimeout specifies the maximum duration that flows are kept in the accounting
	// cache before being flushed for its later export
	CacheActiveTimeout time.Duration `env:"CACHE_ACTIVE_TIMEOUT" envDefault:"5s"`
	// Logger level. From more to less verbose: trace, debug, info, warn, error, fatal, panic.
	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`
	// Sampling holds the rate at which packets should be sampled and sent to the target collector.
	// E.g. if set to 100, one out of 100 packets, on average, will be sent to the target collector.
	Sampling uint32 `env:"SAMPLING" envDefault:"0"`

	// accepted values: "poll", "watch"
	ListenDevices    string        `env:"LISTEN_DEVICES" envDefault:"watch"`
	ListenPollPeriod time.Duration `env:"LISTEN_POLL_PERIOD" envDefault:"10s"`
}
