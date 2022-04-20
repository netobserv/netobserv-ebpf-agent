package agent

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

type Config struct {
	// TargetHost is the host name or IP of the target Flow collector
	TargetHost string `env:"FLOWS_TARGET_HOST,notEmpty"`
	// TargetHost is the port the target Flow collector
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
	// being flushing the cache for its later export
	CacheMaxFlows int `env:"CACHE_MAX_FLOWS" envDefault:"1000"`
	// CacheActiveTimeout specifies the maximum duration in which a flow is kept in the accounting
	// cache before being flushed for its later export
	CacheActiveTimeout time.Duration `env:"CACHE_ACTIVE_TIMEOUT" envDefault:"5s"`
	// Logger level. From more to less verbose: trace, debug, info, warn, error, fatal, panic.
	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`
	// Sampling holds the rate at which packets should be sampled and sent to the target collector.
	// E.g. if set to 100, one out of 100 packets, on average, will be sent to each target collector.
	Sampling uint32 `env:"SAMPLING" envDefault:"0"`
}

func getInterfaces(cfg *Config, interfaces func() ([]net.Interface, error)) (map[string]struct{}, error) {
	// get interfaces from configuration or acquire them from the system
	actual, err := interfaces()
	if err != nil {
		return nil, fmt.Errorf("can't get network interfaces: %w", err)
	}
	accepted := map[string]struct{}{}

	// Accept only defined interfaces, or all if the interfaces section is not defined
	if len(cfg.Interfaces) > 0 {
		for _, definition := range cfg.Interfaces {
			for _, iface := range actual {
				if m, err := isMatch(iface.Name, definition); err != nil {
					return nil, fmt.Errorf("wrong definition of interface: %w", err)
				} else if m {
					accepted[iface.Name] = struct{}{}
				}
			}
		}
	} else {
		for _, iface := range actual {
			accepted[iface.Name] = struct{}{}
		}
	}

	// exclude interfaces
	for _, definition := range cfg.ExcludeInterfaces {
		for iface := range accepted {
			if m, err := isMatch(iface, definition); err != nil {
				return nil, fmt.Errorf("wrong definition of excluded interfaces: %w", err)
			} else if m {
				delete(accepted, iface)
			}
		}
	}
	return accepted, nil
}

func isMatch(iface, definition string) (bool, error) {
	var isRegexp = regexp.MustCompile("^/(.*)/$")
	definition = strings.Trim(definition, " ")

	// the user defined a /regexp/ between slashes: check if matches
	if sm := isRegexp.FindStringSubmatch(definition); len(sm) > 0 {
		m, err := regexp.MatchString(sm[1], iface)
		if err != nil {
			return false, fmt.Errorf("wrong pattern %s: %w", definition, err)
		}
		return m, nil
	}
	// the user defined a plain string: check exact match
	return iface == definition, nil
}
