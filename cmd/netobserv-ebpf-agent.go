//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/caarlos0/env/v6"
	"github.com/sirupsen/logrus"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/agent"
)

func main() {
	logrus.Infof("starting NetObserv eBPF Agent")
	config := agent.Config{}
	if err := env.Parse(&config); err != nil {
		logrus.WithError(err).Fatal("can't load configuration from environment")
	}
	if config.Verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	logrus.WithField("configuration", fmt.Sprintf("%#v", config)).Debugf("configuration loaded")

	flowsAgent, err := agent.FlowsAgent(&config)
	if err != nil {
		logrus.WithError(err).Fatal("can't instantiate NetObserv eBPF Agent")
	}

	logrus.Infof("push CTRL+C or send SIGTERM to interrupt execution")
	ctx, canceler := context.WithCancel(context.Background())
	// Subscribe to signals for terminating the program.
	go func() {
		stopper := make(chan os.Signal, 1)
		signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
		<-stopper
		canceler()
	}()
	if err := flowsAgent.Run(ctx); err != nil {
		logrus.WithError(err).Fatal("can't start netobserv-ebpf-agent")
	}
}
