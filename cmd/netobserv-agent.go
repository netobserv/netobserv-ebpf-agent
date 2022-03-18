//go:build linux

package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/netobserv/netobserv-agent/pkg/agent"
	"github.com/sirupsen/logrus"
)

// TODO: make configurable. NETOBSERV-201
const (
	maxStoredFlowEntries      = 1000
	maxFlowEvictionPeriod     = 5 * time.Second
	communicationBufferLength = 20
)

func main() {
	flag.Parse()

	logrus.SetLevel(logrus.DebugLevel)
	// temporary hack until NETOBSERV-201
	flowsTarget := os.Getenv("FLOWS_TARGET")
	if flowsTarget == "" {
		panic("expecting a collector target in the FLOWS_TARGET env var")
	}
	logrus.WithField("FLOWS_TARGET", flowsTarget).Infof("Starting eBFP flows' agent")

	flowsAgent, err := agent.FlowsAgent(&agent.Config{
		FlowsTarget:        flowsTarget,
		ExcludeIfaces:      []string{"lo"},
		BuffersLen:         communicationBufferLength,
		CacheMaxFlows:      maxStoredFlowEntries,
		CacheActiveTimeout: maxFlowEvictionPeriod,
	})
	if err != nil {
		logrus.WithError(err).Fatal("can't instantiate netobserv-agent")
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
		logrus.WithError(err).Fatal("can't start netobserv-agent")
	}
}
