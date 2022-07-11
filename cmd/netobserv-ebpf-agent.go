//go:build linux

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/caarlos0/env/v6"
	"github.com/sirupsen/logrus"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/agent"

	_ "net/http/pprof"
)

func main() {
	logrus.Infof("starting NetObserv eBPF Agent")
	config := agent.Config{}
	if err := env.Parse(&config); err != nil {
		logrus.WithError(err).Fatal("can't load configuration from environment")
	}
	setLoggerVerbosity(&config)

	if config.ProfilePort != 0 {
		go func() {
			logrus.WithField("port", config.ProfilePort).Info("starting PProf HTTP listener")
			logrus.WithError(http.ListenAndServe(fmt.Sprintf(":%d", config.ProfilePort), nil)).
				Error("PProf HTTP listener stopped working")
		}()
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

func setLoggerVerbosity(cfg *agent.Config) {
	lvl, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logrus.WithError(err).Warn("assuming 'info' logger level as default")
		lvl = logrus.InfoLevel
	}
	logrus.SetLevel(lvl)
}
