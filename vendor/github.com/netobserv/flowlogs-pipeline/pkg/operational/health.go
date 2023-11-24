/*
 * Copyright (C) 2022 IBM, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package operational

import (
	"net"
	"net/http"
	"time"

	"github.com/heptiolabs/healthcheck"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	log "github.com/sirupsen/logrus"
)

type Server struct {
	handler healthcheck.Handler
	Address string
}

func (hs *Server) Serve() {
	for {
		err := http.ListenAndServe(hs.Address, hs.handler)
		log.Errorf("http.ListenAndServe error %v", err)
		time.Sleep(60 * time.Second)
	}
}

func NewHealthServer(opts *config.Options, isAlive healthcheck.Check, isReady healthcheck.Check) *Server {

	handler := healthcheck.NewHandler()
	address := net.JoinHostPort(opts.Health.Address, opts.Health.Port)
	handler.AddLivenessCheck("PipelineCheck", isAlive)
	handler.AddReadinessCheck("PipelineCheck", isReady)

	server := &Server{
		handler: handler,
		Address: address,
	}

	go server.Serve()

	return server
}
