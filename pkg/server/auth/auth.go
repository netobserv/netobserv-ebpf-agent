// Package auth provides authentication and authorization middleware for the HTTP
// endpoints exposed by the agent, such as the Prometheus metrics endpoint.
package auth

import (
	"fmt"
	"net/http"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/netobserv/flowlogs-pipeline/pkg/utils/k8sutils"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
)

var alog = logrus.WithField("component", "server.auth")

// debugVerbosity is the logr verbosity level needed to surface the filter's
// per-request "authentication/authorization failed" messages, which it logs at V(4).
const debugVerbosity = 4

// NewHandler wraps inner with Kubernetes-delegated authentication and authorization,
// as configured by cfg. When authentication is disabled, inner is returned unchanged.
//
// Authenticated callers must present a bearer token that the Kubernetes API accepts via a
// TokenReview, and must be allowed by a SubjectAccessReview for the verb matching the HTTP
// method on the requested path. This requires the agent itself to be granted `create` on
// `authentication.k8s.io/tokenreviews` and `authorization.k8s.io/subjectaccessreviews`, and
// the scraping client to be granted a non-resource URL rule such as
// `nonResourceURLs: ["/metrics"], verbs: ["get"]`.
func NewHandler(cfg *metrics.PromAuth, inner http.Handler) (http.Handler, error) {
	if cfg == nil || cfg.Type == "" || cfg.Type == metrics.PromAuthDisabled {
		return inner, nil
	}
	if cfg.Type != metrics.PromAuthKubernetes {
		return nil, fmt.Errorf("unknown authentication type %q, expected one of %q or %q",
			cfg.Type, metrics.PromAuthDisabled, metrics.PromAuthKubernetes)
	}
	restCfg, err := k8sutils.LoadK8sConfig(cfg.KubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("cannot load kubernetes config: %w", err)
	}
	return newHandlerFromConfig(restCfg, inner)
}

// newHandlerFromConfig is separated from NewHandler so that tests can point it at a stub
// API server instead of resolving a real cluster configuration.
func newHandlerFromConfig(restCfg *rest.Config, inner http.Handler) (http.Handler, error) {
	httpClient, err := rest.HTTPClientFor(restCfg)
	if err != nil {
		return nil, fmt.Errorf("cannot build kubernetes http client: %w", err)
	}
	filter, err := filters.WithAuthenticationAndAuthorization(restCfg, httpClient)
	if err != nil {
		return nil, fmt.Errorf("cannot build authentication filter: %w", err)
	}
	handler, err := filter(logger(), inner)
	if err != nil {
		return nil, fmt.Errorf("cannot build authentication handler: %w", err)
	}
	alog.Info("Kubernetes authentication enabled: clients must provide a bearer token")
	return handler, nil
}

// logger bridges the logr.Logger expected by controller-runtime onto logrus.
func logger() logr.Logger {
	verbosity := 0
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		verbosity = debugVerbosity
	}
	return funcr.New(func(prefix, args string) {
		if prefix != "" {
			alog.Infof("%s: %s", prefix, args)
		} else {
			alog.Info(args)
		}
	}, funcr.Options{Verbosity: verbosity})
}
