package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// protected stands in for the metrics handler that authentication is guarding.
func protected() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("metrics body"))
	})
}

func doGet(t *testing.T, handler http.Handler, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://localhost:9090/metrics", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestNewHandler_Disabled(t *testing.T) {
	for name, cfg := range map[string]*metrics.PromAuth{
		"nil config":    nil,
		"empty type":    {},
		"type disabled": {Type: metrics.PromAuthDisabled},
	} {
		t.Run(name, func(t *testing.T) {
			handler, err := NewHandler(cfg, protected())
			require.NoError(t, err)

			// Without authentication the handler is passed through untouched.
			rec := doGet(t, handler, "")
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, "metrics body", rec.Body.String())
		})
	}
}

func TestNewHandler_UnknownType(t *testing.T) {
	handler, err := NewHandler(&metrics.PromAuth{Type: "something-else"}, protected())
	require.Error(t, err)
	assert.Nil(t, handler)
	assert.Contains(t, err.Error(), "unknown authentication type")
}

// TestNewHandler_FromKubeConfig covers the full NewHandler path, including resolving the
// cluster from a kubeconfig file.
func TestNewHandler_FromKubeConfig(t *testing.T) {
	apiServer := test.StubK8sAuthServer(t)

	handler, err := NewHandler(&metrics.PromAuth{
		Type:           metrics.PromAuthKubernetes,
		KubeConfigPath: test.WriteKubeConfig(t, apiServer.URL),
	}, protected())
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, doGet(t, handler, test.AllowedToken).Code)
	assert.Equal(t, http.StatusUnauthorized, doGet(t, handler, "").Code)
}

func TestKubernetesAuth(t *testing.T) {
	apiServer := test.StubK8sAuthServer(t)
	handler, err := newHandlerFromConfig(&rest.Config{Host: apiServer.URL}, protected())
	require.NoError(t, err)

	t.Run("no token is unauthorized", func(t *testing.T) {
		rec := doGet(t, handler, "")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.NotContains(t, rec.Body.String(), "metrics body")
	})

	// A request carrying a bearer token that the API server rejects comes back as 500
	// rather than 401. That is upstream controller-runtime behaviour, not ours: the
	// bearertoken authenticator turns every rejected token into an error ("invalid bearer
	// token") and the filter maps any authentication error to 500, so only a request with
	// no Authorization header at all reaches the 401 path. Asserted here so that a future
	// dependency bump changing it is noticed. Either way the request is refused.
	t.Run("rejected token is refused", func(t *testing.T) {
		rec := doGet(t, handler, test.UnknownToken)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.NotContains(t, rec.Body.String(), "metrics body")
	})

	t.Run("failing token review is refused", func(t *testing.T) {
		rec := doGet(t, handler, test.BrokenToken)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.NotContains(t, rec.Body.String(), "metrics body")
	})

	t.Run("authenticated but unauthorized token is forbidden", func(t *testing.T) {
		rec := doGet(t, handler, test.DeniedToken)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.NotContains(t, rec.Body.String(), "metrics body")
	})

	t.Run("authorized token is served", func(t *testing.T) {
		rec := doGet(t, handler, test.AllowedToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "metrics body", rec.Body.String())
	})
}
