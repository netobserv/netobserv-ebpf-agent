package test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
)

// Tokens understood by StubK8sAuthServer. Tests should use a distinct token per case:
// the delegating authenticator caches TokenReview results for 1 minute and the authorizer
// caches SubjectAccessReview results for 5 minutes, so reusing a token across cases makes
// them bleed into each other.
const (
	// AllowedToken authenticates and is granted access.
	AllowedToken = "allowed-token"
	// DeniedToken authenticates but is refused by the SubjectAccessReview.
	DeniedToken = "denied-token"
	// UnknownToken is not recognised by the stub API server.
	UnknownToken = "unknown-token"
	// BrokenToken makes the TokenReview itself fail, simulating a server-side problem.
	BrokenToken = "broken-token"
)

// K8sAuthUserFor returns the username that StubK8sAuthServer authenticates a token as.
func K8sAuthUserFor(token string) string {
	return "user-" + token
}

// StubK8sAuthServer starts an HTTP server that implements the two subresources used by
// Kubernetes-delegated authentication: TokenReview and SubjectAccessReview. It lets the
// metrics authentication middleware be tested without a real cluster. The server is
// closed when the test finishes.
func StubK8sAuthServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/apis/authentication.k8s.io/v1/tokenreviews", func(w http.ResponseWriter, r *http.Request) {
		var review authnv1.TokenReview
		require.NoError(t, json.NewDecoder(r.Body).Decode(&review))

		switch token := review.Spec.Token; token {
		case UnknownToken:
			// How a real API server answers for a token it does not recognise:
			// not authenticated, and no error because nothing went wrong server-side.
			review.Status = authnv1.TokenReviewStatus{Authenticated: false}
		case BrokenToken:
			review.Status = authnv1.TokenReviewStatus{Authenticated: false, Error: "review backend unavailable"}
		default:
			review.Status = authnv1.TokenReviewStatus{
				Authenticated: true,
				User:          authnv1.UserInfo{Username: K8sAuthUserFor(token), UID: token},
			}
		}
		writeK8sJSON(t, w, &review)
	})

	mux.HandleFunc("/apis/authorization.k8s.io/v1/subjectaccessreviews", func(w http.ResponseWriter, r *http.Request) {
		var review authzv1.SubjectAccessReview
		require.NoError(t, json.NewDecoder(r.Body).Decode(&review))

		review.Status = authzv1.SubjectAccessReviewStatus{
			Allowed: review.Spec.User == K8sAuthUserFor(AllowedToken),
			Reason:  fmt.Sprintf("decided for %s", review.Spec.User),
		}
		writeK8sJSON(t, w, &review)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected call to stub API server: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// WriteKubeConfig writes a kubeconfig pointing at apiURL into a temporary directory and
// returns its path, for code that resolves its client from a kubeconfig file.
func WriteKubeConfig(t *testing.T, apiURL string) string {
	t.Helper()
	content := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: stub
  cluster:
    server: %s
contexts:
- name: stub
  context:
    cluster: stub
    user: stub
current-context: stub
users:
- name: stub
  user: {}
`, apiURL)

	path := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func writeK8sJSON(t *testing.T, w http.ResponseWriter, obj interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(obj))
}
