// Package testidp provides a minimal OIDC provider for tests. It serves the discovery
// document and a token endpoint, and records the headers of the requests it receives.
package testidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

const (
	// DiscoveryPath is the path of the OIDC discovery document.
	DiscoveryPath = "/.well-known/openid-configuration"
	// TokenPath is the path of the token endpoint.
	TokenPath = "/token"
)

// Server is a started test OIDC provider.
type Server struct {
	*httptest.Server

	mu      sync.Mutex
	headers map[string]http.Header
	hosts   map[string]string
}

// New starts a test OIDC provider, over TLS with a self-signed certificate if useTLS is set.
func New(t *testing.T, useTLS bool) *Server {
	t.Helper()
	s := &Server{headers: map[string]http.Header{}, hosts: map[string]string{}}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.headers[r.URL.Path] = r.Header.Clone()
		s.hosts[r.URL.Path] = r.Host
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case DiscoveryPath:
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":         s.URL,
				"token_endpoint": s.URL + TokenPath,
			})
		case TokenPath:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		default:
			http.NotFound(w, r)
		}
	})
	if useTLS {
		s.Server = httptest.NewTLSServer(handler)
	} else {
		s.Server = httptest.NewServer(handler)
	}
	t.Cleanup(s.Close)
	return s
}

// Header returns the value of the header on the last request to the path, or "" if there was none.
func (s *Server) Header(path, name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.headers[path].Get(name)
}

// Host returns the host of the last request to the path, or "" if there was none.
func (s *Server) Host(path string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hosts[path]
}

// Requested reports whether the path was requested.
func (s *Server) Requested(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.headers[path]
	return ok
}

// PrivateKey returns a PEM encoded RSA private key for signing JWT profile assertions.
func PrivateKey(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

// KeyFileJSON returns a service account key file with a freshly generated key.
func KeyFileJSON(t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]string{
		"type":   "serviceaccount",
		"keyId":  "key-id",
		"userId": "user-id",
		"key":    string(PrivateKey(t)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
