// Package httpclient builds the HTTP client used for the OIDC discovery and token
// requests of the SDK clients, so that the TLS and transport header options apply
// to them as well as to the gRPC calls.
package httpclient

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/client/profile"
	"golang.org/x/oauth2"
)

// New returns an HTTP client that skips certificate verification and/or adds the
// given headers to every request. It returns nil if neither is requested, so that
// callers keep using the default client.
func New(insecureSkipVerify bool, headers map[string]string) *http.Client {
	if !insecureSkipVerify && len(headers) == 0 {
		return nil
	}

	var base *http.Transport
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		base = t.Clone()
	} else {
		base = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}

	if insecureSkipVerify {
		if base.TLSClientConfig == nil {
			base.TLSClientConfig = &tls.Config{}
		}
		//nolint:gosec // InsecureSkipVerify is intentionally configurable for local development with self-signed certs.
		base.TLSClientConfig.InsecureSkipVerify = true
	}

	var rt http.RoundTripper = base
	if len(headers) > 0 {
		rt = &headerRoundTripper{rt: base, headers: headers}
	}
	return &http.Client{Transport: rt}
}

// WithContext returns a context carrying the client under the key the oauth2
// package uses for its own HTTP client.
func WithContext(ctx context.Context, c *http.Client) context.Context {
	if c == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, c)
}

// FromContext returns the HTTP client stored in the context, or nil.
func FromContext(ctx context.Context) *http.Client {
	c, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	return c
}

// OrDefault returns the HTTP client stored in the context, or [http.DefaultClient].
func OrDefault(ctx context.Context) *http.Client {
	if c := FromContext(ctx); c != nil {
		return c
	}
	return http.DefaultClient
}

// JWTProfileTokenSource creates a JWT profile token source whose discovery and token
// requests use the HTTP client stored in the context, if there is one.
func JWTProfileTokenSource(ctx context.Context, issuer, clientID, keyID string, key []byte, scopes []string) (profile.TokenSource, error) {
	if c := FromContext(ctx); c != nil {
		return profile.NewJWTProfileTokenSource(ctx, issuer, clientID, keyID, key, scopes, profile.WithHTTPClient(c))
	}
	return profile.NewJWTProfileTokenSource(ctx, issuer, clientID, keyID, key, scopes)
}

type headerRoundTripper struct {
	rt      http.RoundTripper
	headers map[string]string
}

func (h *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	newReq := *req
	newReq.Header = make(http.Header, len(req.Header))
	for k, s := range req.Header {
		newReq.Header[k] = s
	}
	for k, v := range h.headers {
		newReq.Header.Set(k, v)
	}
	return h.rt.RoundTrip(&newReq)
}
