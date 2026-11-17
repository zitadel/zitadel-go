// Package httpclient builds the HTTP client used for the OIDC discovery and token
// requests of the SDK clients, so that the TLS and transport header options apply
// to them as well as to the gRPC calls.
package httpclient

import (
	"context"
	"crypto/tls"
	"maps"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/profile"
	"golang.org/x/oauth2"
)

// Configure returns a context carrying an HTTP client that skips the certificate verification
// and/or adds the headers to every request, under the key the oauth2 package uses for its own
// HTTP client. The context is returned unchanged if neither is requested.
//
// The returned client is a copy of the one the context carries, or of [http.DefaultClient] if it
// carries none, with the options applied on top, so its timeout, redirect policy, cookie jar and
// trusted certificates are kept. The headers
// are copied, so later changes to the map have no effect.
func Configure(ctx context.Context, insecureSkipVerify bool, headers map[string]string) context.Context {
	if !insecureSkipVerify && len(headers) == 0 {
		return ctx
	}

	clone := *OrDefault(ctx)
	c := &clone

	rt := c.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	if insecureSkipVerify {
		rt = skipVerify(rt)
	}
	if len(headers) > 0 {
		rt = &headerRoundTripper{rt: rt, headers: maps.Clone(headers)}
	}
	c.Transport = rt

	return context.WithValue(ctx, oauth2.HTTPClient, c)
}

// skipVerify returns a copy of the transport that does not verify the server certificate. A round
// tripper that is not a *http.Transport cannot be configured, so it is replaced by a transport
// with the settings of the default one.
func skipVerify(rt http.RoundTripper) *http.Transport {
	var t *http.Transport
	if base, ok := rt.(*http.Transport); ok {
		t = base.Clone()
	} else if base, ok := http.DefaultTransport.(*http.Transport); ok {
		t = base.Clone()
	} else {
		t = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		}
	}
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{}
	}
	//nolint:gosec // InsecureSkipVerify is intentionally configurable for local development with self-signed certs.
	t.TLSClientConfig.InsecureSkipVerify = true
	return t
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

// Host returns the value of the Host header in the headers, matching the name case-insensitively.
// Neither the HTTP client nor gRPC takes the host from a header, so callers apply it themselves.
func Host(headers map[string]string) (string, bool) {
	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			return v, true
		}
	}
	return "", false
}

// headerRoundTripper adds the headers to a copy of every request before handing it to the wrapped round tripper.
// A Host header sets the host of the request, as the HTTP client ignores it in the header.
type headerRoundTripper struct {
	rt      http.RoundTripper
	headers map[string]string
}

func (h *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	newReq := req.Clone(req.Context())
	for k, v := range h.headers {
		if strings.EqualFold(k, "Host") {
			newReq.Host = v
			continue
		}
		newReq.Header.Set(k, v)
	}
	return h.rt.RoundTrip(newReq)
}

// CloseIdleConnections closes the idle connections of the wrapped round tripper, if it supports that.
func (h *headerRoundTripper) CloseIdleConnections() {
	if c, ok := h.rt.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
