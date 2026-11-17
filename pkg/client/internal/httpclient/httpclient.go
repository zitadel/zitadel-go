// Package httpclient builds the HTTP client used for the OIDC discovery and token
// requests of the SDK clients, so that the TLS and transport header options apply
// to them as well as to the gRPC calls.
package httpclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/profile"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

// Configure returns a context carrying an HTTP client that skips the certificate verification
// and/or adds the headers to every request, under the key the oauth2 package uses for its own
// HTTP client. The context is returned unchanged if neither is requested.
//
// The returned client is a copy of the one the context carries, or of [http.DefaultClient] if it
// carries none, with the options applied on top, so its timeout, redirect policy, cookie jar and
// trusted certificates are kept. The headers are copied, so later changes to the map have no effect.
// An error is returned if the certificate verification is to be skipped but the transport of the
// client the context carries is not an *http.Transport, as it cannot be configured.
//
// The origin is where ZITADEL is reached. If a Host header names another host, ZITADEL serves its
// OIDC discovery document for that host, so the requests for that host, such as the token endpoint
// of the document, are sent to the origin instead, with the Host header. See [JWTProfileTokenSource].
func Configure(ctx context.Context, origin string, insecureSkipVerify bool, headers map[string]string) (context.Context, error) {
	if !insecureSkipVerify && len(headers) == 0 {
		return ctx, nil
	}

	if injected := FromContext(ctx); insecureSkipVerify && injected != nil && injected.Transport != nil {
		if _, ok := injected.Transport.(*http.Transport); !ok {
			return nil, fmt.Errorf("zitadel: cannot skip the TLS verification of the injected HTTP client, its transport is a %T and not an *http.Transport", injected.Transport)
		}
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
	if value, ok := lookup(headers, "Proxy-Authorization"); ok {
		rt = proxyConnectHeader(rt, value)
	}
	if len(headers) > 0 {
		hrt := &headerRoundTripper{rt: rt, headers: maps.Clone(headers)}
		if host, ok := lookup(headers, "Host"); ok {
			if u, err := url.Parse(origin); err == nil && u.Host != "" && !sameHost(u.Host, host) {
				hrt.redirect = &redirect{origin: u, host: host}
				ctx = context.WithValue(ctx, redirectKey{}, hrt.redirect)
			}
		}
		rt = hrt
	}
	c.Transport = rt

	return context.WithValue(ctx, oauth2.HTTPClient, c), nil
}

// redirect sends the requests for the host, which the Host header names, to the origin.
type redirect struct {
	origin *url.URL
	host   string
}

type redirectKey struct{}

// sameHost reports whether the hosts are equal, ignoring the case and a default port.
func sameHost(a, b string) bool {
	trim := func(host string) string {
		host = strings.ToLower(host)
		host = strings.TrimSuffix(host, ":443")
		return strings.TrimSuffix(host, ":80")
	}
	return trim(a) == trim(b)
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

// proxyConnectHeader returns a copy of the transport which also sends the Proxy-Authorization header to
// the proxy in the CONNECT request of a TLS connection, where the header of the request does not reach it.
// A round tripper that is not a *http.Transport cannot be configured and is returned as it is.
func proxyConnectHeader(rt http.RoundTripper, value string) http.RoundTripper {
	base, ok := rt.(*http.Transport)
	if !ok {
		return rt
	}
	t := base.Clone()
	if t.ProxyConnectHeader == nil {
		t.ProxyConnectHeader = http.Header{}
	}
	t.ProxyConnectHeader.Set("Proxy-Authorization", value)
	if previous := t.GetProxyConnectHeader; previous != nil {
		t.GetProxyConnectHeader = func(ctx context.Context, proxyURL *url.URL, target string) (http.Header, error) {
			header, err := previous(ctx, proxyURL, target)
			if err != nil {
				return nil, err
			}
			header = header.Clone()
			if header == nil {
				header = http.Header{}
			}
			header.Set("Proxy-Authorization", value)
			return header, nil
		}
	}
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
	issuer = resolveIssuer(ctx, issuer)
	if c := FromContext(ctx); c != nil {
		return profile.NewJWTProfileTokenSource(ctx, issuer, clientID, keyID, key, scopes, profile.WithHTTPClient(c))
	}
	return profile.NewJWTProfileTokenSource(ctx, issuer, clientID, keyID, key, scopes)
}

// Discover fetches the OIDC discovery document of the issuer using the HTTP client stored in the context,
// or the default client.
func Discover(ctx context.Context, issuer string) (*oidc.DiscoveryConfiguration, error) {
	return client.Discover(ctx, resolveIssuer(ctx, issuer), OrDefault(ctx))
}

// resolveIssuer returns the issuer ZITADEL announces if the context redirects the requests for another host to
// the issuer, and the issuer otherwise. ZITADEL announces the host of the request, so with a Host header it is not
// the origin ZITADEL is reached on, and both the discovery check and the audience of a JWT assertion need the
// announced one. If it cannot be read, the issuer is returned, so that the discovery reports the actual error.
func resolveIssuer(ctx context.Context, issuer string) string {
	r, _ := ctx.Value(redirectKey{}).(*redirect)
	if r == nil {
		return issuer
	}
	if u, err := url.Parse(issuer); err != nil || u.Scheme != r.origin.Scheme || u.Host != r.origin.Host {
		return issuer
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(issuer, "/")+oidc.DiscoveryEndpoint, nil)
	if err != nil {
		return issuer
	}
	resp, err := OrDefault(ctx).Do(req)
	if err != nil {
		return issuer
	}
	defer func() { _ = resp.Body.Close() }()
	var discovery struct {
		Issuer string `json:"issuer"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&discovery) != nil || discovery.Issuer == "" {
		return issuer
	}
	return discovery.Issuer
}

// Host returns the value of the Host header in the headers, matching the name case-insensitively.
// Neither the HTTP client nor gRPC takes the host from a header, so callers apply it themselves.
func Host(headers map[string]string) (string, bool) {
	return lookup(headers, "Host")
}

// lookup returns the value of the header, matching the name case-insensitively.
func lookup(headers map[string]string, name string) (string, bool) {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// headerRoundTripper adds the headers to a copy of every request before handing it to the wrapped round tripper.
// A Host header sets the host of the request, as the HTTP client ignores it in the header. Requests for that host
// are sent to the redirect's origin, if there is one.
type headerRoundTripper struct {
	rt       http.RoundTripper
	headers  map[string]string
	redirect *redirect
}

func (h *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	newReq := req.Clone(req.Context())
	if h.redirect != nil && sameHost(req.URL.Host, h.redirect.host) {
		newReq.URL.Scheme = h.redirect.origin.Scheme
		newReq.URL.Host = h.redirect.origin.Host
	}
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
