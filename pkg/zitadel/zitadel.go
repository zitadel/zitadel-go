package zitadel

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
)

// Zitadel provides the ability to interact with your ZITADEL instance.
// This includes authentication, authorization as well as explicit API interaction
// and is dependent of the provided information and initialization of such.
type Zitadel struct {
	domain                string
	port                  string
	tls                   bool
	insecureSkipVerifyTLS bool
	caCertPool            *x509.CertPool
	transportHeaders      map[string]string
	initErr               error // stores any error from option initialization
}

func New(domain string, options ...Option) *Zitadel {
	zitadel := &Zitadel{
		domain:                domain,
		port:                  "443",
		tls:                   true,
		insecureSkipVerifyTLS: false,
		transportHeaders:      make(map[string]string),
	}
	for _, option := range options {
		option(zitadel)
	}
	return zitadel
}

// Option allows customization of the [Zitadel] provider.
type Option func(*Zitadel)

// WithInsecure allows to connect to a ZITADEL instance running without TLS
// Do not use in production
func WithInsecure(port string) Option {
	return func(z *Zitadel) {
		z.port = port
		z.tls = false
	}
}

// WithInsecureSkipVerifyTLS allows to connect to a ZITADEL instance running with TLS but has an untrusted certificate
// Do not use in production
func WithInsecureSkipVerifyTLS() Option {
	return func(z *Zitadel) {
		z.insecureSkipVerifyTLS = true
	}
}

// WithTrustStore adds custom CA certificates to the trust store for both gRPC and HTTP transports.
// The certificates should be PEM-encoded. This is useful when connecting to servers using
// certificates signed by a private CA (e.g., in development or enterprise environments).
// The provided certificates are appended to the system certificate pool.
// Any error will be returned when calling client.New().
func WithTrustStore(caCerts ...[]byte) Option {
	return func(z *Zitadel) {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		for _, cert := range caCerts {
			if !pool.AppendCertsFromPEM(cert) {
				z.initErr = errors.New("failed to append CA certificate to trust store")
				return
			}
		}
		z.caCertPool = pool
	}
}

// WithPort allows to connect to a ZITADEL instance running on a different port
func WithPort(port uint16) Option {
	return func(z *Zitadel) {
		z.port = strconv.Itoa(int(port))
	}
}

// WithTransportHeader allows to set custom headers (e.g. Proxy-Authorization) that will be sent
// with both HTTP (authentication) and gRPC (API) requests.
func WithTransportHeader(key, value string) Option {
	return func(z *Zitadel) {
		z.transportHeaders[key] = value
	}
}

// Origin returns the HTTP Origin (schema://hostname[:port]), e.g.
// https://your-instance.zitadel.cloud
// https://your-domain.com
// http://localhost:8080
func (z *Zitadel) Origin() string {
	return buildOrigin(z.domain, z.port, z.tls)
}

// Host returns the domain:port (even if the default port is used)
func (z *Zitadel) Host() string {
	return z.domain + ":" + z.port
}

func (z *Zitadel) IsTLS() bool {
	return z.tls
}

func (z *Zitadel) IsInsecureSkipVerifyTLS() bool {
	return z.insecureSkipVerifyTLS
}

func (z *Zitadel) Domain() string {
	return z.domain
}

func (z *Zitadel) TransportHeaders() map[string]string {
	return z.transportHeaders
}

func (z *Zitadel) CACertPool() *x509.CertPool {
	return z.caCertPool
}

func (z *Zitadel) InitErr() error {
	return z.initErr
}

func buildOrigin(hostname string, externalPort string, tls bool) string {
	if externalPort == "" || (externalPort == "443" && tls) || (externalPort == "80" && !tls) {
		return buildOriginFromHost(hostname, tls)
	}
	return buildOriginFromHost(fmt.Sprintf("%s:%s", hostname, externalPort), tls)
}

func buildOriginFromHost(host string, tls bool) string {
	schema := "https"
	if !tls {
		schema = "http"
	}
	return fmt.Sprintf("%s://%s", schema, host)
}
