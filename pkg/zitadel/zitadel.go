package zitadel

import (
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
	transportHeaders      map[string]string
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
