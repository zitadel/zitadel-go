package zitadel

import "fmt"

// Zitadel provides the ability to interact with your ZITADEL instance.
// This includes authentication, authorization as well as explicit API interaction
// and is dependent of the provided information and initialization of such.
type Zitadel struct {
	domain string
	port   string
	tls    bool
}

func New(domain string, options ...Option) *Zitadel {
	zitadel := &Zitadel{
		domain: domain,
		port:   "443",
		tls:    true,
	}
	for _, option := range options {
		option(zitadel)
	}
	return zitadel
}

// Option allows customization of the [Zitadel] provider.
type Option func(*Zitadel)

// WithInsecure allows to connect to a ZITADEL instance running without TLS
func WithInsecure(port string) Option {
	return func(z *Zitadel) {
		z.port = port
		z.tls = false
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

func (z *Zitadel) Domain() string {
	return z.domain
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
