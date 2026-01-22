package http

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

func NewClient(z *zitadel.Zitadel) *http.Client {
	var transport *http.Transport
	if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok && defaultTransport != nil {
		transport = defaultTransport.Clone()
	} else {
		transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		}
	}

	if z.IsInsecureSkipVerifyTLS() {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	var roundTripper http.RoundTripper = transport

	if len(z.TransportHeaders()) > 0 {
		roundTripper = &headerRoundTripper{
			base:    transport,
			headers: z.TransportHeaders(),
		}
	}

	return &http.Client{
		Transport: roundTripper,
		Timeout:   30 * time.Second,
	}
}

type headerRoundTripper struct {
	base    http.RoundTripper
	headers map[string]string
}

func (h *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clonedReq := req.Clone(req.Context())
	for name, value := range h.headers {
		clonedReq.Header.Set(name, value)
	}
	return h.base.RoundTrip(clonedReq)
}
