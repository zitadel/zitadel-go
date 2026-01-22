package http

import (
	"crypto/tls"
	"net/http"

	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

func NewClient(z *zitadel.Zitadel) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}

	if z.IsInsecureSkipVerifyTLS() {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	var rt http.RoundTripper = transport

	if len(z.TransportHeaders()) > 0 {
		rt = &headerRoundTripper{
			rt:      transport,
			headers: z.TransportHeaders(),
		}
	}

	return &http.Client{
		Transport: rt,
	}
}

type headerRoundTripper struct {
	rt      http.RoundTripper
	headers map[string]string
}

func (h *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	newReq := req.Clone(req.Context())
	for k, v := range h.headers {
		newReq.Header.Set(k, v)
	}
	return h.rt.RoundTrip(newReq)
}
