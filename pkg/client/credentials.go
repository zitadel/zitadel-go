package client

import (
	"context"
	"crypto/x509"

	"golang.org/x/oauth2"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type key int

const (
	ctxOverwrite = 1
)

type cred struct {
	tokenSource oauth2.TokenSource
	tls         bool
}

// GetRequestMetadata implements [credentials.PerRPCCredentials]
// It will check if an explicit token was set into context and use that as authorization.
// If no token is set, it will check if there is a default authorization in form of a token source to use.
func (c *cred) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	// if there was an explicit token set, use this
	token, ok := ctx.Value(ctxOverwrite).(*oauth2.Token)
	if ok {
		return requestMetadataFromToken(token), nil
	}
	// check if there was a default token source provided
	if c.tokenSource != nil {
		return c.tokenFromTokenSource()
	}
	return nil, nil
}

// RequireTransportSecurity implements [credentials.PerRPCCredentials]
func (c *cred) RequireTransportSecurity() bool {
	return c.tls
}

func (c *cred) tokenFromTokenSource() (map[string]string, error) {
	token, err := c.tokenSource.Token()
	if err != nil {
		return nil, err
	}
	return requestMetadataFromToken(token), nil
}

func requestMetadataFromToken(token *oauth2.Token) map[string]string {
	return map[string]string{
		"authorization": token.Type() + " " + token.AccessToken,
	}
}

func transportCredentials(domain string, tls bool) (credentials.TransportCredentials, error) {
	if !tls {
		return insecure.NewCredentials(), nil
	}
	ca, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if ca == nil {
		ca = x509.NewCertPool()
	}
	return credentials.NewClientTLSFromCert(ca, domain), nil
}
