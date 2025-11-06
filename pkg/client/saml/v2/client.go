package v2

import (
	"context"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
	saml "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/saml/v2"
)

type Client struct {
	Connection *zitadel.Connection
	saml.SAMLServiceClient
}

func NewClient(ctx context.Context, issuer, api string, scopes []string, options ...zitadel.Option) (*Client, error) {
	conn, err := zitadel.NewConnection(ctx, issuer, api, scopes, options...)
	if err != nil {
		return nil, err
	}

	return &Client{
		Connection:        conn,
		SAMLServiceClient: saml.NewSAMLServiceClient(conn.ClientConn),
	}, nil
}
