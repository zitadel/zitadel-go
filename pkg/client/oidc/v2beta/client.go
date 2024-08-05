package v2beta

import (
	"context"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
	oidc "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/oidc/v2beta"
)

type Client struct {
	Connection *zitadel.Connection
	oidc.OIDCServiceClient
}

func NewClient(ctx context.Context, issuer, api string, scopes []string, options ...zitadel.Option) (*Client, error) {
	conn, err := zitadel.NewConnection(ctx, issuer, api, scopes, options...)
	if err != nil {
		return nil, err
	}

	return &Client{
		Connection:        conn,
		OIDCServiceClient: oidc.NewOIDCServiceClient(conn.ClientConn),
	}, nil
}
