package v2beta

import (
	"context"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
	authorization "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2beta"
)

type Client struct {
	Connection *zitadel.Connection
	authorization.AuthorizationServiceClient
}

func NewClient(ctx context.Context, issuer, api string, scopes []string, options ...zitadel.Option) (*Client, error) {
	conn, err := zitadel.NewConnection(ctx, issuer, api, scopes, options...)
	if err != nil {
		return nil, err
	}

	return &Client{
		Connection:                 conn,
		AuthorizationServiceClient: authorization.NewAuthorizationServiceClient(conn.ClientConn),
	}, nil
}
