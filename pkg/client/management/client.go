package management

import (
	"context"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
)

type Client struct {
	Connection *zitadel.Connection
	management.ManagementServiceClient
}

func NewClient(ctx context.Context, issuer, api string, scopes []string, options ...zitadel.Option) (*Client, error) {
	conn, err := zitadel.NewConnection(ctx, issuer, api, scopes, options...)
	if err != nil {
		return nil, err
	}
	return &Client{
		Connection:              conn,
		ManagementServiceClient: management.NewManagementServiceClient(conn.ClientConn),
	}, nil
}
