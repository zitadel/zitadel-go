package v2

import (
	"context"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
	internal "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/internal_permission/v2"
)

type Client struct {
	Connection *zitadel.Connection
	internal.InternalPermissionServiceClient
}

func NewClient(ctx context.Context, issuer, api string, scopes []string, options ...zitadel.Option) (*Client, error) {
	conn, err := zitadel.NewConnection(ctx, issuer, api, scopes, options...)
	if err != nil {
		return nil, err
	}

	return &Client{
		Connection:                      conn,
		InternalPermissionServiceClient: internal.NewInternalPermissionServiceClient(conn.ClientConn),
	}, nil
}
