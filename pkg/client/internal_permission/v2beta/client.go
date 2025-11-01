package v2beta

import (
	"context"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
	internal_permission "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/internal_permission/v2beta"
)

type Client struct {
	Connection *zitadel.Connection
	internal_permission.InternalPermissionServiceClient
}

func NewClient(ctx context.Context, issuer, api string, scopes []string, options ...zitadel.Option) (*Client, error) {
	conn, err := zitadel.NewConnection(ctx, issuer, api, scopes, options...)
	if err != nil {
		return nil, err
	}

	return &Client{
		Connection:                      conn,
		InternalPermissionServiceClient: internal_permission.NewInternalPermissionServiceClient(conn.ClientConn),
	}, nil
}
