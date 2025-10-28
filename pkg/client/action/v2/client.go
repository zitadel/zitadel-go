package v2

import (
	"context"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/action/v2"
)

type Client struct {
	Connection *zitadel.Connection
	action.ActionServiceClient
}

func NewClient(ctx context.Context, issuer, api string, scopes []string, options ...zitadel.Option) (*Client, error) {
	conn, err := zitadel.NewConnection(ctx, issuer, api, scopes, options...)
	if err != nil {
		return nil, err
	}
	return &Client{
		Connection:          conn,
		ActionServiceClient: action.NewActionServiceClient(conn.ClientConn),
	}, nil
}
