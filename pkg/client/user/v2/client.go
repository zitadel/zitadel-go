package v2

import (
	"context"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
	user "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
)

type Client struct {
	Connection *zitadel.Connection
	user.UserServiceClient
}

func NewClient(ctx context.Context, issuer, api string, scopes []string, options ...zitadel.Option) (*Client, error) {
	conn, err := zitadel.NewConnection(ctx, issuer, api, scopes, options...)
	if err != nil {
		return nil, err
	}

	return &Client{
		Connection:        conn,
		UserServiceClient: user.NewUserServiceClient(conn.ClientConn),
	}, nil
}
