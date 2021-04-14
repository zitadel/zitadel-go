package auth

import (
	"github.com/caos/zitadel-go/pkg/client/zitadel"
	"github.com/caos/zitadel-go/pkg/client/zitadel/auth"
)

type Client struct {
	Connection *zitadel.Connection
	auth.AuthServiceClient
}

func NewClient(scopes []string, options ...zitadel.Option) (*Client, error) {
	conn, err := zitadel.NewConnection(scopes, options...)
	if err != nil {
		return nil, err
	}
	return &Client{
		Connection:        conn,
		AuthServiceClient: auth.NewAuthServiceClient(conn.ClientConn),
	}, nil
}
