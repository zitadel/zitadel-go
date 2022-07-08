package auth

import (
	"github.com/zitadel/zitadel-go/v2/pkg/client/zitadel"
	"github.com/zitadel/zitadel-go/v2/pkg/client/zitadel/auth"
)

type Client struct {
	Connection *zitadel.Connection
	auth.AuthServiceClient
}

func NewClient(issuer, api string, scopes []string, options ...zitadel.Option) (*Client, error) {
	conn, err := zitadel.NewConnection(issuer, api, scopes, options...)
	if err != nil {
		return nil, err
	}
	return &Client{
		Connection:        conn,
		AuthServiceClient: auth.NewAuthServiceClient(conn.ClientConn),
	}, nil
}
