package v2beta

import (
	"context"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
	session "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/session/v2beta"
)

type Client struct {
	Connection *zitadel.Connection
	session.SessionServiceClient
}

func NewClient(ctx context.Context, issuer, api string, scopes []string, options ...zitadel.Option) (*Client, error) {
	conn, err := zitadel.NewConnection(ctx, issuer, api, scopes, options...)
	if err != nil {
		return nil, err
	}

	return &Client{
		Connection:           conn,
		SessionServiceClient: session.NewSessionServiceClient(conn.ClientConn),
	}, nil
}
