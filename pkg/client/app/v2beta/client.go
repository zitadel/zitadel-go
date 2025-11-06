package v2beta

import (
	"context"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
	app "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/app/v2beta"
)

type Client struct {
	Connection *zitadel.Connection
	app.AppServiceClient
}

func NewClient(ctx context.Context, issuer, api string, scopes []string, options ...zitadel.Option) (*Client, error) {
	conn, err := zitadel.NewConnection(ctx, issuer, api, scopes, options...)
	if err != nil {
		return nil, err
	}

	return &Client{
		Connection:       conn,
		AppServiceClient: app.NewAppServiceClient(conn.ClientConn),
	}, nil
}
