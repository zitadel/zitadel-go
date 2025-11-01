package v2beta

import (
	"context"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
	analytics "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/analytics/v2beta"
)

type Client struct {
	Connection *zitadel.Connection
	analytics.TelemetryServiceClient
}

func NewClient(ctx context.Context, issuer, api string, scopes []string, options ...zitadel.Option) (*Client, error) {
	conn, err := zitadel.NewConnection(ctx, issuer, api, scopes, options...)
	if err != nil {
		return nil, err
	}

	return &Client{
		Connection:             conn,
		TelemetryServiceClient: analytics.NewTelemetryServiceClient(conn.ClientConn),
	}, nil
}
