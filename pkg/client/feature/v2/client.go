package v2

import (
	"context"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
	feature "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/feature/v2"
)

type Client struct {
	Connection *zitadel.Connection
	feature.FeatureServiceClient
}

func NewClient(ctx context.Context, issuer, api string, scopes []string, options ...zitadel.Option) (*Client, error) {
	conn, err := zitadel.NewConnection(ctx, issuer, api, scopes, options...)
	if err != nil {
		return nil, err
	}

	return &Client{
		Connection:           conn,
		FeatureServiceClient: feature.NewFeatureServiceClient(conn.ClientConn),
	}, nil
}
