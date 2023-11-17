package zitadel

import (
	"context"

	"github.com/zitadel/zitadel-go/v2/pkg/authorization"
)

type Zitadel[Z authorization.Ctx] struct {
	Domain        string
	Authorization *authorization.Authorizer[Z]
}

func New[Z authorization.Ctx](domain string, options ...Option[Z]) (*Zitadel[Z], error) {
	zitadel := &Zitadel[Z]{
		Domain: domain,
	}
	for _, option := range options {
		if err := option(zitadel); err != nil {
			return nil, err
		}
	}
	return zitadel, nil
}

type Option[Z authorization.Ctx] func(*Zitadel[Z]) error

func WithAuthorization[Z authorization.Ctx](ctx context.Context, newVerifier authorization.NewVerifier[Z], options ...authorization.Option[Z]) Option[Z] {
	return func(z *Zitadel[Z]) (err error) {
		z.Authorization, err = authorization.New(ctx, z.Domain, newVerifier, options...)
		return err
	}
}
