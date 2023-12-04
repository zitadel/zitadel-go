package zitadel

import (
	"context"

	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
)

// Zitadel provides the ability to interact with your ZITADEL instance.
// This includes authentication, authorization as well as explicit API interaction
// and is dependent of the provided information and initialization of such.
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

// Option allows customization of the [Zitadel] provider.
type Option[Z authorization.Ctx] func(*Zitadel[Z]) error

// WithAuthorization initializes the authorization check capability of the provider.
// It will define the type of the [authorization.Ctx] you can access in your API.
// It requires you to provide a [authorization.VerifierInitializer] such as [oauth.DefaultAuthorization].
func WithAuthorization[Z authorization.Ctx](ctx context.Context, initVerifier authorization.VerifierInitializer[Z], options ...authorization.Option[Z]) Option[Z] {
	return func(z *Zitadel[Z]) (err error) {
		z.Authorization, err = authorization.New(ctx, z.Domain, initVerifier, options...)
		return err
	}
}
