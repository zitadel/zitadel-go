package zitadel

import (
	"context"

	"github.com/zitadel/zitadel-go/v3/pkg/authentication"
	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
)

// Zitadel provides the ability to interact with your ZITADEL instance.
// This includes authentication, authorization as well as explicit API interaction
// and is dependent of the provided information and initialization of such.
type Zitadel[N authentication.Ctx, Z authorization.Ctx] struct {
	Domain         string
	Authentication *authentication.Authenticator[N]
	Authorization  *authorization.Authorizer[Z]
}

func New[N authentication.Ctx, Z authorization.Ctx](domain string, options ...Option[N, Z]) (*Zitadel[N, Z], error) {
	zitadel := &Zitadel[N, Z]{
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
type Option[N authentication.Ctx, Z authorization.Ctx] func(*Zitadel[N, Z]) error

// WithAuthentication initializes the authentication capability of the provider.
// It will define the type of the [authentication.Ctx] you can access in your application.
// It requires you to provide a [authorization.VerifierInitializer] such as [oauth.DefaultAuthorization].
func WithAuthentication[N authentication.Ctx](ctx context.Context, encryptionKey string, initHandler authentication.HandlerInitializer[N], options ...authentication.Option[N]) Option[N, authorization.Ctx] {
	return func(z *Zitadel[N, authorization.Ctx]) (err error) {
		z.Authentication, err = authentication.New(ctx, z.Domain, encryptionKey, initHandler, options...)
		return err
	}
}

// WithAuthorization initializes the authorization check capability of the provider.
// It will define the type of the [authorization.Ctx] you can access in your API.
// It requires you to provide a [authorization.VerifierInitializer] such as [oauth.DefaultAuthorization].
func WithAuthorization[Z authorization.Ctx](ctx context.Context, initVerifier authorization.VerifierInitializer[Z], options ...authorization.Option[Z]) Option[authentication.Ctx, Z] {
	return func(z *Zitadel[authentication.Ctx, Z]) (err error) {
		z.Authorization, err = authorization.New(ctx, z.Domain, initVerifier, options...)
		return err
	}
}
