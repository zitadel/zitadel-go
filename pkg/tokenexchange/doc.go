// Package tokenexchange provides RFC 8693 OAuth 2.0 Token Exchange functionality for ZITADEL.
//
// Token exchange allows exchanging one token for another with different properties,
// enabling impersonation and delegation use cases. This package wraps the lower-level
// github.com/zitadel/oidc/v3/pkg/client/tokenexchange package with a simpler,
// ZITADEL-specific API.
//
// Before using token exchange, ensure the Token Exchange feature is enabled on your
// ZITADEL instance via the Feature API, and that your application has the Token Exchange
// grant type enabled. For impersonation, the actor must have appropriate permissions
// such as ORG_END_USER_IMPERSONATOR.
//
// # Client Authentication
//
// Token exchange requires client authentication. Use [ClientCredentials] for
// applications configured with a client secret, or [JWTProfile] for applications
// using JWT assertion authentication:
//
//	auth := tokenexchange.ClientCredentials("client-id", "client-secret")
//
//	result, err := tokenexchange.Impersonate(ctx, z,
//	    "259242039378444290",
//	    actorToken,
//	    tokenexchange.SubjectIsUserID(),
//	    tokenexchange.WithClientAuth(auth),
//	)
//
// # Impersonation
//
// Impersonation allows a service account to obtain a token that acts as another user.
// The service account must have impersonation permissions. You can impersonate by
// user ID (a ZITADEL-specific extension) or by providing an existing user token.
// The subject token type is specified using [SubjectIsUserID], [SubjectIsAccessToken],
// [SubjectIsIDToken], or [SubjectIsJWT]. In ZITADEL, delegation and impersonation are
// functionally equivalent, both resulting in a token with an `act` claim identifying
// the actor. The [Delegate] function is provided as an alias for code clarity.
//
// # Simple Token Exchange
//
// Token exchange can also be used without impersonation to reduce scope, restrict
// audience, or convert between token types (opaque to JWT):
//
//	result, err := tokenexchange.Exchange(ctx, z,
//	    myAccessToken,
//	    tokenexchange.SubjectIsAccessToken(),
//	    tokenexchange.WithScopes("openid"),
//	    tokenexchange.WithClientAuth(auth),
//	)
//
// Use [WithScopes], [WithAudience], [WithResource], and [WithRequestedTokenType] to
// customize the exchange request.
//
// # Creating a Client with the Exchanged Token
//
// After obtaining an impersonated token, create a new ZITADEL client using
// [client.PreSignedJWT]. Note that exchanged tokens are static and will not
// auto-refresh. When a token expires, perform the exchange again.
//
//	result, _ := tokenexchange.Impersonate(ctx, z, ...)
//
//	impersonatedClient, _ := client.New(ctx, z,
//	    client.WithAuth(client.PreSignedJWT(result.AccessToken)),
//	)
//
// # Security Considerations
//
// Token exchange is a powerful feature. Only grant impersonation permissions to
// trusted service accounts, use confidential clients for token exchange, and
// minimize token scope and audience when possible. Note that impersonated tokens
// cannot be used against the ZITADEL API by design.
//
// For more information, see https://zitadel.com/docs/guides/integrate/token-exchange
package tokenexchange
