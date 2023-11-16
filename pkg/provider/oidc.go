package provider

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/client/rs"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zitadel/zitadel-go/v2/pkg/info"
)

var (
	ErrMissingCookie        = errors.New("auth cookie missing")
	ErrMissingHeader        = errors.New("auth header missing")
	ErrInvalidHeader        = errors.New("invalid auth header")
	ErrInvalidToken         = errors.New("invalid token")
	ErrInvalidAuthorization = errors.New("invalid authorization")
)

const (
	oidcCookieName = "zitadel-go"
)

func newResourceServer(ctx context.Context, oidc *configurationOIDC) (rs.ResourceServer, error) {
	if oidc.keyPath != "" {
		return rs.NewResourceServerFromKeyFile(ctx, oidc.issuer, oidc.keyPath)
	}
	return rs.NewResourceServerClientCredentials(ctx, oidc.issuer, oidc.clientID, oidc.clientSecret)
}

func newRelayingPartyOIDC(ctx context.Context, oidc *configurationOIDC) (rp.RelyingParty, error) {
	opts := make([]httphelper.CookieHandlerOpt, 0)
	if oidc.insecure {
		opts = append(opts, httphelper.WithUnsecure())
	}
	cookieHandler := httphelper.NewCookieHandler(oidc.cookieKey, oidc.cookieKey, opts...)
	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
	}
	if oidc.clientSecret == "" {
		options = append(options, rp.WithPKCE(cookieHandler))
	}
	if oidc.keyPath != "" {
		options = append(options, rp.WithJWTProfile(rp.SignerFromKeyPath(oidc.keyPath)))
	}
	return rp.NewRelyingPartyOIDC(ctx,
		oidc.issuer,
		oidc.clientID,
		oidc.clientSecret,
		oidc.callbackURL,
		oidc.scopes,
		options...,
	)
}

func oidcAuthenticatedHTTPInterceptor[U rp.SubjectGetter](cache Cache[string, U], relayingParty rp.RelyingParty) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx, _, err := checkOIDCTokenFromRequest[U](cache, relayingParty, req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}

func oidcAuthorizedHTTPInterceptor[R any](getToken func(r *http.Request) (string, error), cache Cache[string, R], resourceServer rs.ResourceServer, check Check[R]) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := req.Context()
			token, err := getToken(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			ctx, _, err = checkIntrospect[R](ctx, cache, resourceServer, token, check)
			if err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}

func oidcAuthenticatedUnaryInterceptor[U rp.SubjectGetter](cache Cache[string, U], relayingParty rp.RelyingParty) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, sInfo *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		ctx, _, err = checkOIDCToken[U](ctx, cache, relayingParty, metautils.ExtractIncoming(ctx).Get("authorization"))
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		return handler(ctx, req)
	}
}

type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *serverStream) Context() context.Context {
	return s.ctx
}

func oidcAuthenticatedStreamInterceptor[U rp.SubjectGetter](cache Cache[string, U], relayingParty rp.RelyingParty) grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, sInfo *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := stream.Context()

		ctx, _, err := checkOIDCToken[U](ctx, cache, relayingParty, metautils.ExtractIncoming(ctx).Get("authorization"))
		if err != nil {
			return status.Error(codes.Unauthenticated, err.Error())
		}

		return handler(srv, &serverStream{stream, ctx})
	}
}

func checkOIDCTokenFromRequest[U rp.SubjectGetter](cache Cache[string, U], relayingParty rp.RelyingParty, r *http.Request) (context.Context, string, error) {
	token, err := getTokenFromRequest(r)
	if err != nil {
		return r.Context(), "", err
	}
	return checkOIDCToken[U](r.Context(), cache, relayingParty, token)
}

func getTokenFromRequest(r *http.Request) (string, error) {
	auth := r.Header.Get("authorization")
	if auth == "" {
		return "", ErrMissingHeader
	}
	if !strings.HasPrefix(auth, oidc.PrefixBearer) {
		return "", ErrInvalidHeader
	}
	return strings.TrimPrefix(auth, oidc.PrefixBearer), nil
}

func setTokenToHeader(w http.ResponseWriter, value string) {
	w.Header().Add("authorization", value)
}

func getTokenFromCookie(r *http.Request) (string, error) {
	auth, err := r.Cookie(oidcCookieName)
	if err != nil {
		return "", ErrMissingCookie
	}
	return auth.Value, nil
}

func setTokenToCookieFunc(path, domain string, maxAge int) func(w http.ResponseWriter, value string) {
	return func(w http.ResponseWriter, value string) {
		http.SetCookie(w, &http.Cookie{
			Name:     oidcCookieName,
			Value:    value,
			Path:     path,
			Domain:   domain,
			Expires:  time.Now().Add(time.Hour),
			MaxAge:   maxAge,
			Secure:   false,
			HttpOnly: false,
			SameSite: 0,
		})
	}
}

func checkOIDCToken[U rp.SubjectGetter](ctx context.Context, cache Cache[string, U], relayingParty rp.RelyingParty, token string) (context.Context, string, error) {
	resp, err := cache.Get(token)
	if err != nil {
		resp, err := rp.Userinfo[U](ctx, token, oidc.PrefixBearer, "userid", relayingParty)
		if err != nil {
			return ctx, "", ErrInvalidToken
		}
		if err := cache.Set(token, resp); err != nil {
			return ctx, "", ErrInvalidToken
		}
	}
	return info.UserinfoIntoContext[U](ctx, resp), token, err
}

func checkIntrospect[R any](ctx context.Context, cache Cache[string, R], resourceServer rs.ResourceServer, token string, check func(resp R) error) (context.Context, R, error) {
	var rnil R
	// try get from cache
	resp, err := cache.Get(token)
	// if not found in cache, try to call introspection endpoint
	if err != nil {
		resp, err := rs.Introspect[R](ctx, resourceServer, token)
		if err != nil {
			return ctx, rnil, ErrInvalidToken
		}
		// set introspection response in cache
		if err := cache.Set(token, resp); err != nil {
			return ctx, rnil, ErrInvalidToken
		}
	}
	// check introspection response if authorization are correct
	if err := check(resp); err != nil {
		return ctx, rnil, err
	}
	// save checked introspection response into context
	return info.IntrospectionIntoContext[R](ctx, resp), resp, nil
}

func redirectCallback(setToken func(w http.ResponseWriter, value string), redirectURL string) rp.CodeExchangeCallback[*oidc.IDTokenClaims] {
	return func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty) {
		log.Printf("access token: %v", tokens.AccessToken)
		log.Printf("refresh token: %v", tokens.RefreshToken)
		log.Printf("id token: %v", tokens.IDToken)
		log.Printf("state: %v", state)
		setToken(w, tokens.AccessToken)
		http.Redirect(w, r, redirectURL, 302)
	}
}