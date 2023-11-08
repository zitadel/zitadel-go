package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	ErrMissingHeader        = errors.New("auth header missing")
	ErrInvalidHeader        = errors.New("invalid auth header")
	ErrInvalidToken         = errors.New("invalid token")
	ErrInvalidAuthorization = errors.New("invalid authorization")
)

func newRelayingPartyOIDC(ctx context.Context, oidc *configurationOIDC) (rp.RelyingParty, error) {
	redirectURI := fmt.Sprintf("http://localhost:%v%v", oidc.port, oidc.callbackURL)
	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())
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
	return rp.NewRelyingPartyOIDC(ctx, oidc.issuer, oidc.clientID, oidc.clientSecret, redirectURI, oidc.scopes, options...)
}

func marshalUserinfo() rp.CodeExchangeUserinfoCallback[*oidc.IDTokenClaims, *oidc.UserInfo] {
	return func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {
		data, err := json.Marshal(info)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}
}

func oidcAuthenticatedHTTPInterceptor(resourceServer rs.ResourceServer) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := req.Context()

			token, err := checkOIDCTokenFromRequest(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			pi := info.ProviderInfoFromContext(ctx)
			resp, err := checkIntrospectWithCached(ctx, resourceServer, token, pi.IntrospectionResponse)
			if err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			ctx = pi.SetIntrospectionResponse(resp).IntoContext(ctx)

			next.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}
func oidcAuthorizedHTTPInterceptor(resourceServer rs.ResourceServer, requestedClaim, requestedValue string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := req.Context()

			token, err := checkOIDCTokenFromRequest(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			pi := info.ProviderInfoFromContext(ctx)
			resp, err := checkIntrospectWithCached(ctx, resourceServer, token, pi.IntrospectionResponse)
			if err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			ctx = pi.SetIntrospectionResponse(resp).IntoContext(ctx)

			if err := checkAuthorization(pi.IntrospectionResponse, requestedClaim, requestedValue); err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}

func oidcAuthenticatedUnaryInterceptor(resourceServer rs.ResourceServer) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, sInfo *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		token, err := checkOIDCToken(metautils.ExtractIncoming(ctx).Get("authorization"))
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		pi := info.ProviderInfoFromContext(ctx)
		iResp, err := checkIntrospectWithCached(ctx, resourceServer, token, pi.IntrospectionResponse)
		if err != nil {
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
		ctx = pi.SetIntrospectionResponse(iResp).IntoContext(ctx)

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

func oidcAuthenticatedStreamInterceptor(resourceServer rs.ResourceServer) grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, sInfo *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := stream.Context()

		token, err := checkOIDCToken(metautils.ExtractIncoming(ctx).Get("authorization"))
		if err != nil {
			return status.Error(codes.Unauthenticated, err.Error())
		}

		pi := info.ProviderInfoFromContext(ctx)
		resp, err := checkIntrospectWithCached(ctx, resourceServer, token, pi.IntrospectionResponse)
		if err != nil {
			return status.Error(codes.PermissionDenied, err.Error())
		}
		ctx = pi.SetIntrospectionResponse(resp).IntoContext(ctx)

		return handler(srv, &serverStream{stream, ctx})
	}
}

func checkOIDCTokenFromRequest(r *http.Request) (string, error) {
	auth := r.Header.Get("authorization")
	if auth == "" {
		return "", ErrMissingHeader
	}
	return checkOIDCToken(auth)
}

func checkOIDCToken(auth string) (string, error) {
	if !strings.HasPrefix(auth, oidc.PrefixBearer) {
		return "", ErrInvalidHeader
	}
	return strings.TrimPrefix(auth, oidc.PrefixBearer), nil
}

func checkIntrospect(ctx context.Context, resourceServer rs.ResourceServer, token string) (*oidc.IntrospectionResponse, error) {
	resp, err := rs.Introspect[*oidc.IntrospectionResponse](ctx, resourceServer, token)
	if err != nil {
		return nil, ErrInvalidToken
	}
	if !resp.Active {
		return nil, ErrInvalidToken
	}
	return resp, nil
}

func checkIntrospectWithCached(ctx context.Context, resourceServer rs.ResourceServer, token string, cached *oidc.IntrospectionResponse) (*oidc.IntrospectionResponse, error) {
	if cached == nil {
		return checkIntrospect(ctx, resourceServer, token)
	}
	return cached, nil
}

func checkAuthorization(resp *oidc.IntrospectionResponse, requestedClaim, requestedValue string) error {
	value, ok := resp.Claims[requestedClaim].(string)
	if !ok || value == "" || value != requestedValue {
		return ErrInvalidAuthorization
	}
	return nil
}
