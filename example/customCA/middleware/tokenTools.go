package middleware

import (
	"context"
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/client/profile"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/middleware"
	"golang.org/x/oauth2"
)

// JWTProfileFromFileData creates a JWTProfileTokenSource from the provided key file data.
/*
It allows using the OAuth2 JWT Profile Grant to get a token using a zitadel json key provided by ZITADEL.
The passed context is only used for the call to the Discover endpoint.
The httpClient is used for the token requests. You can customize it to set timeouts, TLS (self-signed CA) settings, etc.
*/
func JWTProfileFromFileData(ctx context.Context, fileData []byte, httpClient *http.Client) middleware.JWTProfileTokenSource {
	return func(issuer string, scopes []string) (oauth2.TokenSource, error) {
		keyData, err := client.ConfigFromKeyFileData(fileData)
		if err != nil {
			return nil, err
		}
		return JWTProfileFromKeyAndUserID(ctx, keyData.Key, keyData.KeyID, keyData.UserID, httpClient)(issuer, scopes)
	}
}

// JWTProfileFromFile creates a JWTProfileTokenSource from the provided key file path.
/*
It allows using the OAuth2 JWT Profile Grant to get a token using a zitadel json key provided by ZITADEL.
The passed context is only used for the call to the Discover endpoint.
The httpClient is used for the token requests. You can customize it to set timeouts, TLS (self-signed CA) settings, etc.
*/
func JWTProfileFromFile(ctx context.Context, file string, httpClient *http.Client) middleware.JWTProfileTokenSource {
	return func(issuer string, scopes []string) (oauth2.TokenSource, error) {
		keyData, err := client.ConfigFromKeyFile(file)
		if err != nil {
			return nil, err
		}
		return JWTProfileFromKeyAndUserID(ctx, keyData.Key, keyData.KeyID, keyData.UserID, httpClient)(issuer, scopes)
	}
}

// JWTProfileFromKeyAndUserID creates a JWTProfileTokenSource from the provided key, key ID, and user ID.
func JWTProfileFromKeyAndUserID(ctx context.Context, key []byte, keyID, userID string, httpClient *http.Client) middleware.JWTProfileTokenSource {
	return func(issuer string, scopes []string) (oauth2.TokenSource, error) {

		return profile.NewJWTProfileTokenSource(ctx, issuer, userID, keyID, key, scopes, profile.WithHTTPClient(httpClient))
	}
}
