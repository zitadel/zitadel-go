package tokenexchange_test

import (
	"context"
	"fmt"
	"log"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/tokenexchange"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

func Example_impersonateByUserID() {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")

	api, err := client.New(ctx, z,
		client.WithAuth(client.DefaultServiceUserAuthentication(
			"/path/to/key.json",
			oidc.ScopeOpenID,
			client.ScopeZitadelAPI(),
		)),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = api.Close() }()

	actorToken, err := api.GetValidToken()
	if err != nil {
		log.Fatal(err)
	}

	result, err := tokenexchange.Impersonate(ctx, z,
		"259242039378444290",
		actorToken,
		tokenexchange.SubjectIsUserID(),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Impersonated token obtained, expires in %d seconds\n", result.ExpiresIn)
}

func Example_impersonateByAccessToken() {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")

	api, err := client.New(ctx, z,
		client.WithAuth(client.DefaultServiceUserAuthentication(
			"/path/to/key.json",
			oidc.ScopeOpenID,
			client.ScopeZitadelAPI(),
		)),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = api.Close() }()

	actorToken, _ := api.GetValidToken()
	userAccessToken := "NaUAPHy5mLFQlwUCeUGYeDyhcQYuNhzTiYgwMor9BxP..."

	result, err := tokenexchange.Impersonate(ctx, z,
		userAccessToken,
		actorToken,
		tokenexchange.SubjectIsAccessToken(),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Impersonated token: %s...\n", result.AccessToken[:20])
}

func Example_impersonateByIDToken() {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")

	api, err := client.New(ctx, z,
		client.WithAuth(client.DefaultServiceUserAuthentication(
			"/path/to/key.json",
			oidc.ScopeOpenID,
			client.ScopeZitadelAPI(),
		)),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = api.Close() }()

	actorToken, _ := api.GetValidToken()
	userIDToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

	result, err := tokenexchange.Impersonate(ctx, z,
		userIDToken,
		actorToken,
		tokenexchange.SubjectIsIDToken(),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Impersonated token type: %s\n", result.TokenType)
}

func Example_impersonateByJWT() {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")

	api, err := client.New(ctx, z,
		client.WithAuth(client.DefaultServiceUserAuthentication(
			"/path/to/key.json",
			oidc.ScopeOpenID,
			client.ScopeZitadelAPI(),
		)),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = api.Close() }()

	actorToken, _ := api.GetValidToken()
	selfSignedJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

	result, err := tokenexchange.Impersonate(ctx, z,
		selfSignedJWT,
		actorToken,
		tokenexchange.SubjectIsJWT(),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Impersonated token type: %s\n", result.TokenType)
}

func Example_impersonateWithScopes() {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")

	api, err := client.New(ctx, z,
		client.WithAuth(client.DefaultServiceUserAuthentication(
			"/path/to/key.json",
			oidc.ScopeOpenID,
			client.ScopeZitadelAPI(),
		)),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = api.Close() }()

	actorToken, _ := api.GetValidToken()

	result, err := tokenexchange.Impersonate(ctx, z,
		"259242039378444290",
		actorToken,
		tokenexchange.SubjectIsUserID(),
		tokenexchange.WithScopes("openid", "profile", "email"),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Token scopes: %v\n", result.Scopes)
	if result.IDToken != "" {
		fmt.Println("ID Token present (openid scope was granted)")
	}
}

func Example_impersonateWithAudience() {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")

	api, err := client.New(ctx, z,
		client.WithAuth(client.DefaultServiceUserAuthentication(
			"/path/to/key.json",
			oidc.ScopeOpenID,
			client.ScopeZitadelAPI(),
		)),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = api.Close() }()

	actorToken, _ := api.GetValidToken()

	result, err := tokenexchange.Impersonate(ctx, z,
		"259242039378444290",
		actorToken,
		tokenexchange.SubjectIsUserID(),
		tokenexchange.WithAudience("https://api.example.com"),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Token type: %s\n", result.TokenType)
}

func Example_impersonateRequestJWT() {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")

	api, err := client.New(ctx, z,
		client.WithAuth(client.DefaultServiceUserAuthentication(
			"/path/to/key.json",
			oidc.ScopeOpenID,
			client.ScopeZitadelAPI(),
		)),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = api.Close() }()

	actorToken, _ := api.GetValidToken()

	result, err := tokenexchange.Impersonate(ctx, z,
		"259242039378444290",
		actorToken,
		tokenexchange.SubjectIsUserID(),
		tokenexchange.WithRequestedTokenType(oidc.JWTTokenType),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("JWT access token obtained (starts with eyJ): %v\n", result.AccessToken[:3] == "eyJ")
}

func Example_impersonateWithActorIDToken() {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")

	actorIDToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

	result, err := tokenexchange.Impersonate(ctx, z,
		"259242039378444290",
		actorIDToken,
		tokenexchange.SubjectIsUserID(),
		tokenexchange.ActorIsIDToken(),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Impersonated token type: %s\n", result.TokenType)
}

func Example_impersonateWithRefreshToken() {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")

	api, err := client.New(ctx, z,
		client.WithAuth(client.DefaultServiceUserAuthentication(
			"/path/to/key.json",
			oidc.ScopeOpenID,
			client.ScopeZitadelAPI(),
		)),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = api.Close() }()

	actorToken, _ := api.GetValidToken()

	result, err := tokenexchange.Impersonate(ctx, z,
		"259242039378444290",
		actorToken,
		tokenexchange.SubjectIsUserID(),
		tokenexchange.WithScopes("openid", "offline_access"),
	)
	if err != nil {
		log.Fatal(err)
	}

	if result.RefreshToken != "" {
		fmt.Println("Refresh token obtained")
	}
}

func Example_impersonateWithAllOptions() {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")

	api, err := client.New(ctx, z,
		client.WithAuth(client.DefaultServiceUserAuthentication(
			"/path/to/key.json",
			oidc.ScopeOpenID,
			client.ScopeZitadelAPI(),
		)),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = api.Close() }()

	actorToken, _ := api.GetValidToken()

	result, err := tokenexchange.Impersonate(ctx, z,
		"259242039378444290",
		actorToken,
		tokenexchange.SubjectIsUserID(),
		tokenexchange.ActorIsAccessToken(),
		tokenexchange.WithScopes("openid", "profile", "email"),
		tokenexchange.WithAudience("https://api.example.com"),
		tokenexchange.WithRequestedTokenType(oidc.JWTTokenType),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Full impersonation result - Token: %s..., Scopes: %v\n", result.AccessToken[:20], result.Scopes)
}

func Example_delegate() {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")

	api, err := client.New(ctx, z,
		client.WithAuth(client.DefaultServiceUserAuthentication(
			"/path/to/key.json",
			oidc.ScopeOpenID,
			client.ScopeZitadelAPI(),
		)),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = api.Close() }()

	actorToken, _ := api.GetValidToken()

	result, err := tokenexchange.Delegate(ctx, z,
		"259242039378444290",
		actorToken,
		tokenexchange.SubjectIsUserID(),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Delegated token type: %s\n", result.TokenType)
}

func Example_exchangeReduceScope() {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")
	myAccessToken := "existing-access-token..."

	result, err := tokenexchange.Exchange(ctx, z,
		myAccessToken,
		tokenexchange.SubjectIsAccessToken(),
		tokenexchange.WithScopes("openid"),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Token with reduced scope: %v\n", result.Scopes)
}

func Example_exchangeReduceAudience() {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")
	myAccessToken := "existing-access-token..."

	result, err := tokenexchange.Exchange(ctx, z,
		myAccessToken,
		tokenexchange.SubjectIsAccessToken(),
		tokenexchange.WithAudience("https://restricted-api.example.com"),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Token type: %s\n", result.TokenType)
}

func Example_exchangeConvertToJWT() {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")
	opaqueToken := "NaUAPHy5mLFQlwUCeUGYeDyhcQYuNhzTiYgwMor9BxP..."

	result, err := tokenexchange.Exchange(ctx, z,
		opaqueToken,
		tokenexchange.SubjectIsAccessToken(),
		tokenexchange.WithRequestedTokenType(oidc.JWTTokenType),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Converted to JWT: %v\n", result.AccessToken[:3] == "eyJ")
}

func Example_exchangeFromIDToken() {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")
	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

	result, err := tokenexchange.Exchange(ctx, z,
		idToken,
		tokenexchange.SubjectIsIDToken(),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Exchanged token type: %s\n", result.TokenType)
}

func Example_exchangeFromJWT() {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")
	selfSignedJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

	result, err := tokenexchange.Exchange(ctx, z,
		selfSignedJWT,
		tokenexchange.SubjectIsJWT(),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Exchanged token type: %s\n", result.TokenType)
}

func Example_exchangeWithAllOptions() {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")
	myAccessToken := "existing-access-token..."

	result, err := tokenexchange.Exchange(ctx, z,
		myAccessToken,
		tokenexchange.SubjectIsAccessToken(),
		tokenexchange.WithScopes("openid", "profile"),
		tokenexchange.WithAudience("https://api.example.com"),
		tokenexchange.WithRequestedTokenType(oidc.JWTTokenType),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Full exchange result - Token: %s..., Scopes: %v\n", result.AccessToken[:20], result.Scopes)
}

func Example_createImpersonatedClient() {
	ctx := context.Background()
	z := zitadel.New("example.zitadel.cloud")

	serviceClient, err := client.New(ctx, z,
		client.WithAuth(client.DefaultServiceUserAuthentication(
			"/path/to/key.json",
			oidc.ScopeOpenID,
			client.ScopeZitadelAPI(),
		)),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = serviceClient.Close() }()

	actorToken, err := serviceClient.GetValidToken()
	if err != nil {
		log.Fatal(err)
	}

	result, err := tokenexchange.Impersonate(ctx, z,
		"259242039378444290",
		actorToken,
		tokenexchange.SubjectIsUserID(),
		tokenexchange.WithScopes("openid", "profile"),
	)
	if err != nil {
		log.Fatal(err)
	}

	impersonatedClient, err := client.New(ctx, z,
		client.WithAuth(client.PreSignedJWT(result.AccessToken)),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = impersonatedClient.Close() }()

	fmt.Println("Successfully created impersonated client")
}
