package oauth_test

import (
	"crypto/rsa"
	jwt "github.com/golang-jwt/jwt/v5"
	"time"
)

type signParams struct {
	KeyID      string
	PrivateKey *rsa.PrivateKey
	Issuer     string
	Subject    string
	Audience   []string
	TTL        time.Duration
}

// signTestJWT builds a signed RS256 token for unit tests only.
func signTestJWT(p signParams) (string, error) {
	now := time.Now().UTC()

	claims := jwt.RegisteredClaims{
		Issuer:    p.Issuer,
		Subject:   p.Subject,
		Audience:  jwt.ClaimStrings(p.Audience),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(p.TTL)),
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = p.KeyID
	return tok.SignedString(p.PrivateKey)
}
