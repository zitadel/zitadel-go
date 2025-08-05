package oauth_test

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type signParams struct {
	KeyID      string
	PrivateKey *rsa.PrivateKey
	Issuer     string
	Subject    string
	Audience   []string
	TTL        time.Duration
	NotBefore  time.Duration
	Algorithm  jwt.SigningMethod
}

// signTestJWT builds a signed token for unit tests only, with configurable options.
func signTestJWT(p signParams) (string, error) {
	now := time.Now().UTC()

	claims := jwt.RegisteredClaims{
		Issuer:    p.Issuer,
		Subject:   p.Subject,
		Audience:  jwt.ClaimStrings(p.Audience),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(p.NotBefore)),
		ExpiresAt: jwt.NewNumericDate(now.Add(p.TTL)),
	}

	// Default to RS256 if no algorithm is specified
	if p.Algorithm == nil {
		p.Algorithm = jwt.SigningMethodRS256
	}

	tok := jwt.NewWithClaims(p.Algorithm, claims)
	tok.Header["kid"] = p.KeyID

	// Handle the "none" algorithm case, which is unsigned
	if p.Algorithm == jwt.SigningMethodNone {
		return tok.SigningString()
	}

	if p.PrivateKey == nil {
		return "", errors.New("private key is required for signing")
	}
	return tok.SignedString(p.PrivateKey)
}
