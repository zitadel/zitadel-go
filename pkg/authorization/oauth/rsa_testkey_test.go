// Package oauth provides helpers used exclusively in unit tests.
//
// This file defines TestKey, a thin wrapper around a generated RSA key
// pair that exposes convenience methods for producing JWK‑compatible
// values (modulus, exponent, thumb‑print) without leaking production
// code into the final binaries.
package oauth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
)

// b64 is the JOSE‑style base64url encoding (no padding).
var b64 = base64.RawURLEncoding

// TestKey represents an in‑memory RSA key pair and exposes helper
// methods that simplify JWT and JWKS related unit tests.
type TestKey struct {
	priv *rsa.PrivateKey
	kid  string
}

// NewTestKey generates a fresh RSA key pair of the requested size and
// immediately computes its RFC 7638 thumb‑print, caching the result in
// the TestKey instance.
func NewTestKey(bits int) (*TestKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	// Compute RFC 7638 SHA‑256 thumb‑print for the new public key.
	eBytes := big.NewInt(int64(priv.PublicKey.E)).Bytes()
	jwk := fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`,
		b64.EncodeToString(eBytes),
		b64.EncodeToString(priv.N.Bytes()))
	sum := sha256.Sum256([]byte(jwk))

	return &TestKey{
		priv: priv,
		kid:  b64.EncodeToString(sum[:]),
	}, nil
}

// Private returns the *rsa.PrivateKey associated with the TestKey so the
// caller can sign JSON Web Tokens directly.
func (k *TestKey) Private() *rsa.PrivateKey { return k.priv }

// Public returns the public portion of the RSA key. The value can be
// embedded into a JWKS document for token verification.
func (k *TestKey) Public() *rsa.PublicKey { return &k.priv.PublicKey }

// ExponentString encodes the public exponent using base64url without
// padding, matching the representation required for the JWK "e" field.
func (k *TestKey) ExponentString() string {
	eBytes := big.NewInt(int64(k.Public().E)).Bytes()
	return b64.EncodeToString(eBytes)
}

// ModulusString encodes the modulus using base64url without padding, as
// expected for the JWK "n" field.
func (k *TestKey) ModulusString() string {
	return b64.EncodeToString(k.Public().N.Bytes())
}

// KID returns the pre‑computed RFC 7638 thumb‑print for this key.
func (k *TestKey) KID() string { return k.kid }
