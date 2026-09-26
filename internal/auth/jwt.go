package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTConfig struct {
	Secret []byte
	Iss    string
	Aud    string
	Skew   time.Duration // allowed clock skew
}

func IssueJWT(sub string, ttl time.Duration, cfg JWTConfig) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Subject:   sub,
		Issuer:    cfg.Iss,
		Audience:  jwt.ClaimStrings{cfg.Aud},
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-cfg.Skew)),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		ID:        hex.EncodeToString(jti),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(cfg.Secret)
}

func VerifyJWT(tok string, cfg JWTConfig) (string, error) {
	// Let the parser enforce alg, iss, aud, exp/nbf/iat with leeway.
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithLeeway(cfg.Skew),
		jwt.WithIssuer(cfg.Iss),
		jwt.WithAudience(cfg.Aud),
	)

	var rc jwt.RegisteredClaims
	_, err := parser.ParseWithClaims(tok, &rc, func(t *jwt.Token) (interface{}, error) {
		return cfg.Secret, nil
	})
	if err != nil {
		return "", err
	}

	// Defense-in-depth: ensure subject and audience explicitly.
	if rc.Subject == "" {
		return "", errors.New("missing sub")
	}
	if !audContains(rc.Audience, cfg.Aud) {
		return "", errors.New("bad aud")
	}
	if rc.Issuer != cfg.Iss {
		return "", errors.New("bad iss")
	}
	return rc.Subject, nil
}

func audContains(aud jwt.ClaimStrings, want string) bool {
	for _, a := range aud {
		if a == want {
			return true
		}
	}
	return false
}
