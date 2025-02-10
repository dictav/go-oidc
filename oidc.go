package oidc

import (
	"context"
	"fmt"
	"net/mail"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	expirationMargin = 60 * time.Second
)

var (
	jwkCache *jwk.Cache
)

func init() {
	jwkCache = jwk.NewCache(context.Background())
}

type parseOption struct {
	aud     string
	kid     string
	jwksuri string
}

type ParseOption func(*parseOption)

func WithAudience(aud string) ParseOption {
	return func(opt *parseOption) {
		opt.aud = aud
	}
}

func WithKeyID(kid string) ParseOption {
	return func(opt *parseOption) {
		opt.kid = kid
	}
}

func WithJWKSURI(uri string) ParseOption {
	return func(opt *parseOption) {
		opt.aud = uri
	}
}

//nolint:cyclop,funlen,ireturn
func Parse(ctx context.Context, token []byte, opts ...ParseOption) (jwt.Token, error) {
	var opt parseOption

	for _, f := range opts {
		f(&opt)
	}

	t, err := jwt.ParseInsecure(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if err := validateAudience(t.Audience(), opt.aud); err != nil {
		return nil, err
	}

	if time.Until(t.Expiration()) < expirationMargin {
		return nil, fmt.Errorf("token is too old: %s", t.Expiration())
	}

	alg, kid, err := extractAlgAndKid(token)
	if err != nil {
		return nil, err
	}

	if opt.kid != "" {
		kid = opt.kid
	}

	jwksuri := opt.jwksuri
	if jwksuri == "" {
		uri, err := jwksURI(ctx, t)
		if err != nil {
			return nil, fmt.Errorf("built-in jwks uri: %w", err)
		}

		jwksuri = uri
	}

	jwks, err := jwkSet(ctx, jwksuri)
	if err != nil {
		return nil, err
	}

	if jwks.Len() == 0 {
		return nil, fmt.Errorf("there is no key in JWKS")
	}

	pubKey, ok := jwks.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("no such key: %s", kid)
	}

	if _, err = jws.Verify(token, jws.WithKey(alg, pubKey)); err != nil {
		return nil, fmt.Errorf("verify error: %w", err)
	}

	return t, nil
}

func Email(t jwt.Token) (string, error) {
	iss := t.Issuer()

	switch {
	case iss == appleIssuer:
		return email(t, appleEmailKey)
	case iss == googleIssuer:
		return email(t, googleEmailKey)
	case adb2cIssuerRegex.MatchString(iss):
		return adb2cEmail(t)
	default:
		return "", fmt.Errorf("email not supported for %s", iss)
	}
}

func email(t jwt.Token, key string) (string, error) {
	v, ok := t.Get(key)
	if !ok {
		return "", fmt.Errorf("there is no email in token")
	}

	if err := validateEmailValue(v); err != nil {
		return "", err
	}

	return v.(string), nil //nolint:forcetypeassert
}

func validateEmailValue(v any) error {
	s, ok := v.(string)
	if !ok || s == "" {
		return fmt.Errorf("unexpected email value: %v", v)
	}

	if _, err := mail.ParseAddressList(s); err != nil {
		return fmt.Errorf("invalid email: %w", err)
	}

	return nil
}

func extractAlgAndKid(token []byte) (jwa.SignatureAlgorithm, string, error) {
	ts, err := jws.Parse(token)
	if err != nil {
		return "", "", fmt.Errorf("invalid signature: %w", err)
	}

	sigs := ts.Signatures()
	csigs := len(sigs)

	if csigs != 1 {
		return "", "", fmt.Errorf("invalid signatures count: %d", csigs)
	}

	// alg value is validated in jws.Verify() to ensure it is registered.
	// Note: jws.Verify() explicitly disallows the use of 'none':
	// > failed to create verifier for algorithm "none": unsupported signature algorithm "none"
	alg := sigs[0].ProtectedHeaders().Algorithm()
	kid := sigs[0].ProtectedHeaders().KeyID()

	return alg, kid, nil
}
