package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"sync"
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
	jwkCache      *jwk.Cache
	validAudience func(audiences []string) bool
	muxAud        sync.RWMutex
)

func init() {
	jwkCache = jwk.NewCache(context.Background())
}

func SetValidAudience(f func(audiences []string) bool) {
	muxAud.Lock()
	validAudience = f
	muxAud.Unlock()
}

func validateAudience(audiences []string, aud string) error {
	if aud == "" && validAudience == nil {
		slog.Warn("strongly recommend checking the Audience using SetValidAudience or WithAudience option")
		return nil
	}

	if aud != "" {
		if !cotainsAudience(audiences, aud) {
			return fmt.Errorf("invalid audience (option): want=%s, got=%s", aud, audiences)
		}

		return nil
	}

	var ok bool

	muxAud.RLock()
	if validAudience != nil {
		ok = validAudience(audiences)
	}
	muxAud.RUnlock()

	if !ok {
		return fmt.Errorf("invalid audience (func): got=%v", audiences)
	}

	return nil
}

func cotainsAudience(list []string, aud string) bool {
	for _, v := range list {
		if v == aud {
			return true
		}
	}

	return false
}

type parseOption struct {
	aud         string
	adb2cTenant string
}

type ParseOption func(*parseOption)

func WithAudience(aud string) ParseOption {
	return func(opt *parseOption) {
		opt.aud = aud
	}
}

func WithAzureADB2CTenant(tenant string) ParseOption {
	return func(o *parseOption) {
		o.adb2cTenant = tenant
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

	var (
		cfguri string
		iss    = t.Issuer()
	)

	switch {
	case iss == appleIssuer:
		cfguri = appleConfigurationURI
	case iss == googleIssuer:
		cfguri = googleConfigurationURI
	case adb2cIssuerRegex.MatchString(iss):
		cfguri, err = makeADB2CConfigurationURI(opt.adb2cTenant, t)
		if err != nil {
			return nil, fmt.Errorf("make adb2c configuration uri: %w", err)
		}

	default:
		return nil, fmt.Errorf("not supported issuer: %s", iss)
	}

	if time.Until(t.Expiration()) < expirationMargin {
		return nil, fmt.Errorf("token is too old: %s", t.Expiration())
	}

	alg, kid, err := extractAlgAndKid(token)
	if err != nil {
		return nil, err
	}

	jwks, err := JWKSet(ctx, cfguri)
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

//nolint:ireturn
func JWKSet(ctx context.Context, cfguri string) (jwk.Set, error) {
	cfg, err := fetchProviderMetadata(ctx, cfguri)
	if err != nil {
		return nil, fmt.Errorf("fetch provider metadata: %w", err)
	}

	if !jwkCache.IsRegistered(cfg.JWKSURI) {
		if err := jwkCache.Register(cfg.JWKSURI); err != nil {
			return nil, fmt.Errorf("register jwks_uri: %w", err)
		}
	}

	set, err := jwkCache.Get(ctx, cfg.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("get jwk set: %w", err)
	}

	return set, nil
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

var cacheProviderMeta sync.Map

func fetchProviderMetadata(ctx context.Context, cfguri string) (*ProviderMetadata, error) {
	if v, ok := cacheProviderMeta.Load(cfguri); ok {
		if c, ok := v.(ProviderMetadata); ok {
			return &c, nil
		}

		slog.Warn("cache has invalid value: uri=%s value=%v", cfguri, v)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfguri, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid uri (%s): %w", cfguri, err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", cfguri, err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http get %s: stauts=%d", cfguri, res.StatusCode)
	}

	var cfg ProviderMetadata

	if err := json.NewDecoder(res.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode configuration json: %w", err)
	}

	if err := cfg.Valid(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	cacheProviderMeta.Store(cfguri, cfg)

	return &cfg, nil
}
