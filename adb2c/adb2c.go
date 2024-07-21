package adb2c

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"sync"
	"time"

	"github.com/dictav/go-oidc"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	defaultAuthorityDomain       = "login.microsoftonline.com"
	authorityDomainSuffix        = ".b2clogin.com"
	tenantSuffix                 = ".onmicrosoft.com"
	openIDConfigurationURISuffix = "/v2.0/.well-known/openid-configuration"

	emailKey         = "preferred_username"
	expirationMargin = 60 * time.Second
)

var (
	jwkCache *jwk.Cache
	mu       sync.Mutex
)

func init() {
	jwkCache = jwk.NewCache(context.Background())
}

func SetCache(c *jwk.Cache) error {
	mu.Lock()
	defer mu.Unlock()

	if c == nil {
		return fmt.Errorf("cache is required")
	}

	jwkCache = c

	return nil
}

//nolint:cyclop,ireturn
func Parse(ctx context.Context, tenant string, token []byte) (jwt.Token, error) {
	t, err := jwt.ParseInsecure(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if time.Until(t.Expiration()) < expirationMargin {
		return nil, fmt.Errorf("token is too old: %s", t.Expiration())
	}

	alg, kid, err := extractAlgAndKid(token)
	if err != nil {
		return nil, err
	}

	var policy string

	if tfp, ok := t.Get("tfp"); ok {
		policy, ok = tfp.(string)
		if !ok || policy == "" {
			return nil, fmt.Errorf("invalid tfp value: %q", policy)
		}
	}

	jwks, err := JWKSets(ctx, tenant, policy)
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

func Email(t jwt.Token) (string, error) {
	if v, ok := t.Get(emailKey); ok {
		if err := validateEmailValue(v); err != nil {
			return "", err
		}

		return v.(string), nil //nolint:forcetypeassert
	}

	emails, err := Emails(t)
	if err != nil {
		return "", err
	}

	if len(emails) != 1 {
		return "", fmt.Errorf("unexpected emails count: %d", len(emails))
	}

	return emails[0], nil
}

func Emails(t jwt.Token) ([]string, error) {
	var emails []string

	v, ok := t.Get("emails")
	if !ok {
		return nil, fmt.Errorf("no emails value")
	}

	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("unexpected `emails` value: %v", v)
	}

	emails = make([]string, len(arr))

	for i, vv := range arr {
		if err := validateEmailValue(vv); err != nil {
			return nil, err
		}

		emails[i] = vv.(string) //nolint:forcetypeassert
	}

	return emails, nil
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

var cacheConfigURI sync.Map

// makeAzureConfigurationURI builds the URI for the OpenID Configuration document.
//
// Reference: https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc#find-your-apps-openid-configuration-document-uri
//
// Why doesn't it use the `iss` field from the OpenID Connect ID Token?
//
// The ID Token in Azure AD B2C includes an `iss` field formatted like below:
//
//	https://{tenant}.b2clogin.com/{tenant_uuid}/v2.0
//
// According to OpenID Connect Discovery 1.0, the OpenID Configuration URI should be:
//
//	https://{tenant}.b2clogin.com/{tenant_uuid}/v2.0/.well-known/openid-configuration
//
// Unfortunately, this URI returns a 404 error when a User-flow/Custom-policy is configured.
// As a workaround, the following URI format is effective:
//
//	https://{tenant}.b2clogin.com/{tenant_uuid}/v2.0/.well-known/openid-configuration?p={policy}
//
// However, this format is not documented in the official Azure documentation.
// The official documentation suggests using:
//
//	https://{tenant}.b2clogin.com/{tenant}.onmicrosoft.com/{policy}/v2.0/.well-known/openid-configuration
//
// Therefore, this function needs to manually set the tenant and policy values.
//
//nolint:cyclop
func makeAzureConfigurationURI(tenant, policy string) (string, error) {
	if tenant == "" && policy != "" {
		return "", fmt.Errorf("not support specifying only policy")
	}

	if tenant == "" {
		tenant = "common"
	}

	if v, ok := cacheConfigURI.Load(tenant + policy); ok {
		if s, ok := v.(string); ok {
			return s, nil
		}

		slog.Warn("cache has invalid value: tenant=%s policy=%s value=%v", tenant, policy, v)
	}

	u, _ := url.Parse("https://")

	switch tenant {
	case "common", "organizations", "consumers":
		if policy != "" {
			return "", fmt.Errorf("not support specifying policy for %q", tenant)
		}

		u.Host = defaultAuthorityDomain
		u.Path = "/" + tenant

	default:
		u.Host = tenant + authorityDomainSuffix
		u.Path = "/" + tenant + tenantSuffix

		if policy != "" {
			u.Path += "/" + policy
		}
	}

	u.Path += openIDConfigurationURISuffix
	cfguri := u.String()

	if _, err := url.Parse(cfguri); err != nil {
		return "", fmt.Errorf("invalid url: %s", cfguri)
	}

	cacheConfigURI.Store(tenant+policy, cfguri)

	return cfguri, nil
}

var cacheProviderMeta sync.Map

func fetchProviderMetadata(ctx context.Context, cfguri string) (*oidc.ProviderMeatadata, error) {
	if v, ok := cacheProviderMeta.Load(cfguri); ok {
		if c, ok := v.(oidc.ProviderMeatadata); ok {
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

	var cfg oidc.ProviderMeatadata

	if err := json.NewDecoder(res.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode configuration json: %w", err)
	}

	if err := cfg.Valid(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	cacheProviderMeta.Store(cfguri, cfg)

	return &cfg, nil
}

// JWKSet returns jwk.Set for Azure AD B2C specified by tenant and policy.
//
//nolint:ireturn
func JWKSet(ctx context.Context, tenant, policy string) (jwk.Set, error) {
	cfguri, err := makeAzureConfigurationURI(tenant, policy)
	if err != nil {
		return nil, fmt.Errorf("make openid configuration uri: %w", err)
	}

	cfg, err := fetchProviderMetadata(ctx, cfguri)
	if err != nil {
		return nil, fmt.Errorf("fetch openid provider metadata: %w", err)
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

// Deprecated: Use JWKSet instead.
//
//nolint:ireturn
func JWKSets(ctx context.Context, tenant, policy string) (jwk.Set, error) {
	return JWKSet(ctx, tenant, policy)
}
