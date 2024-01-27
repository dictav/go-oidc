package adb2c

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/dictav/go-oidc"
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

		return v.(string), nil
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

		emails[i] = vv.(string)
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

// buildOpenIDConfigurationURI builds the URI for the OpenID Configuration document.
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
func buildOpenIDConfigurationURI(tenant, policy string) (string, error) {
	if tenant == "" && policy != "" {
		return "", fmt.Errorf("not support specifing only policy")
	}

	if tenant == "" {
		tenant = "common"
	}

	u, _ := url.Parse("https://")

	switch tenant {
	case "common", "organizations", "consumers":
		if policy != "" {
			return "", fmt.Errorf("not support specifing policy for %q", tenant)
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
		return "", fmt.Errorf("invalid openid-configuration url: %s", cfguri)
	}

	return cfguri, nil
}

// JWKSets returns jwk.Set for Azure AD B2C specified by tenant and policy.
//
// TODO: cache jwks_uri
func JWKSets(ctx context.Context, tenant, policy string) (jwk.Set, error) {
	cfguri, err := buildOpenIDConfigurationURI(tenant, policy)
	if err != nil {
		return nil, fmt.Errorf("failed to build openid configuration uri: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfguri, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid openid configuration uri (%s): %w", cfguri, err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch openid-configuration (%s): %w", cfguri, err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch openid-configuration (%s): stauts=%d", cfguri, res.StatusCode)
	}

	var cfg oidc.ProviderMeatadata
	if err := json.NewDecoder(res.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode configuration json: %w", err)
	}

	if err := cfg.Valid(); err != nil {
		return nil, fmt.Errorf("invalid openid configuration: %w", err)
	}

	if !jwkCache.IsRegistered(cfg.JWKSURI) {
		jwkCache.Register(cfg.JWKSURI)
	}

	return jwkCache.Get(ctx, cfg.JWKSURI)
}
