package oidc

import (
	"fmt"
	"log/slog"
	"net/url"
	"regexp"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	adb2cDefaultAuthorityDomain = "login.microsoftonline.com"
	adb2cAuthorityDomainSuffix  = ".b2clogin.com"
	adb2cTenantSuffix           = ".onmicrosoft.com"
	adb2cConfigurationURISuffix = "/v2.0/.well-known/openid-configuration"
	adb2cEmailKey               = "preferred_username"
	adb2cEmailsKey              = "emails"
)

var adb2cIssuerRegex = regexp.MustCompile(`^https://(login.microsoftonline.com|[a-zA-Z0-9-]+\.b2clogin\.com)/`)

func adb2cEmail(t jwt.Token) (string, error) {
	v, ok := t.Get(adb2cEmailKey)
	if ok {
		if s, ok := v.(string); ok {
			return s, nil
		}

		slog.Warn("adb2cEmail: unexpected `%s` value: %v", adb2cEmailKey, v)
	}

	v, ok = t.Get(adb2cEmailsKey)
	if !ok {
		return "", fmt.Errorf("there is no email in token")
	}

	arr, ok := v.([]any)
	if !ok {
		return "", fmt.Errorf("unexpected `%s` value: %v", adb2cEmailsKey, v)
	}

	for _, vv := range arr {
		err := validateEmailValue(vv)
		if err == nil {
			return vv.(string), nil //nolint:forcetypeassert
		}

		slog.Warn("adb2cEmail: invalid email: %s: %v", vv, err)
	}

	return "", fmt.Errorf("there is no valid email in token")
}

// makeADB2CConfigurationURI builds the URI for the OpenID Configuration document.
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
func makeADB2CConfigurationURI(tenant string, token jwt.Token) (string, error) {
	var policy string

	if v, ok := token.Get("tfp"); ok {
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("invalid tfp value: %q", policy)
		}

		policy = s
	}

	if tenant == "" && policy != "" {
		return "", fmt.Errorf("not support specifying only policy")
	}

	if tenant == "" {
		tenant = "common"
	}

	u, _ := url.Parse("https://")

	switch tenant {
	case "common", "organizations", "consumers":
		if policy != "" {
			return "", fmt.Errorf("not support specifying policy for %q", tenant)
		}

		u.Host = adb2cDefaultAuthorityDomain
		u.Path = "/" + tenant

	default:
		u.Host = tenant + adb2cAuthorityDomainSuffix
		u.Path = "/" + tenant + adb2cTenantSuffix

		if policy != "" {
			u.Path += "/" + policy
		}
	}

	u.Path += adb2cConfigurationURISuffix
	cfguri := u.String()

	if _, err := url.Parse(cfguri); err != nil {
		return "", fmt.Errorf("invalid url: %s", cfguri)
	}

	return cfguri, nil
}
