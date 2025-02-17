package oidc

import (
	"context"
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	adb2cTenant  string
	customIssure func(iss string) (string, bool)
	httpClient   jwk.HTTPClient
	muxJWKS      sync.RWMutex
)

func SetAzureADB2CTenant(tenant string) {
	muxJWKS.Lock()
	defer muxJWKS.Unlock()

	adb2cTenant = tenant
}

func SetCustomIssure(f func(iss string) (string, bool)) {
	muxJWKS.Lock()
	defer muxJWKS.Unlock()

	customIssure = f
}

func SetHTTPClient(client jwk.HTTPClient) {
	muxJWKS.Lock()
	defer muxJWKS.Unlock()

	httpClient = client
}

func jwksURI(ctx context.Context, t jwt.Token) (string, error) {
	var (
		cfguri string
		err    error
		iss    = t.Issuer()
	)

	switch {
	case iss == appleIssuer:
		cfguri = appleConfigurationURI
	case iss == googleIssuer:
		cfguri = googleConfigurationURI
	case adb2cIssuerRegex.MatchString(iss):
		cfguri, err = makeADB2CConfigurationURI(adb2cTenant, t)
		if err != nil {
			return "", fmt.Errorf("make adb2c configuration uri: %w", err)
		}

	default:
		var ok bool

		muxJWKS.RLock()
		if customIssure != nil {
			cfguri, ok = customIssure(iss)
		}
		muxJWKS.RUnlock()

		if !ok {
			return "", fmt.Errorf("not supported issuer: %s", iss)
		}
	}

	cfg, err := fetchProviderMetadata(ctx, cfguri)
	if err != nil {
		return "", fmt.Errorf("fetch provider metadata: %w", err)
	}

	return cfg.JWKSURI, nil
}

//nolint:ireturn
func jwkSet(ctx context.Context, jwksuri string) (jwk.Set, error) {
	var (
		opts         []jwk.RegisterOption
		isRegistered bool
	)

	muxJWKS.RLock()
	if httpClient != nil {
		opts = append(opts, jwk.WithHTTPClient(httpClient))
	}
	isRegistered = jwkCache.IsRegistered(jwksuri)
	muxJWKS.RUnlock()

	if !isRegistered {
		muxJWKS.Lock()
		err := jwkCache.Register(jwksuri, opts...)
		muxJWKS.Unlock()

		if err != nil {
			return nil, fmt.Errorf("register jwks_uri: %w", err)
		}
	}

	set, err := jwkCache.Get(ctx, jwksuri)
	if err != nil {
		return nil, fmt.Errorf("get jwk set: %w", err)
	}

	return set, nil
}
