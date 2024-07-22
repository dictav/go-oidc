package oidc

import (
	"log"
)

var (
	Export_appleCoinfigurationURI    = appleConfigurationURI
	Export_googleCoinfigurationURI   = googleConfigurationURI
	Export_makeADB2CConfigurationURI = makeADB2CConfigurationURI
)

func CheckCache(cfguri string) bool {
	v, ok := cacheProviderMeta.Load(cfguri)
	if !ok {
		log.Printf("cacheProviderMeta: %s not found in cache", cfguri)
		return false
	}

	cfg := v.(ProviderMetadata)

	return jwkCache.IsRegistered(cfg.JWKSURI)
}
