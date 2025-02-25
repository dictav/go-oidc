package oidc //nolint:testpackage

import (
	"log"
)

var (
	Export_validateAudience          = validateAudience
	Export_appleCoinfigurationURI    = appleConfigurationURI
	Export_googleCoinfigurationURI   = googleConfigurationURI
	Export_makeADB2CConfigurationURI = makeADB2CConfigurationURI
)

func CheckCache(cfguri string) bool {
	muxPM.RLock()
	defer muxPM.RUnlock()

	cfg, ok := cacheProviderMeta[cfguri]
	if !ok {
		log.Printf("cacheProviderMeta: %s not found in cache", cfguri)
		return false
	}

	return jwkCache.IsRegistered(cfg.JWKSURI)
}
