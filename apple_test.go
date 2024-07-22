package oidc_test

import (
	"testing"

	"github.com/dictav/go-oidc"
)

func TestJWKSet_apple(t *testing.T) {
	t.Parallel()
	testJWKSet(t, oidc.Export_appleCoinfigurationURI)
}

func TestParse_Apple(t *testing.T) {
	t.Parallel()
	testParse(t, "APPLE_ID_TOKEN")
}
