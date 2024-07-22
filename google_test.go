package oidc_test

import (
	"testing"

	"github.com/dictav/go-oidc"
)

func TestJWKSet_Google(t *testing.T) {
	t.Parallel()
	testJWKSet(t, oidc.Export_googleCoinfigurationURI)
}

func TestParse_Google(t *testing.T) {
	t.Parallel()
	testParse(t, "GOOGLE_ID_TOKEN")
}
