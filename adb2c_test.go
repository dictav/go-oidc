package oidc_test

import (
	"context"
	"log"
	"os"
	"testing"

	"github.com/dictav/go-oidc"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func TestJWKSet_adb2c(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	emptyToken := jwt.New()

	// test with common authority
	cfguri, err := oidc.Export_makeADB2CConfigurationURI("", emptyToken)
	if err != nil {
		t.Fatal(err)
	}

	set, err := oidc.JWKSet(ctx, cfguri)
	if err != nil {
		t.Fatal(err)
	}

	if !oidc.CheckCache(cfguri) {
		t.Errorf("should be registered: %s", cfguri)
	}

	if set.Len() == 0 {
		t.Fatal("empty JWK set")
	}

	t.Logf("there is %d keys", set.Len())

	it := set.Keys(ctx)

	for it.Next(ctx) {
		pair := it.Pair()

		v, err := jwk.PublicKeyOf(pair.Value)
		if err != nil {
			t.Errorf("failed to get public key: %v", err)
			continue
		}

		t.Logf("%d: %+v", pair.Index, v.KeyID())
	}
}

func TestParse_ADB2C(t *testing.T) {
	t.Parallel()

	token := os.Getenv("ADB2C_ID_TOKEN")
	if token == "" {
		t.Skip("ADB2C_ID_TOKEN is not set")
	}

	tenant := os.Getenv("ADB2C_TENANT")
	if tenant == "" {
		t.Log("NO SET ADB2C_TENANT")
	}

	ret, err := oidc.Parse(context.Background(), []byte(token), oidc.WithAzureADB2CTenant(tenant))
	if err != nil {
		t.Fatal(err)
	}

	email, err := oidc.Email(ret)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("Parse ADB2C ID Token: email=%s", email)
}
