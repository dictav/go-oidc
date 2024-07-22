package oidc_test

import (
	"context"
	"log"
	"os"
	"testing"

	"github.com/dictav/go-oidc"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func TestJWKSet_apple(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	cfguri := oidc.Export_appleCoinfigurationURI

	set, err := oidc.JWKSet(ctx, cfguri)
	if err != nil {
		t.Fatal(err)
	}

	if !oidc.CheckCache(cfguri) {
		t.Errorf("should be registered: %s", cfguri)
	}

	t.Logf("there is %d keys", set.Len())

	if set.Len() == 0 {
		t.Fatal("empty JWK set")
	}

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

func TestParse_Apple(t *testing.T) {
	t.Parallel()

	token := os.Getenv("APPLE_ID_TOKEN")
	if token == "" {
		t.Skip("APPLE_ID_TOKEN is not set")
	}

	ret, err := oidc.Parse(context.Background(), []byte(token))
	if err != nil {
		t.Fatal(err)
	}

	email, err := oidc.Email(ret)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("Parse Apple ID Token: email=%s", email)
}
