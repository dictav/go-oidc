package oidc_test

import (
	"context"
	"log"
	"os"
	"testing"

	"github.com/dictav/go-oidc"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func testJWKSet(t *testing.T, cfguri string) {
	t.Helper()

	ctx := context.Background()

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

func testParse(t *testing.T, envkey string, opts ...oidc.ParseOption) {
	t.Helper()

	token := os.Getenv(envkey)
	if token == "" {
		t.Skip(envkey + " is not set")
	}

	ret, err := oidc.Parse(context.Background(), []byte(token), opts...)
	if err != nil {
		t.Fatal(err)
	}

	email, err := oidc.Email(ret)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("Parse %s: email=%s", envkey, email)
}
