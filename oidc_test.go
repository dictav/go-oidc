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

//nolint:cyclop,gocognit,paralleltest
func TestValidateAudience(t *testing.T) {
	// usage: validateAudience(token.Audience(), parseOption.aud)
	token := jwt.New()
	if err := token.Set(jwt.AudienceKey, []string{
		"https://example.com",
		"https://accounts.example.com",
	}); err != nil {
		t.Fatal(err)
	}

	audiences := token.Audience()

	t.Log("audiences:", audiences)

	t.Run("no validation", func(t *testing.T) {
		oidc.SetValidAudience(nil)

		if err := oidc.Export_validateAudience(nil, ""); err != nil {
			t.Errorf("should not return error")
		}

		if err := oidc.Export_validateAudience(audiences, ""); err != nil {
			t.Errorf("should not return error")
		}
	})

	t.Run("WithAudience Option", func(t *testing.T) {
		if err := oidc.Export_validateAudience(audiences, "https://example.com"); err != nil {
			t.Errorf("should not return error: err=%s", err)
		}

		if err := oidc.Export_validateAudience(audiences, "https://accounts.example.com"); err != nil {
			t.Errorf("should not return error: err=%s", err)
		}

		if err := oidc.Export_validateAudience(audiences, "https://akuma.example.com"); err == nil {
			t.Errorf("should return error")
		}

		if err := oidc.Export_validateAudience(nil, "https://example.com"); err == nil {
			t.Errorf("should return error")
		}
	})

	t.Run("SetValidAudience", func(t *testing.T) {
		defer oidc.SetValidAudience(nil)

		t.Run("allow accounts.example.com", func(t *testing.T) {
			oidc.SetValidAudience(func(audiences []string) bool {
				for _, aud := range audiences {
					switch aud {
					case "https://accounts.example.com":
						return true
					}
				}

				return false
			})

			if err := oidc.Export_validateAudience(audiences, ""); err != nil {
				t.Errorf("should not return error: err=%s", err)
			}
		})

		t.Run("allow akuma.example.com", func(t *testing.T) {
			oidc.SetValidAudience(func(audiences []string) bool {
				for _, aud := range audiences {
					switch aud {
					case "https://akuma.example.com":
						return true
					}
				}

				return false
			})

			if err := oidc.Export_validateAudience(audiences, ""); err == nil {
				t.Errorf("should return error")
			}
		})

		t.Run("always true", func(t *testing.T) {
			oidc.SetValidAudience(func(_ []string) bool {
				return false
			})

			if err := oidc.Export_validateAudience(nil, ""); err == nil {
				t.Errorf("should not return error")
			}
		})
	})
}

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
