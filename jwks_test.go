package oidc_test

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"

	. "github.com/dictav/go-oidc"
)

//go:embed testdata/jwks.json
var internalJWKS []byte

//go:embed testdata/token.json
var testTokenData []byte

type internalClient struct{}

type tokenData struct {
	Header    map[string]any `json:"header"`
	Payload   map[string]any `json:"payload"`
	Signature string         `json:"signature"`
}

func (c *internalClient) Get(u string) (*http.Response, error) {
	var res http.Response

	b := bytes.NewBuffer(internalJWKS)
	res.Header = make(http.Header)
	res.StatusCode = http.StatusOK
	res.Body = io.NopCloser(b)

	res.Header.Add("Content-Type", "application/json")

	return &res, nil
}

func Test_internalJWKS(t *testing.T) {
	c := &internalClient{}
	ctx := context.Background()

	SetHTTPClient(c)
	t.Cleanup(func() {
		SetHTTPClient(nil)
	})

	set, err := Export_jwkSet(ctx, "test")
	if err != nil {
		t.Fatalf("should not return error: %v", err)
	}

	key, ok := set.LookupKeyID("test")
	if !ok {
		t.Fatalf("should return key for %q", "test")
	}

	var data tokenData

	if err := json.Unmarshal(testTokenData, &data); err != nil {
		t.Fatalf("should not return error: %v", err)
	}

	hb, err := json.Marshal(data.Header)
	if err != nil {
		t.Fatalf("should not return error: %v", err)
	}

	pb, err := json.Marshal(data.Payload)
	if err != nil {
		t.Fatalf("should not return error: %v", err)
	}

	token := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb) + "." + data.Signature

	t.Logf("token: %s", token)

	b, err := jws.Verify([]byte(token), jws.WithKey(jwa.RS256, key))
	if err != nil {
		t.Fatalf("should not return error: %v", err)
	}

	t.Logf("verified payload: %s", b)
}
