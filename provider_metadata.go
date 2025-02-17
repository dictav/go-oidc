/*
Copyright (c) 2023 The OpenID Foundation.

The OpenID Foundation (OIDF) grants to any Contributor, developer, implementer, or other interested party a non-exclusive, royalty free, worldwide copyright license to reproduce, prepare derivative works from, distribute, perform and display, this Implementers Draft or Final Specification solely for the purposes of (i) developing specifications, and (ii) implementing Implementers Drafts and Final Specifications based on such documents, provided that attribution be made to the OIDF as the source of the material, but that such attribution does not indicate an endorsement by the OIDF.

The technology described in this specification was made available from contributions from various sources, including members of the OpenID Foundation and others. Although the OpenID Foundation has taken steps to help ensure that the technology is available for distribution, it takes no position regarding the validity or scope of any intellectual property or other rights that might be claimed to pertain to the implementation or use of the technology described in this specification or the extent to which any license under such rights might or might not be available; neither does it represent that it has made any independent effort to identify any such rights. The OpenID Foundation and the contributors to this specification make no (and hereby expressly disclaim any) warranties (express, implied, or otherwise), including implied warranties of merchantability, non-infringement, fitness for a particular purpose, or title, related to this specification, and the entire risk as to implementing this specification is assumed by the implementer. The OpenID Intellectual Property Rights policy requires contributors to offer a patent promise not to assert certain patent claims against other contributors and against implementers. The OpenID Foundation invites any interested party to bring to its attention any copyrights, patents, patent applications, or other proprietary rights that may cover technology that may be required to practice this specification.
*/

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
)

var (
	cacheProviderMeta map[string]ProviderMetadata
	pmmux             sync.RWMutex
)

func init() {
	cacheProviderMeta = make(map[string]ProviderMetadata)
}

// This code is based on the OpenID Connect 1.0 specification, which is
// licensed under the Apache License, Version 2.0.
//
// see https://openid.net/specs/openid-connect-discovery-1_0.html
type ProviderMetadata struct {
	// REQUIRED. URL using the https scheme with no query or fragment components that the OP asserts as its Issuer Identifier. If Issuer discovery is supported (see Section 2), this value MUST be identical to the issuer value returned by WebFinger. This also MUST be identical to the iss Claim value in ID Tokens issued from this Issuer.
	Issuer string `json:"issuer"`

	// REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint [OpenID.Core]. This URL MUST use the https scheme and MAY contain port, path, and query parameter components.
	AuthorizationEndpoint string `json:"authorization_endpoint"`

	// URL of the OP's OAuth 2.0 Token Endpoint [OpenID.Core]. This is REQUIRED unless only the Implicit Flow is used. This URL MUST use the https scheme and MAY contain port, path, and query parameter components.
	TokenEndpoint string `json:"token_endpoint"`

	// RECOMMENDED. URL of the OP's UserInfo Endpoint [OpenID.Core]. This URL MUST use the https scheme and MAY contain port, path, and query parameter components.
	UserinfoEndpoint string `json:"userinfo_endpoint"`

	// REQUIRED. URL of the OP's JWK Set [JWK] document, which MUST use the https scheme. This contains the signing key(s) the RP uses to validate signatures from the OP. The JWK Set MAY also contain the Server's encryption key(s), which are used by RPs to encrypt requests to the Server. When both signing and encryption keys are made available, a use (public key use) parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended usage. Although some algorithms allow the same key to be used for both signatures and encryption, doing so is NOT RECOMMENDED, as it is less secure. The JWK x5c parameter MAY be used to provide X.509 representations of keys provided. When used, the bare key values MUST still be present and MUST match those in the certificate. The JWK Set MUST NOT contain private or symmetric key values.
	JWKSURI string `json:"jwks_uri"`

	// RECOMMENDED. URL of the OP's Dynamic Client Registration Endpoint [OpenID.Registration], which MUST use the https scheme.
	RegistrationEndpoint string `json:"registration_endpoint"`

	// RECOMMENDED. JSON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server supports. The server MUST support the openid scope value. Servers MAY choose not to advertise some supported scope values even when this parameter is used, although those defined in [OpenID.Core] SHOULD be listed, if supported.
	ScopesSupported []string `json:"scopes_supported"`

	// REQUIRED. JSON array containing a list of the OAuth 2.0 response_type values that this OP supports. Dynamic OpenID Providers MUST support the code, id_token, and the id_token token Response Type values.
	ResponseTypesSupported []string `json:"response_types_supported"`

	// OPTIONAL. JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports, as specified in OAuth 2.0 Multiple Response Type Encoding Practices [OAuth.Responses]. If omitted, the default for Dynamic OpenID Providers is ["query", "fragment"].
	ResponseModesSupported []string `json:"response_modes_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports. Dynamic OpenID Providers MUST support the authorization_code and implicit Grant Type values and MAY support other Grant Types. If omitted, the default value is ["authorization_code", "implicit"].
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the Authentication Context Class References that this OP supports.
	ACRValuesSupported []string `json:"acr_values_supported,omitempty"`

	// REQUIRED. JSON array containing a list of the Subject Identifier types that this OP supports. Valid types include pairwise and public.
	SubjectTypesSupported []string `json:"subject_types_supported"`

	// REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT]. The algorithm RS256 MUST be included. The value none MAY be supported but MUST NOT be used unless the Response Type used returns no ID Token from the Authorization Endpoint (such as when using the Authorization Code Flow).
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT].
	IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT].
	IDTokenEncryptionEncvaluesSupported []string `json:"id_token_encryption_enc_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the JWS [JWS] signing algorithms (alg values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT]. The value none MAY be included.
	UserinfoSigningAlgValuesSupported []string `json:"userinfo_signing_alg_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the JWE [JWE] encryption algorithms (alg values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
	UserinfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
	UserinfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for Request Objects, which are described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core]. These algorithms are used both when the Request Object is passed by value (using the request parameter) and when it is passed by reference (using the request_uri parameter). Servers SHOULD support none and RS256.
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported"`

	// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for Request Objects. These algorithms are used both when the Request Object is passed by value and when it is passed by reference.
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for Request Objects. These algorithms are used both when the Request Object is passed by value and when it is passed by reference.
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of Client Authentication methods supported by this Token Endpoint. The options are client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt, as described in Section 9 of OpenID Connect Core 1.0 [OpenID.Core]. Other authentication methods MAY be defined by extensions. If omitted, the default is client_secret_basic -- the HTTP Basic Authentication Scheme specified in Section 2.3.1 of OAuth 2.0 [RFC6749].
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the Token Endpoint for the signature on the JWT [JWT] used to authenticate the Client at the Token Endpoint for the private_key_jwt and client_secret_jwt authentication methods. Servers SHOULD support RS256. The value none MUST NOT be used.
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	// OPTIONAL. JSON array containing a list of the display parameter values that the OpenID Provider supports. These values are described in Section 3.1.2.1 of OpenID Connect Core 1.0 [OpenID.Core].
	DisplayValuesSupported []string `json:"display_values_supported"`

	// OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports. These Claim Types are described in Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core]. Values defined by this specification are normal, aggregated, and distributed. If omitted, the implementation supports only normal Claims.
	ClaimTypesSupported []string `json:"claim_types_supported,omitempty"`

	// RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for. Note that for privacy or other reasons, this might not be an exhaustive list.
	ClaimsSupported []string `json:"claims_supported"`

	// OPTIONAL. URL of a page containing human-readable information that developers might want or need to know when using the OpenID Provider. In particular, if the OpenID Provider does not support Dynamic Client Registration, then information on how to register Clients needs to be provided in this documentation.
	ServiceDocumentation string `json:"service_documentation,omitempty"`

	// OPTIONAL. Languages and scripts supported for values in Claims being returned, represented as a JSON array of BCP47 [RFC5646] language tag values. Not all languages and scripts are necessarily supported for all Claim values.
	ClaimsLocalesSupported []string `json:"claims_locales_supported,omitempty"`

	// OPTIONAL. Languages and scripts supported for the user interface, represented as a JSON array of BCP47 [RFC5646] language tag values.
	UILocalesSupported []string `json:"ui_locales_supported,omitempty"`

	// OPTIONAL. Boolean value specifying whether the OP supports use of the claims parameter, with true indicating support. If omitted, the default value is false.
	ClaimsParameterSupported bool `json:"claims_parameter_supported,omitempty"`

	// OPTIONAL. Boolean value specifying whether the OP supports use of the request parameter, with true indicating support. If omitted, the default value is false.
	RequestParameterSupported bool `json:"request_parameter_supported,omitempty"`

	// OPTIONAL. Boolean value specifying whether the OP supports use of the request_uri parameter, with true indicating support. If omitted, the default value is true.
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported,omitempty"`

	// OPTIONAL. Boolean value specifying whether the OP requires any request_uri values used to be pre-registered using the request_uris registration parameter. Pre-registration is REQUIRED when the value is true. If omitted, the default value is false.
	RequireRequestURIRegistration bool `json:"require_request_uri_registration,omitempty"`

	// OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about the OP's requirements on how the Relying Party can use the data provided by the OP. The registration process SHOULD display this URL to the person registering the Client if it is given.
	OPPolicyURI string `json:"op_policy_uri,omitempty"`

	// OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about the OpenID Provider's terms of service. The registration process SHOULD display this URL to the person registering the Client if it is given.
	OPTermsOfServiceURI string `json:"op_tos_uri,omitempty"`
}

func (c ProviderMetadata) Valid() error {
	var err error

	if c.Issuer == "" {
		err = errors.Join(errors.New("issuer is required"), err)
	}

	if c.AuthorizationEndpoint == "" {
		err = errors.Join(errors.New("authorization_endpoint is required"), err)
	}

	if c.TokenEndpoint == "" {
		err = errors.Join(errors.New("token_endpoint is required"), err)
	}

	// RECOMMENDED: UserinfoEndpoint

	if c.JWKSURI == "" {
		err = errors.Join(errors.New("jwks_uri is required"), err)
	}

	// RECOMMENDED: RegistrationEndpoint

	// RECOMMENDED: ScopesSupported

	if len(c.ResponseTypesSupported) == 0 {
		err = errors.Join(errors.New("response_types_supported is required"), err)
	}

	// REQUIRED. JSON array containing a list of the Subject Identifier types that this OP supports. Valid types include pairwise and public.
	if len(c.SubjectTypesSupported) == 0 {
		err = errors.Join(errors.New("subject_types_supported is required"), err)
	}

	// REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT]. The algorithm RS256 MUST be included. The value none MAY be supported but MUST NOT be used unless the Response Type used returns no ID Token from the Authorization Endpoint (such as when using the Authorization Code Flow).
	if len(c.IDTokenSigningAlgValuesSupported) == 0 {
		err = errors.Join(errors.New("id_token_signing_alg_values_supported"), err)
	}

	// RECOMMENDED: ClaimsSupported

	return err
}

func fetchProviderMetadata(ctx context.Context, cfguri string) (*ProviderMetadata, error) {
	pmmux.RLock()
	v, ok := cacheProviderMeta[cfguri]
	pmmux.RUnlock()

	if ok {
		return &v, nil
	}

	pmmux.Lock()
	defer pmmux.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfguri, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid uri (%s): %w", cfguri, err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", cfguri, err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http get %s: stauts=%d", cfguri, res.StatusCode)
	}

	var cfg ProviderMetadata

	if err := json.NewDecoder(res.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode configuration json: %w", err)
	}

	if err := cfg.Valid(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	cacheProviderMeta[cfguri] = cfg

	return &cfg, nil
}
