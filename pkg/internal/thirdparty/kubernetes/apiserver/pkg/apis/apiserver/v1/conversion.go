// TODO: Should wire up conversion-gen to automatically create conversion methods instead of hand-writing
// new conversions
package v1

import (
	"fmt"
	"unsafe"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/everettraven/oidc-external-sources-webhook/pkg/internal/thirdparty/kubernetes/apiserver/pkg/apis/apiserver"
)

func Convert_v1_AuthenticationConfiguration_To_apiserver_AuthenticationConfiguration(in *AuthenticationConfiguration, out *apiserver.AuthenticationConfiguration) error {
	if in.JWT != nil {
		in, out := &in.JWT, &out.JWT
		*out = make([]apiserver.JWTAuthenticator, len(*in))
		for i := range *in {
			if err := Convert_v1_JWTAuthenticator_To_apiserver_JWTAuthenticator(&(*in)[i], &(*out)[i]); err != nil {
				return err
			}
		}
	} else {
		out.JWT = nil
	}
	return nil
}

func Convert_v1_JWTAuthenticator_To_apiserver_JWTAuthenticator(in *JWTAuthenticator, out *apiserver.JWTAuthenticator) error {
	err := Convert_v1_Issuer_To_apiserver_Issuer(&in.Issuer, &out.Issuer)
	if err != nil {
		return fmt.Errorf("converting issuer: %w", err)
	}

	err = Convert_v1_ClaimMappings_To_apiserver_ClaimMappings(&in.ClaimMappings, &out.ClaimMappings)
	if err != nil {
		return fmt.Errorf("converting claim mappings: %w", err)
	}

	out.ClaimValidationRules = *(*[]apiserver.ClaimValidationRule)(unsafe.Pointer(&in.ClaimValidationRules))
	out.UserValidationRules = *(*[]apiserver.UserValidationRule)(unsafe.Pointer(&in.UserValidationRules))

	outECS := []apiserver.ExternalClaimsSource{}
	for _, inEC := range in.ExternalClaimsSources {
		outEC := &apiserver.ExternalClaimsSource{}
		err := Convert_v1_ExternalClaimsSource_To_apiserver_ExternalClaimsSource(&inEC, outEC)
		if err != nil {
			return fmt.Errorf("converting external claims source: %w", err)
		}
		outECS = append(outECS, *outEC)
	}

	out.ExternalClaimsSources = outECS

	return nil
}

func Convert_v1_ClaimMappings_To_apiserver_ClaimMappings(in *ClaimMappings, out *apiserver.ClaimMappings) error {
	if err := Convert_v1_PrefixedClaimOrExpression_To_apiserver_PrefixedClaimOrExpression(&in.Username, &out.Username); err != nil {
		return err
	}
	if err := Convert_v1_PrefixedClaimOrExpression_To_apiserver_PrefixedClaimOrExpression(&in.Groups, &out.Groups); err != nil {
		return err
	}
	if err := Convert_v1_ClaimOrExpression_To_apiserver_ClaimOrExpression(&in.UID, &out.UID); err != nil {
		return err
	}
	out.Extra = *(*[]apiserver.ExtraMapping)(unsafe.Pointer(&in.Extra))
	return nil
}

func Convert_v1_PrefixedClaimOrExpression_To_apiserver_PrefixedClaimOrExpression(in *PrefixedClaimOrExpression, out *apiserver.PrefixedClaimOrExpression) error {
	out.Claim = in.Claim
	out.Prefix = (*string)(unsafe.Pointer(in.Prefix))
	out.Expression = in.Expression
	return nil
}

func Convert_v1_ClaimOrExpression_To_apiserver_ClaimOrExpression(in *ClaimOrExpression, out *apiserver.ClaimOrExpression) error {
	out.Claim = in.Claim
	out.Expression = in.Expression
	return nil
}

func Convert_v1_Issuer_To_apiserver_Issuer(in *Issuer, out *apiserver.Issuer) error {
	out.URL = in.URL
	if err := metav1.Convert_Pointer_string_To_string(&in.DiscoveryURL, &out.DiscoveryURL, nil); err != nil {
		return err
	}
	out.CertificateAuthority = in.CertificateAuthority
	out.Audiences = *(*[]string)(unsafe.Pointer(&in.Audiences))
	out.AudienceMatchPolicy = apiserver.AudienceMatchPolicyType(in.AudienceMatchPolicy)
	return nil
}

func Convert_v1_ExternalClaimsSource_To_apiserver_ExternalClaimsSource(in *ExternalClaimsSource, out *apiserver.ExternalClaimsSource) error {
	if in == nil {
		in = &ExternalClaimsSource{}
	}
	if out == nil {
		out = &apiserver.ExternalClaimsSource{}
	}
	if err := Convert_v1_Authentication_To_apiserver_Authentication(in.Authentication, out.Authentication); err != nil {
		return err
	}

	if err := Convert_v1_TLS_To_apiserver_TLS(in.TLS, out.TLS); err != nil {
		return err
	}

	if err := Convert_v1_SourceURL_To_apiserver_SourceURL(in.URL, out.URL); err != nil {
		return err
	}

	out.Mappings = *(*[]apiserver.SourcedClaimMapping)(unsafe.Pointer(&in.Mappings))
	out.Conditions = *(*[]apiserver.ExternalSourceCondition)(unsafe.Pointer(&in.Conditions))

	return nil
}

func Convert_v1_SourceURL_To_apiserver_SourceURL(in *SourceURL, out *apiserver.SourceURL) error {
	if out == nil {
		out = &apiserver.SourceURL{}
	}

	if in == nil {
		return nil
	}

	out.Hostname = in.Hostname
	out.PathExpression = in.PathExpression
	return nil
}

func Convert_v1_Authentication_To_apiserver_Authentication(in *Authentication, out *apiserver.Authentication) error {
	if out == nil {
		out = &apiserver.Authentication{}
	}

	// defaulting?
	if in == nil {
		out.Type = apiserver.AuthenticationTypeRequestProvidedToken
		return nil
	}

	out.Type = apiserver.AuthenticationType(in.Type)
	return nil
}

func Convert_v1_TLS_To_apiserver_TLS(in *TLS, out *apiserver.TLS) error {
	out.CA = in.CA
	return nil
}

