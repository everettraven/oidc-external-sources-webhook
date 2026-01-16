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
	out.EgressSelectorType = apiserver.EgressSelectorType(in.EgressSelectorType)
	return nil
}
