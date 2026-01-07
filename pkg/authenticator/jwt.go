package authenticator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"unsafe"

	"github.com/everettraven/oidc-external-sources-webhook/pkg/internal/thirdparty/kubernetes/apiserver/pkg/apis/apiserver"
	apiserverv1 "github.com/everettraven/oidc-external-sources-webhook/pkg/internal/thirdparty/kubernetes/apiserver/pkg/apis/apiserver/v1"
	"github.com/everettraven/oidc-external-sources-webhook/pkg/internal/thirdparty/kubernetes/apiserver/plugin/pkg/authenticator/token/oidc"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

func NewJWT() *JWT {
	return &JWT{}
}

type JWT struct {
	configFile string
	delegate   authenticator.Token
}

func (j *JWT) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&j.configFile, "config", "", "configure the JWT authenticator")
}

func (j *JWT) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	return j.delegate.AuthenticateToken(ctx, token)
}

func (j *JWT) Run(ctx context.Context) error {
	if j.configFile == "" {
		return fmt.Errorf("configuration file must be specified for jwt authentication")
	}

	// TODO: hot-reload of configuration. For now, just load once on startup.
	configBytes, err := os.ReadFile(j.configFile)
	if err != nil {
		return fmt.Errorf("reading configuration file: %w", err)
	}

	// TODO: Use AuthenticationConfiguration type instead.
	config := &apiserverv1.JWTAuthenticator{}
	// TODO: unmarshal from YAML
	err = json.Unmarshal(configBytes, config)
	if err != nil {
		return fmt.Errorf("unmarshalling configuration: %w", err)
	}

	out := &apiserver.JWTAuthenticator{}

	err = Convert_v1_JWTAuthenticator_To_apiserver_JWTAuthenticator(config, out)
	if err != nil {
		return fmt.Errorf("converting: %w", err)
	}

	tokenAuthenticator, err := oidc.New(ctx, oidc.Options{
		JWTAuthenticator: *out,
	})
	if err != nil {
		return fmt.Errorf("creating token authenticator: %w", err)
	}

	j.delegate = tokenAuthenticator

	return nil
}

func Convert_v1_JWTAuthenticator_To_apiserver_JWTAuthenticator(in *apiserverv1.JWTAuthenticator, out *apiserver.JWTAuthenticator) error {
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

func Convert_v1_ClaimMappings_To_apiserver_ClaimMappings(in *apiserverv1.ClaimMappings, out *apiserver.ClaimMappings) error {
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

func Convert_v1_PrefixedClaimOrExpression_To_apiserver_PrefixedClaimOrExpression(in *apiserverv1.PrefixedClaimOrExpression, out *apiserver.PrefixedClaimOrExpression) error {
	out.Claim = in.Claim
	out.Prefix = (*string)(unsafe.Pointer(in.Prefix))
	out.Expression = in.Expression
	return nil
}

func Convert_v1_ClaimOrExpression_To_apiserver_ClaimOrExpression(in *apiserverv1.ClaimOrExpression, out *apiserver.ClaimOrExpression) error {
	out.Claim = in.Claim
	out.Expression = in.Expression
	return nil
}

func Convert_v1_Issuer_To_apiserver_Issuer(in *apiserverv1.Issuer, out *apiserver.Issuer) error {
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
