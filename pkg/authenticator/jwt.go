package authenticator

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/everettraven/oidc-external-sources-webhook/pkg/internal/thirdparty/kubernetes/apiserver/pkg/apis/apiserver"
	apiserverv1 "github.com/everettraven/oidc-external-sources-webhook/pkg/internal/thirdparty/kubernetes/apiserver/pkg/apis/apiserver/v1"
	"github.com/everettraven/oidc-external-sources-webhook/pkg/internal/thirdparty/kubernetes/apiserver/pkg/apis/apiserver/validation"
	"github.com/everettraven/oidc-external-sources-webhook/pkg/internal/thirdparty/kubernetes/apiserver/plugin/pkg/authenticator/token/oidc"
	"github.com/spf13/pflag"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/token/union"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/kubernetes/pkg/util/filesystem"
	"sigs.k8s.io/yaml"

	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
)

func NewJWT() *JWT {
	return &JWT{}
}

type JWT struct {
	configFile string
	delegate   authenticator.Token
	cancel     context.CancelFunc
}

func (j *JWT) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&j.configFile, "config", "", "configure the JWT authenticator")
}

func (j *JWT) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	return j.delegate.AuthenticateToken(ctx, token)
}

func (j *JWT) Run(ctx context.Context) error {
	// validations
	if j.configFile == "" {
		return fmt.Errorf("configuration file must be specified for jwt authentication")
	}

	// initial setup
	if err := j.SetDelegateFromConfigFile(ctx); err != nil {
		return fmt.Errorf("configuring token authenticator: %w", err)
	}

	go filesystem.WatchUntil(ctx, time.Minute, j.configFile, func() {
		err := j.SetDelegateFromConfigFile(ctx)
		if err != nil {
			fmt.Println("error reloading configuration", err)
		}
	}, func(err error) {
		if err != nil {
			fmt.Println("error watching configuration", err)
		}
	})

	return nil
}

func (j *JWT) SetDelegateFromConfigFile(ctx context.Context) error {
	authnConfig, err := AuthenticationConfigurationFromConfigurationFile(j.configFile)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	out := &apiserver.AuthenticationConfiguration{}

	err = apiserverv1.Convert_v1_AuthenticationConfiguration_To_apiserver_AuthenticationConfiguration(authnConfig, out)
	if err != nil {
		return fmt.Errorf("converting external representation to internal representation: %w", err)
	}

	compiler := authenticationcel.NewDefaultCompiler()
	fieldErrs := validation.ValidateAuthenticationConfiguration(compiler, out, nil)
	if err := fieldErrs.ToAggregate(); err != nil {
		return fmt.Errorf("validating authentication configuration: %w", err)
	}

	wrappedCtx, cancel := context.WithCancel(ctx)
	tokenAuthenticator, err := TokenAuthenticatorForAuthenticationConfiguration(wrappedCtx, out)
	if err != nil {
		defer cancel()
		return fmt.Errorf("creating token authenticator: %w", err)
	}


	if j.delegate != nil {
		j.cancel()
	}

	j.cancel = cancel
	j.delegate = tokenAuthenticator

	return nil
}

func AuthenticationConfigurationFromConfigurationFile(cfgPath string) (*apiserverv1.AuthenticationConfiguration, error) {
	configBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("reading configuration file: %w", err)
	}

	config := &apiserverv1.AuthenticationConfiguration{}
	err = yaml.Unmarshal(configBytes, config)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling configuration: %w", err)
	}

	return config, nil
}

func TokenAuthenticatorForAuthenticationConfiguration(ctx context.Context, cfg *apiserver.AuthenticationConfiguration) (authenticator.Token, error) {
	jwtAuthenticators := []authenticator.Token{}

	for _, jwt := range cfg.JWT {
		caContentProvider, err := dynamiccertificates.NewStaticCAContent("oidc-authenticator", []byte(jwt.Issuer.CertificateAuthority))
		if err != nil {
			return nil, fmt.Errorf("creating CA content provider: %w", err)
		}

		tokenAuthenticator, err := oidc.New(ctx, oidc.Options{
			JWTAuthenticator:  jwt,
			CAContentProvider: caContentProvider,
		})
		if err != nil {
			return nil, fmt.Errorf("creating token authenticator: %w", err)
		}

		jwtAuthenticators = append(jwtAuthenticators, tokenAuthenticator)
	}

	return union.New(jwtAuthenticators...), nil
}
