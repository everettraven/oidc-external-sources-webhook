package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"

	"golang.org/x/oauth2"
)

func NewOAuthCommand() *cobra.Command {
	var clientID string
	var clientSecret string
	var issuer string
	cmd := &cobra.Command{
		Use: "oauth",
		RunE: func(cmd *cobra.Command, args []string) error {
			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}

			specialCtx := context.WithValue(cmd.Context(), oauth2.HTTPClient, httpClient)

			provider, err := oidc.NewProvider(specialCtx, issuer)
			if err != nil {
				return fmt.Errorf("creating provider: %w", err)
			}

			fmt.Println(provider.Endpoint().DeviceAuthURL)

			conf := &oauth2.Config{
				Endpoint: oauth2.Endpoint{
					TokenURL:      provider.Endpoint().TokenURL,
					AuthURL:       provider.Endpoint().AuthURL,
					DeviceAuthURL: provider.Endpoint().DeviceAuthURL,
				},

				ClientID:     clientID,
				ClientSecret: clientSecret,

				// "openid" is a required scope for OpenID Connect flows.
				Scopes: []string{oidc.ScopeOpenID, "email", "profile"},
			}

			// Redirect user to consent page to ask for permission
			// for the scopes specified above.
			resp, err := conf.DeviceAuth(specialCtx)
			if err != nil {
				return fmt.Errorf("device auth: %w", err)
			}
			fmt.Println("User Code", resp.UserCode)
			fmt.Println("Verification URI", resp.VerificationURI)

			tok, err := conf.DeviceAccessToken(specialCtx, resp)
			if err != nil {
				fmt.Println("error in exchange, continuing... err: %w", err)
			}

			fmt.Println(tok.AccessToken)
			return nil
		},
	}

	cmd.Flags().StringVar(&clientID, "client-id", "", "client id")
	cmd.Flags().StringVar(&clientSecret, "client-secret", "", "client secret")
	cmd.Flags().StringVar(&issuer, "issuer", "", "issuer")

	return cmd
}
