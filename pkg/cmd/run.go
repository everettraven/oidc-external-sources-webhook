package cmd

import (
	"log"

	"github.com/everettraven/oidc-external-sources-webhook/pkg/authenticator/jwt"
	"github.com/everettraven/oidc-external-sources-webhook/pkg/server"
	"github.com/spf13/cobra"
)

func NewRunCommand() *cobra.Command {
	authn := jwt.New()
	srv := server.New(authn)

	cmd := &cobra.Command{
		Use: "run",
		RunE: func(cmd *cobra.Command, args []string) error {
			go func() {
				err := authn.Run(cmd.Context())
				if err != nil {
					log.Fatalf("jwt.Run error: %v", err)
				}
			}()

			return srv.Serve()
		},
	}

	srv.AddFlags(cmd.Flags())
	authn.AddFlags(cmd.Flags())

	return cmd
}
