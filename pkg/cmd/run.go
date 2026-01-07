package cmd

import (
	"log"

	"github.com/everettraven/oidc-external-sources-webhook/pkg/authenticator"
	"github.com/everettraven/oidc-external-sources-webhook/pkg/server"
	"github.com/spf13/cobra"
)

func NewRunCommand() *cobra.Command {
	jwt := authenticator.NewJWT()
	srv := server.New(jwt)

	cmd := &cobra.Command{
		Use: "run",
		RunE: func(cmd *cobra.Command, args []string) error {
			go func() {
				err := jwt.Run(cmd.Context())
				if err != nil {
					log.Println("jwt.Run error", err)
				}
			}()

			return srv.Serve()
		},
	}

	srv.AddFlags(cmd.Flags())
	jwt.AddFlags(cmd.Flags())

	return cmd
}
