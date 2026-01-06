package cmd

import (
	"github.com/everettraven/oidc-external-sources-webhook/pkg/server"
	"github.com/spf13/cobra"
)

func NewRunCommand() *cobra.Command {
	srv := server.New()

	cmd := &cobra.Command{
		Use: "run",
		RunE: func(cmd *cobra.Command, args []string) error {
			return srv.Serve()
		},
	}

	srv.AddFlags(cmd.Flags())

	return cmd
}
