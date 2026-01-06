package cmd

import "github.com/spf13/cobra"

func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "oidc-external-sources-webhook",
	}

	cmd.AddCommand(NewRunCommand())

	return cmd
}
