package main

import (
	"log"

	"github.com/everettraven/oidc-external-sources-webhook/pkg/cmd"
)

func main() {
	if err := cmd.NewRootCommand().Execute(); err != nil {
		log.Fatal(err)
	}
}
