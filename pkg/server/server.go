package server

import (
	"net/http"

	"github.com/everettraven/oidc-external-sources-webhook/pkg/authenticator"
	"github.com/everettraven/oidc-external-sources-webhook/pkg/handlers"
	"github.com/spf13/pflag"
)

func New() *Instance {
	return &Instance{}
}

type Instance struct {
	Addr string
}

func (i *Instance) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&i.Addr, "addr", "0.0.0.0:8080", "specifies the address in which the server should listen for incoming requests")
}

func (i *Instance) Serve() error {
	mux := http.NewServeMux()

	mux.Handle("/authenticate", handlers.NewAuthenticate(authenticator.NewSimple()))

	return http.ListenAndServe(i.Addr, mux)
}
