package server

import (
	"net/http"

	"github.com/everettraven/oidc-external-sources-webhook/pkg/handlers"
	"github.com/spf13/pflag"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

func New(at authenticator.Token) *Instance {
	return &Instance{
		tokenAuthenticator: at,
	}
}

type Instance struct {
	addr               string
	tokenAuthenticator authenticator.Token
}

func (i *Instance) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&i.addr, "addr", "0.0.0.0:8080", "specifies the address in which the server should listen for incoming requests")
}

func (i *Instance) Serve() error {
	mux := http.NewServeMux()

	mux.Handle("/authenticate", handlers.NewAuthenticate(i.tokenAuthenticator))

	return http.ListenAndServe(i.addr, mux)
}
