package authenticator

import (
	"context"
	"fmt"

	"k8s.io/apiserver/pkg/authentication/authenticator"
)

func NewSimple() *Simple {
	return &Simple{
		tokenToUserInfo: map[string]*userInfo{
			"blah": {
				username: "bpalmer",
				groups: []string{
					"admin",
					"developer",
					"team-corgi",
				},
				uid: "19",
				extra: map[string][]string{
					"thing.openshift.io/something": {"value"},
				},
			},
		},
	}
}

type userInfo struct {
	username string
	groups []string
	uid string
	extra map[string][]string
}

func (ui *userInfo) GetName() string {
	return ui.username
}

func (ui *userInfo) GetGroups() []string {
	return ui.groups
}

func (ui *userInfo) GetUID() string {
	return ui.uid
}

func (ui *userInfo) GetExtra() map[string][]string {
	return ui.extra
}

type Simple struct {
	tokenToUserInfo map[string]*userInfo
}

func (s *Simple) AuthenticateToken(_ context.Context, token string) (*authenticator.Response, bool, error) {
	val, ok := s.tokenToUserInfo[token]
	if !ok {
		return nil, false, fmt.Errorf("unknown token")
	}

	return &authenticator.Response{
		User: val,
	}, true, nil
}
