package api

import (
	"errors"
	"net/http"
)

var (
	CC98APIURL    = "https://api.cc98.org"
	CC98OpenIDURL = "https://openid.cc98.org"
)

type Token struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

type CC98 struct {
	token    *Token
	username string
	password string
	client   *http.Client
}

func NewCC98(username, password string) (*CC98, error) {
	return &CC98{
		username: username,
		password: password,
		client:   &http.Client{},
	}, nil
}

func (c *CC98) Token() (*Token, error) {
	if c == nil || c.token == nil {
		return nil, errors.New("尚未登录，token 不可用")
	}
	return c.token, nil
}
