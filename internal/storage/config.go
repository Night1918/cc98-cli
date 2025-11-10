package storage

import "time"

type Config struct {
	DefaultAccount string                   `json:"default_account,omitempty"`
	Accounts       map[string]AccountConfig `json:"accounts"`
	Master         *MasterInfo              `json:"master,omitempty"`
}

type AccountConfig struct {
	TokenFile   string `json:"token_file"`
	DisplayName string `json:"display_name,omitempty"`
	LastUpdated string `json:"last_updated,omitempty"`
}

type TokenRecord struct {
	AccessToken           string `json:"access_token"`
	RefreshToken          string `json:"refresh_token"`
	TokenType             string `json:"token_type"`
	Scope                 string `json:"scope"`
	AccessTokenExpiresAt  int64  `json:"access_token_expires_at"`
	RefreshTokenExpiresAt int64  `json:"refresh_token_expires_at"`
}

type MasterInfo struct {
	KDF       string         `json:"kdf"`
	Params    map[string]int `json:"params,omitempty"`
	Salt      string         `json:"salt"`
	Verifier  string         `json:"verifier"`
	CreatedAt time.Time      `json:"created_at"`
}

func NewConfig() Config {
	return Config{
		Accounts: make(map[string]AccountConfig),
	}
}
