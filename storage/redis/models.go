package redis

import (
	"connectivly/storage"
	"strings"
)

type OAuthRequest struct {
	ID           string `redis:"id"`
	Expires      int64  `redis:"expires"`
	Code         string `redis:"code"`
	Approved     bool   `redis:"approved"`
	UserID       string `redis:"user_id"`
	State        string `redis:"state"`
	ClientID     string `redis:"client_id"`
	RedirectURI  string `redis:"redirect_uri"`
	Scope        string `redis:"scope"`
	ResponseType string `redis:"response_type"`
	Nonce        string `redis:"nonce"`
	Prompt       string `redis:"prompt"`
	MaxAge       string `redis:"max_age"`
}

func (o OAuthRequest) toStorageOAuthRequest() storage.OAuthRequest {
	return storage.OAuthRequest(o)
}

type StoredOAuthToken struct {
	HashedAccessToken   string `redis:"hashed_access_token"`
	AccessTokenExpires  int64  `redis:"access_token_expires"`
	HashedRefreshToken  string `redis:"hashed_refresh_token"`
	RefreshTokenExpires int64  `redis:"refresh_token_expires"`
	TokenType           string `redis:"token_type"`
	Scopes              string `redis:"scopes"`
	UserID              string `redis:"user_id"`
}

func (o StoredOAuthToken) toStorageOAuthToken() storage.StoredOAuthToken {
	return storage.StoredOAuthToken{
		HashedAccessToken:   o.HashedAccessToken,
		AccessTokenExpires:  o.AccessTokenExpires,
		HashedRefreshToken:  o.HashedRefreshToken,
		RefreshTokenExpires: o.RefreshTokenExpires,
		TokenType:           o.TokenType,
		Scopes:              strings.Split(o.Scopes, " "),
		UserID:              o.UserID,
	}
}

type App struct {
	ID           uint   `redis:"id"`
	Name         string `redis:"name"`
	ClientID     string `redis:"client_id"`
	ClientSecret string `redis:"client_secret"`
	OwnerID      string `redis:"owner_id"`
}
