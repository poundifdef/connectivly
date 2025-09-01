package sqlite

import (
	"connectivly/storage"
	"strings"

	"gorm.io/gorm"
)

type KeyValue struct {
	gorm.Model
	Key   string `gorm:"unique"`
	Value string
}

type OAuthRequest struct {
	ID           string
	Expires      int64
	Code         string
	Approved     bool
	UserID       string
	State        string
	ClientID     string
	RedirectURI  string
	Scope        string
	ResponseType string
	Nonce        string
	Prompt       string
	MaxAge       string
}

func (o OAuthRequest) toStorageOAuthRequest() storage.OAuthRequest {
	return storage.OAuthRequest(o)
}

type StoredOAuthToken struct {
	HashedAccessToken   string
	AccessTokenExpires  int64
	HashedRefreshToken  string
	RefreshTokenExpires int64
	TokenType           string
	Scopes              string
	UserID              string
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
	gorm.Model
	Name         string
	ClientID     string
	ClientSecret string
	OwnerID      string
	RedirectURI  string
}
