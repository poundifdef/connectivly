package storage

import (
	"context"
	"crypto/rsa"
	"strings"
)

type OAuthParams struct {
	ProviderRedirectURL string
}

type AuthSession struct {
	ID     string   `json:"id" redis:"id"`
	App    App      `json:"app" redis:"id"`
	Scopes []string `json:"scopes" redis:"id"`
}

type Scope struct {
	ID          string `json:"id" redis:"id"`
	Name        string `json:"name" redis:"name"`
	Description string `json:"description" redis:"description"`
}

type Provider interface {
	Name(ctx context.Context) string
	Logo(ctx context.Context) []byte
	Scopes(ctx context.Context) []Scope
}

type App struct {
	ID           uint     `json:"id"`
	Name         string   `json:"name"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURI  []string `json:"redirect_uri"`
	OwnerID      string   `json:"-"`
}

type OAuthRequest struct {
	ID           string `redis:"id"`
	Expires      int64  `redis:"expires"`
	Code         string `redis:"code"`
	Approved     bool   `redis:"approved"`
	UserID       string `redis:"user_id"`
	State        string `query:"state" redis:"state"`
	ClientID     string `query:"client_id" redis:"client_id"` // Required
	RedirectURI  string `query:"redirect_uri" redis:"redirect_uri"`
	Scope        string `query:"scope" redis:"scope"`                 // Required for oidc
	ResponseType string `query:"response_type" redis:"response_type"` // Required
	Nonce        string `query:"nonce,omitempty" redis:"nonce"`
	Prompt       string `query:"prompt,omitempty" redis:"prompt"`
	MaxAge       string `query:"max_age,omitempty" redis:"max_age"`
}

func (o OAuthRequest) Scopes() []string {
	return strings.Split(o.Scope, " ")
}

type TokenRequest struct {
	GrantType    string `form:"grant_type"`
	RedirectURI  string `form:"redirect_uri"`
	Code         string `form:"code"`
	RefreshToken string `form:"refresh_token"`
	ClientID     string `form:"client_id"`
	ClientSecret string `form:"client_secret"`
}

type OAuthToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	State        string `json:"state,omitempty"`
	Scope        string `json:"scope"`
	UserID       string `json:"userid"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

func (o OAuthToken) Scopes() []string {
	return strings.Split(o.Scope, " ")
}

type StoredOAuthToken struct {
	HashedAccessToken   string   `json:"access_token"`
	AccessTokenExpires  int64    `json:"access_token_expires"`
	HashedRefreshToken  string   `json:"refresh_token"`
	RefreshTokenExpires int64    `json:"refresh_token_expires"`
	TokenType           string   `json:"token_type"`
	Scopes              []string `json:"scopes"`
	UserID              string   `json:"userid"`
}

type Storage interface {
	GenerateRandomString(length uint) string
	Hash(input string) string
	GetProvider(ctx context.Context) Provider
	GetApp(ctx context.Context, clientid string) App
	CreateApp(ctx context.Context, app App) (App, error)
	GetAuthRequestByCode(ctx context.Context, code string) OAuthRequest
	GetAuthRequest(ctx context.Context, id string, approvalRequired bool) OAuthRequest
	ApproveAuthRequest(ctx context.Context, id string, user_id string) error
	DeleteAuthRequest(ctx context.Context, id string)
	ValidateAPIKey(ctx context.Context, api_key string) bool
	GetOAuthProviderParams(ctx context.Context) OAuthParams
	SaveOAuthRequest(ctx context.Context, token string, request OAuthRequest) error
	SaveOAuthToken(ctx context.Context, token StoredOAuthToken) error
	GetOAuthTokenByHashedAccessToken(ctx context.Context, token string) StoredOAuthToken
	GetOAuthTokenByHashedRefreshToken(ctx context.Context, token string) StoredOAuthToken
	InvalidateOAuthTokenByHashedAccessToken(ctx context.Context, token string) error
	GetRSAPublicKey(ctx context.Context) (*rsa.PublicKey, string, error)
	GetRSAPrivateKey(ctx context.Context) (*rsa.PrivateKey, string, error)
}
