package storage

import (
	"crypto/rsa"
	"strings"
)

type OAuthParams struct {
	ProviderRedirectURL string
}

type AuthSession struct {
	ID     string   `json:"id"`
	App    App      `json:"app"`
	Scopes []string `json:"scopes"`
}

type Scope struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type Provider interface {
	Name() string
	Logo() []byte
	Scopes() []Scope
}

type App struct {
	ID           uint     `json:"id"`
	Name         string   `json:"name"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"-"`
	RedirectURI  []string `json:"redirect_uri"`
	OwnerID      string   `json:"-"`
}

type OAuthRequest struct {
	ID           string
	Expires      int64
	Code         string
	Approved     bool
	UserID       string
	State        string `query:"state"`
	ClientID     string `query:"client_id"` // Required
	RedirectURI  string `query:"redirect_uri"`
	Scope        string `query:"scope"`         // Required for oidc
	ResponseType string `query:"response_type"` // Required
	Nonce        string `query:"nonce,omitempty"`
	Prompt       string `query:"prompt,omitempty"`
	MaxAge       string `query:"max_age,omitempty"`
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
	GetProvider() Provider
	GetApp(clientid string) App
	CreateApp(app App) (App, error)
	GetAuthRequestByCode(code string) OAuthRequest
	GetAuthRequest(id string, approvalRequired bool) OAuthRequest
	ApproveAuthRequest(id string, user_id string) error
	DeleteAuthRequest(id string)
	ValidateAPIKey(api_key string) bool
	GetOAuthProviderParams() OAuthParams
	SaveOAuthRequest(token string, request OAuthRequest) error
	SaveOAuthToken(token StoredOAuthToken) error
	GetOAuthTokenByHashedAccessToken(token string) StoredOAuthToken
	GetOAuthTokenByHashedRefreshToken(token string) StoredOAuthToken
	InvalidateOAuthTokenByHashedAccessToken(token string) error
	GetRSAPublicKey() (*rsa.PublicKey, string, error)
	GetRSAPrivateKey() (*rsa.PrivateKey, string, error)
}
