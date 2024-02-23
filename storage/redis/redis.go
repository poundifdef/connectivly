package redis

import (
	"connectivly/storage"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/m1/go-generate-password/generator"
	"github.com/redis/go-redis/v9"
)

const REDIS_PREFIX = "connectivly-"
const API_KEY = REDIS_PREFIX + "api-key"
const PRIVATE_KEY = REDIS_PREFIX + "private-key"
const PRIVATE_KEY_ID = REDIS_PREFIX + "private-key-id"
const PROVIDER_NAME = REDIS_PREFIX + "provider-name"
const PROVIDER_SCOPES = REDIS_PREFIX + "provider-scopes"
const PROVIDER_REDIRECT_URL = REDIS_PREFIX + "provider-redirect-url"
const AUTH_REQUEST = REDIS_PREFIX + "auth-request-"
const AUTH_REQUEST_TOKEN = REDIS_PREFIX + "auth-request-token-"
const APP_ID_COUNTER = REDIS_PREFIX + "counter-app-id"
const SAVED_OAUTH_TOKEN_COUNTER = REDIS_PREFIX + "counter-saved-oauth-token"
const SAVED_OAUTH_TOKEN = REDIS_PREFIX + "saved-oauth-token-"
const HASHED_TOKEN = REDIS_PREFIX + "hashed-token-"
const HASHED_REFRESH = REDIS_PREFIX + "hashed-refresh-"
const APP = REDIS_PREFIX + "app-"
const CLIENT_APP = REDIS_PREFIX + "client-app-"

type RedisStorageProvider struct {
	db *redis.Client
}

func (s RedisStorageProvider) Name(ctx context.Context) string {
	return s.db.Get(ctx, PROVIDER_NAME).Val()
}

func (s RedisStorageProvider) Logo(ctx context.Context) []byte {
	return make([]byte, 0)
}

func (s RedisStorageProvider) Scopes(ctx context.Context) []storage.Scope {
	rc := make([]storage.Scope, 0)
	scopes_json := s.db.Get(ctx, PROVIDER_SCOPES).Val()
	err := json.Unmarshal([]byte(scopes_json), &rc)
	if err != nil {
		log.Println(err)
	}

	return rc
}

type RedisStorage struct {
	db       *redis.Client
	provider storage.Provider
}

func NewRedisStorage(connectionString string, providerURL string) (*RedisStorage, error) {
	ctx := context.Background()

	opt, err := redis.ParseURL(connectionString)
	if err != nil {
		return nil, err
	}
	client := redis.NewClient(opt)

	s := &RedisStorage{db: client}

	// If the DB is brand new, populate with basic information
	redirectURL := client.Get(ctx, PROVIDER_REDIRECT_URL).Val()
	needs_initialization := redirectURL == ""

	res := client.Set(ctx, PROVIDER_REDIRECT_URL, providerURL, 0)
	if res.Err() != nil {
		return nil, res.Err()
	}

	if needs_initialization {
		log.Println("Initializing new Connectivly instance on Redis")

		err := s.initializeNew(ctx)
		if err != nil {
			return nil, err
		}
	}

	s.provider = RedisStorageProvider{db: client}

	return s, nil
}

func (s *RedisStorage) initializeNew(ctx context.Context) error {
	// Generate keypair for JWTs
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}

	s.db.Set(ctx, PRIVATE_KEY, x509.MarshalPKCS1PrivateKey(key), 0)
	s.db.Set(ctx, PRIVATE_KEY_ID, "connectively-key", 0)
	s.db.Set(ctx, PROVIDER_NAME, "ACME Service", 0)

	api_key := s.GenerateRandomString(32)
	s.db.Set(ctx, API_KEY, s.Hash(api_key), 0)

	log.Println()
	log.Println("API Key: " + api_key)
	log.Println()

	s.CreateApp(ctx, storage.App{
		Name:         "Client 1 App",
		ClientID:     "client1",
		ClientSecret: s.Hash("secret1"),
	})

	log.Println("Client 1 App")
	log.Println("Client ID: client1")
	log.Println("Client Secret: secret1")
	log.Println()

	s.CreateApp(ctx, storage.App{
		Name:         "Client 2 App",
		ClientID:     "client2",
		ClientSecret: s.Hash("secret2"),
	})

	log.Println("Client 2 App")
	log.Println("Client ID: client2")
	log.Println("Client Secret: secret2")
	log.Println()

	scopes := make([]storage.Scope, 0)
	scopes = append(scopes, storage.Scope{ID: "openid", Name: "OIDC", Description: "OpenID Connect"})
	scopes_json, err := json.Marshal(&scopes)
	if err != nil {
		log.Println(err)
	}

	s.db.Set(context.Background(), PROVIDER_SCOPES, scopes_json, 0)

	return nil
}

func (s *RedisStorage) ValidateAPIKey(ctx context.Context, input string) bool {
	return s.Hash(input) == s.db.Get(ctx, API_KEY).Val()
}

func (s *RedisStorage) GetRSAPublicKey(ctx context.Context) (*rsa.PublicKey, string, error) {
	privateKeyBytes, err := s.db.Get(ctx, PRIVATE_KEY).Bytes()
	if err != nil {
		return nil, "", err
	}
	keyId := s.db.Get(ctx, PRIVATE_KEY_ID).Val()
	privateKey, _ := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	return &privateKey.PublicKey, keyId, nil
}

func (s *RedisStorage) GetRSAPrivateKey(ctx context.Context) (*rsa.PrivateKey, string, error) {
	privateKeyBytes, err := s.db.Get(ctx, PRIVATE_KEY).Bytes()
	if err != nil {
		return nil, "", err
	}
	keyId := s.db.Get(ctx, PRIVATE_KEY_ID).Val()
	privateKey, _ := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	return privateKey, keyId, nil
}

func (s *RedisStorage) GetProvider(ctx context.Context) storage.Provider {
	return s.provider
}

func (s *RedisStorage) GetOAuthProviderParams(ctx context.Context) storage.OAuthParams {
	rc := storage.OAuthParams{
		ProviderRedirectURL: s.db.Get(ctx, PROVIDER_REDIRECT_URL).Val(),
	}
	return rc
}

func (s *RedisStorage) SaveOAuthRequest(ctx context.Context, token string, request storage.OAuthRequest) error {
	// TODO: check for errors
	// TODO: make sure expiration is atomic

	requestKey := AUTH_REQUEST + token
	requestTokenKey := AUTH_REQUEST_TOKEN + request.Code

	// Set values
	s.db.HSet(ctx, requestKey, request)
	s.db.Set(ctx, requestTokenKey, requestKey, 0)

	// Set expiration for keys
	s.db.ExpireAt(ctx, requestKey, time.Unix(request.Expires, 0))
	s.db.ExpireAt(ctx, requestTokenKey, time.Unix(request.Expires, 0))

	return nil
}

func (s *RedisStorage) GetAuthRequest(ctx context.Context, id string, approvalRequired bool) storage.OAuthRequest {
	rc := OAuthRequest{}
	requestKey := AUTH_REQUEST + id

	err := s.db.HGetAll(ctx, requestKey).Scan(&rc)
	if err != nil {
		log.Println(err)
	}

	if approvalRequired && (!rc.Approved) {
		empty := OAuthRequest{}
		return empty.toStorageOAuthRequest()
	}

	return rc.toStorageOAuthRequest()
}

func (s *RedisStorage) GetAuthRequestByCode(ctx context.Context, code string) storage.OAuthRequest {
	rc := OAuthRequest{}

	requestTokenKey := AUTH_REQUEST_TOKEN + code

	requestKey := s.db.Get(ctx, requestTokenKey).Val()
	err := s.db.HGetAll(ctx, requestKey).Scan(&rc)
	if err != nil {
		log.Println(err)
	}

	return rc.toStorageOAuthRequest()
}

func (s *RedisStorage) Hash(input string) string {
	return fmt.Sprintf("%x", sha512.Sum512([]byte(input)))
}

func (s *RedisStorage) GenerateRandomString(length uint) string {
	config := generator.Config{
		IncludeSymbols:             false,
		IncludeNumbers:             true,
		IncludeLowercaseLetters:    true,
		IncludeUppercaseLetters:    true,
		ExcludeSimilarCharacters:   true,
		ExcludeAmbiguousCharacters: false,
	}
	g, _ := generator.New(&config)
	pwd, _ := g.GenerateWithLength(length)
	return *pwd
}

func (s *RedisStorage) ApproveAuthRequest(ctx context.Context, id string, user_id string) error {
	requestKey := AUTH_REQUEST + id
	res := s.db.HMSet(ctx, requestKey, "approved", true, "user_id", user_id)
	return res.Err()
}

func (s *RedisStorage) DeleteAuthRequest(ctx context.Context, id string) {
	requestKey := AUTH_REQUEST + id
	s.db.Del(ctx, requestKey)
}

func (s *RedisStorage) CreateApp(ctx context.Context, app storage.App) (storage.App, error) {
	res := s.db.Incr(ctx, APP_ID_COUNTER)
	appID, _ := res.Uint64()

	obj := App{
		ID:           uint(appID),
		Name:         app.Name,
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
	}

	appKey := fmt.Sprintf("%s%d", APP, res.Val())
	insertRes := s.db.HMSet(ctx, appKey, obj)

	storage_app := storage.App{
		ID:           obj.ID,
		Name:         obj.Name,
		ClientID:     obj.ClientID,
		ClientSecret: obj.ClientSecret,
	}

	clientAppKey := CLIENT_APP + obj.ClientID
	s.db.Set(ctx, clientAppKey, appKey, 0)

	return storage_app, insertRes.Err()
}

func (s *RedisStorage) GetApp(ctx context.Context, clientid string) storage.App {
	log.Println(clientid)
	rc := App{}

	clientAppKey := CLIENT_APP + clientid
	appKey := s.db.Get(ctx, clientAppKey).Val()

	s.db.HGetAll(ctx, appKey).Scan(&rc)

	return storage.App{
		ID:           rc.ID,
		Name:         rc.Name,
		ClientID:     rc.ClientID,
		ClientSecret: rc.ClientSecret,
	}
}

func (s *RedisStorage) SaveOAuthToken(ctx context.Context, o storage.StoredOAuthToken) error {
	obj := StoredOAuthToken{
		HashedAccessToken:   o.HashedAccessToken,
		AccessTokenExpires:  o.AccessTokenExpires,
		HashedRefreshToken:  o.HashedRefreshToken,
		RefreshTokenExpires: o.RefreshTokenExpires,
		TokenType:           o.TokenType,
		Scopes:              strings.Join(o.Scopes, " "),
		UserID:              o.UserID,
	}

	accessTokenExpires := time.Unix(obj.AccessTokenExpires, 0)
	refreshTokenExpires := time.Unix(obj.RefreshTokenExpires, 0)

	res := s.db.Incr(ctx, SAVED_OAUTH_TOKEN_COUNTER)
	tokenID := res.Val()

	tokenKey := fmt.Sprintf("%s%d", SAVED_OAUTH_TOKEN, tokenID)

	s.db.HSet(ctx, tokenKey, obj)
	s.db.ExpireAt(ctx, tokenKey, accessTokenExpires)

	s.db.Set(ctx, HASHED_TOKEN+obj.HashedAccessToken, tokenKey, 0)
	s.db.ExpireAt(ctx, HASHED_TOKEN+obj.HashedAccessToken, accessTokenExpires)

	s.db.Set(ctx, HASHED_REFRESH+obj.HashedRefreshToken, tokenKey, 0)
	s.db.ExpireAt(ctx, HASHED_REFRESH+obj.HashedRefreshToken, refreshTokenExpires)

	return nil
}

func (s *RedisStorage) GetOAuthTokenByHashedAccessToken(ctx context.Context, token string) storage.StoredOAuthToken {
	rc := StoredOAuthToken{}

	key := HASHED_TOKEN + token
	oauthToken := s.db.Get(ctx, key).Val()
	res := s.db.HGetAll(ctx, oauthToken).Scan(&rc)
	log.Println(res)

	return rc.toStorageOAuthToken()
}

func (s *RedisStorage) GetOAuthTokenByHashedRefreshToken(ctx context.Context, token string) storage.StoredOAuthToken {
	rc := StoredOAuthToken{}

	key := HASHED_REFRESH + token
	oauthToken := s.db.Get(ctx, key).Val()
	res := s.db.HGetAll(ctx, oauthToken).Scan(&rc)
	log.Println(res)

	return rc.toStorageOAuthToken()
}

func (s *RedisStorage) InvalidateOAuthTokenByHashedAccessToken(ctx context.Context, token string) error {
	key := HASHED_TOKEN + token
	oauthToken := s.db.Get(ctx, key).Val()

	res := s.db.Del(ctx, oauthToken)
	return res.Err()
}
