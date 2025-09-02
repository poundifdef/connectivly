package sqlite

import (
	"connectivly/storage"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/m1/go-generate-password/generator"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

type SQLiteStorageProvider struct {
	storage *SQLiteStorage
}

func (m SQLiteStorageProvider) Name(ctx context.Context) string {
	return m.storage.get("provider-name")
}

func (m SQLiteStorageProvider) Logo(ctx context.Context) []byte {
	return make([]byte, 0)
}

func (m SQLiteStorageProvider) Scopes(ctx context.Context) []storage.Scope {
	rc := make([]storage.Scope, 0)
	scopes_json := m.storage.get("provider-scopes")
	err := json.Unmarshal([]byte(scopes_json), &rc)
	if err != nil {
		log.Println(err)
	}
	return rc
}

type SQLiteStorage struct {
	filename string
	db       *gorm.DB
	provider storage.Provider
}

func NewSQLiteStorage(filename string, providerURL string) (*SQLiteStorage, error) {
	s := &SQLiteStorage{filename: filename}

	// If the DB is brand new, populate with basic information
	_, err := os.Stat(s.filename)
	needs_initialization := err != nil

	gormConfig := &gorm.Config{TranslateError: true}
	if os.Getenv("DEBUG") == "1" {
		gormConfig.Logger = logger.Default.LogMode(logger.Info)
	}

	db, err := gorm.Open(sqlite.Open(filename), gormConfig)
	if err != nil {
		return nil, err
	}
	s.db = db

	// Set up DB tables
	s.setupDB()

	s.set("provider-redirect-url", providerURL)

	if needs_initialization {
		log.Println("Initializing new Connectivly instance at " + filename)

		err := s.initializeNew()
		if err != nil {
			return nil, err
		}
	}

	s.provider = SQLiteStorageProvider{storage: s}

	return s, nil
}

func (s *SQLiteStorage) setupDB() error {
	err := s.db.AutoMigrate(&KeyValue{})
	if err != nil {
		return err
	}

	err = s.db.AutoMigrate(&OAuthRequest{})
	if err != nil {
		return err
	}
	err = s.db.AutoMigrate(&StoredOAuthToken{})
	if err != nil {
		return err
	}
	err = s.db.AutoMigrate(&App{})
	if err != nil {
		return err
	}

	return nil
}

func (s *SQLiteStorage) initializeNew() error {
	// Generate keypair for JWTs
	ctx := context.Background()
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}
	s.setBytes("private-key", x509.MarshalPKCS1PrivateKey(key))
	s.set("private-key-id", "connectivly-example-key")

	s.set("provider-name", "ACME Service")

	api_key := "local-api-key"
	s.set("api-key", s.Hash(api_key))

	log.Println()
	log.Println("API Key: " + api_key)
	log.Println()

	s.CreateApp(ctx, storage.App{
		Name:         "Client 1 App",
		ClientID:     "client1",
		ClientSecret: s.Hash("secret1"),
		RedirectURI:  []string{"http://localhost:5000/auth"},
		OwnerID:      "test",
	})

	log.Println("Client 1 App")
	log.Println("Client ID: client1")
	log.Println("Client Secret: secret1")
	log.Println("Redirect URI: http://localhost:5000/auth")
	log.Println()

	s.CreateApp(ctx, storage.App{
		Name:         "Client 2 App",
		ClientID:     "client2",
		ClientSecret: s.Hash("secret2"),
		RedirectURI:  []string{"http://localhost:5000/auth"},
		OwnerID:      "test",
	})

	log.Println("Client 2 App")
	log.Println("Client ID: client2")
	log.Println("Client Secret: secret2")
	log.Println("Redirect URI: http://localhost:5000/auth")
	log.Println()

	scopes := make([]storage.Scope, 0)
	scopes = append(scopes, storage.Scope{ID: "openid", Name: "OIDC", Description: "OpenID Connect"})
	scopes_json, err := json.Marshal(&scopes)
	if err != nil {
		log.Println(err)
	}

	s.set("provider-scopes", string(scopes_json))

	return nil
}

func (s *SQLiteStorage) getBytes(key string) []byte {
	value := s.get(key)
	decoded, _ := base64.StdEncoding.DecodeString(value)
	return decoded
}

func (s *SQLiteStorage) setBytes(k string, v []byte) {
	encoded := base64.StdEncoding.EncodeToString(v)
	s.set(k, encoded)
}

func (s *SQLiteStorage) get(key string) string {
	kv := KeyValue{}
	s.db.Where(&KeyValue{Key: key}).First(&kv)
	return kv.Value
}

func (s *SQLiteStorage) set(k string, v string) {
	kv := &KeyValue{Key: k, Value: v}

	s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.Assignments(map[string]interface{}{"value": v}),
	}).Create(&kv)
}

func (s *SQLiteStorage) ValidateAPIKey(ctx context.Context, input string) bool {
	return s.Hash(input) == s.get("api-key")
}

func (s *SQLiteStorage) GetRSAPublicKey(ctx context.Context) (*rsa.PublicKey, string, error) {
	privateKeyBytes := s.getBytes("private-key")
	keyId := s.get("private-key-id")
	privateKey, _ := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	return &privateKey.PublicKey, keyId, nil
}

func (s *SQLiteStorage) GetRSAPrivateKey(ctx context.Context) (*rsa.PrivateKey, string, error) {
	privateKeyBytes := s.getBytes("private-key")
	keyId := s.get("private-key-id")
	privateKey, _ := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	return privateKey, keyId, nil
}

func (s *SQLiteStorage) GetProvider(ctx context.Context) storage.Provider {
	return s.provider
}

func (s *SQLiteStorage) GetOAuthProviderParams(ctx context.Context) storage.OAuthParams {
	rc := storage.OAuthParams{
		ProviderRedirectURL: s.get("provider-redirect-url"),
	}
	return rc
}

func (s *SQLiteStorage) SaveOAuthRequest(ctx context.Context, token string, request storage.OAuthRequest) error {
	rc := s.db.Create(&request)
	return rc.Error
}

func (s *SQLiteStorage) GetAuthRequest(ctx context.Context, id string, approvalRequired bool) storage.OAuthRequest {
	rc := OAuthRequest{}

	if approvalRequired {
		s.db.Where("id = ? AND expires >= ? AND approved = ?", id, time.Now().UTC().Unix(), true).First(&rc)
	} else {
		s.db.Where("id = ? AND expires >= ?", id, time.Now().UTC().Unix()).First(&rc)
	}

	return rc.toStorageOAuthRequest()
}

func (s *SQLiteStorage) GetAuthRequestByCode(ctx context.Context, code string) storage.OAuthRequest {
	rc := OAuthRequest{}
	s.db.Where("code = ? AND expires >= ? AND approved = ?", code, time.Now().UTC().Unix(), true).First(&rc)
	return rc.toStorageOAuthRequest()
}

func (s *SQLiteStorage) Hash(input string) string {
	return fmt.Sprintf("%x", sha512.Sum512([]byte(input)))
}

func (s *SQLiteStorage) GenerateRandomString(length uint) string {
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

func (s *SQLiteStorage) ApproveAuthRequest(ctx context.Context, id string, user_id string) error {
	// rc := s.db.Model(&OAuthRequest{}).Where("id=?", id).Update("approved", true).Update("user_id", user_id)
	rc := s.db.Model(&OAuthRequest{}).Where("id=?", id).Updates(&OAuthRequest{Approved: true, UserID: user_id})
	log.Println(rc.Error)

	return rc.Error
}

func (s *SQLiteStorage) DeleteAuthRequest(ctx context.Context, id string) {
	s.db.Model(&OAuthRequest{}).Where("id=?", id).Delete(&OAuthRequest{})
}

func (s *SQLiteStorage) CreateApp(ctx context.Context, app storage.App) (storage.App, error) {
	var redirectURIBytes []byte
	var err error
	if app.RedirectURI != nil {
		redirectURIBytes, err = json.Marshal(app.RedirectURI)
		if err != nil {
			return storage.App{}, err
		}
	}

	obj := App{
		Name:         app.Name,
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		RedirectURI:  string(redirectURIBytes),
		OwnerID:      app.OwnerID,
	}
	rc := s.db.Create(&obj)

	if rc.Error != nil {
		if errors.Is(rc.Error, gorm.ErrDuplicatedKey) {
			return storage.App{}, errors.New("App with this name already exists")
		}
		return storage.App{}, rc.Error
	}

	var redirectURIs []string
	if err := json.Unmarshal([]byte(obj.RedirectURI), &redirectURIs); err != nil {
		return storage.App{}, err
	}

	storage_app := storage.App{
		ID:           obj.ID,
		Name:         obj.Name,
		ClientID:     obj.ClientID,
		ClientSecret: obj.ClientSecret,
		RedirectURI:  redirectURIs,
	}
	return storage_app, rc.Error
}

func (s *SQLiteStorage) GetApp(ctx context.Context, clientid string) storage.App {
	rc := App{}
	s.db.Where("client_id = ?", clientid).First(&rc)

	var redirectURIs []string
	if err := json.Unmarshal([]byte(rc.RedirectURI), &redirectURIs); err != nil {
		return storage.App{}
	}

	return storage.App{
		ID:           rc.ID,
		Name:         rc.Name,
		ClientID:     rc.ClientID,
		ClientSecret: rc.ClientSecret,
		RedirectURI:  redirectURIs,
	}
}

func (s *SQLiteStorage) SaveOAuthToken(ctx context.Context, o storage.StoredOAuthToken) error {
	obj := StoredOAuthToken{
		HashedAccessToken:   o.HashedAccessToken,
		AccessTokenExpires:  o.AccessTokenExpires,
		HashedRefreshToken:  o.HashedRefreshToken,
		RefreshTokenExpires: o.RefreshTokenExpires,
		TokenType:           o.TokenType,
		Scopes:              strings.Join(o.Scopes, " "),
		UserID:              o.UserID,
	}
	rc := s.db.Create(&obj)
	return rc.Error
}

func (s *SQLiteStorage) GetOAuthTokenByHashedAccessToken(ctx context.Context, token string) storage.StoredOAuthToken {
	rc := StoredOAuthToken{}
	s.db.Where("hashed_access_token = ? AND access_token_expires >= ?", token, time.Now().UTC().Unix()).First(&rc)
	return rc.toStorageOAuthToken()
}

func (s *SQLiteStorage) GetOAuthTokenByHashedRefreshToken(ctx context.Context, token string) storage.StoredOAuthToken {
	rc := StoredOAuthToken{}
	s.db.Where("hashed_refresh_token = ? AND refresh_token_expires >= ?", token, time.Now().UTC().Unix()).First(&rc)
	return rc.toStorageOAuthToken()
}

func (s *SQLiteStorage) InvalidateOAuthTokenByHashedAccessToken(ctx context.Context, token string) error {
	rc := s.db.Where("hashed_access_token = ?", token).Delete(&StoredOAuthToken{})
	return rc.Error
}
