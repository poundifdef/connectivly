package sqlite

import (
	"connectivly/storage"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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

func (m SQLiteStorageProvider) Name() string {
	return m.storage.get("provider-name")
}

func (m SQLiteStorageProvider) Logo() []byte {
	return make([]byte, 0)
}

func (m SQLiteStorageProvider) Scopes() []storage.Scope {
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

func NewSQLiteStorage(filename string, providerURL string, apiKey string) (*SQLiteStorage, error) {
	s := &SQLiteStorage{filename: filename}

	// If the DB is brand new, populate with basic information
	_, err := os.Stat(s.filename)
	needs_initialization := err != nil

	db, err := gorm.Open(sqlite.Open(filename), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	s.db = db

	// Set up DB tables
	s.setupDB()

	s.set("provider-redirect-url", providerURL)
	s.set("api-key", s.Hash(apiKey))

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
	s.db.AutoMigrate(&KeyValue{})
	s.db.AutoMigrate(&OAuthRequest{})
	s.db.AutoMigrate(&StoredOAuthToken{})
	s.db.AutoMigrate(&App{})

	return nil
}

func (s *SQLiteStorage) initializeNew() error {
	// Generate keypair for JWTs
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}
	s.setBytes("private-key", x509.MarshalPKCS1PrivateKey(key))
	s.set("private-key-id", "connectivly-example-key")

	s.set("provider-name", "ACME Service")

	s.CreateApp(storage.App{
		Name:         "Client 1 App",
		ClientID:     "client1",
		ClientSecret: s.Hash("secret1"),
	})

	s.CreateApp(storage.App{
		Name:         "Client 2 App",
		ClientID:     "client2",
		ClientSecret: s.Hash("secret2"),
	})

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

func (s *SQLiteStorage) ValidateAPIKey(input string) bool {
	return s.Hash(input) == s.get("api-key")
}

func (s *SQLiteStorage) GetRSAPublicKey() (*rsa.PublicKey, string, error) {
	privateKeyBytes := s.getBytes("private-key")
	keyId := s.get("private-key-id")
	privateKey, _ := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	return &privateKey.PublicKey, keyId, nil
}

func (s *SQLiteStorage) GetRSAPrivateKey() (*rsa.PrivateKey, string, error) {
	privateKeyBytes := s.getBytes("private-key")
	keyId := s.get("private-key-id")
	privateKey, _ := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	return privateKey, keyId, nil
}

func (s *SQLiteStorage) GetProvider() storage.Provider {
	return s.provider
}

func (s *SQLiteStorage) GetOAuthProviderParams() storage.OAuthParams {
	rc := storage.OAuthParams{
		ProviderRedirectURL: s.get("provider-redirect-url"),
	}
	return rc
}

func (s *SQLiteStorage) SaveOAuthRequest(token string, request storage.OAuthRequest) error {
	rc := s.db.Create(&request)
	return rc.Error
}

func (s *SQLiteStorage) GetAuthRequest(id string, approvalRequired bool) storage.OAuthRequest {
	rc := OAuthRequest{}

	if approvalRequired {
		s.db.Where("id = ? AND expires >= ? AND approved = ?", id, time.Now().UTC().Unix(), true).First(&rc)
	} else {
		s.db.Where("id = ? AND expires >= ?", id, time.Now().UTC().Unix()).First(&rc)
	}

	return rc.toStorageOAuthRequest()
}

func (s *SQLiteStorage) GetAuthRequestByCode(code string) storage.OAuthRequest {
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

func (s *SQLiteStorage) ApproveAuthRequest(id string, user_id string) error {
	// rc := s.db.Model(&OAuthRequest{}).Where("id=?", id).Update("approved", true).Update("user_id", user_id)
	rc := s.db.Model(&OAuthRequest{}).Where("id=?", id).Updates(&OAuthRequest{Approved: true, UserID: user_id})
	log.Println(rc.Error)

	return rc.Error
}

func (s *SQLiteStorage) DeleteAuthRequest(id string) {
	s.db.Model(&OAuthRequest{}).Where("id=?", id).Delete(&OAuthRequest{})
}

func (s *SQLiteStorage) CreateApp(app storage.App) (storage.App, error) {
	obj := App{
		Name:         app.Name,
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
	}
	rc := s.db.Create(&obj)

	storage_app := storage.App{
		ID:           obj.ID,
		Name:         obj.Name,
		ClientID:     obj.ClientID,
		ClientSecret: obj.ClientSecret,
	}
	return storage_app, rc.Error
}

func (s *SQLiteStorage) GetApp(clientid string) storage.App {
	rc := App{}
	s.db.Where("client_id = ?", clientid).First(&rc)
	return storage.App{
		ID:           rc.ID,
		Name:         rc.Name,
		ClientID:     rc.ClientID,
		ClientSecret: rc.ClientSecret,
	}
}

func (s *SQLiteStorage) SaveOAuthToken(o storage.StoredOAuthToken) error {
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

func (s *SQLiteStorage) GetOAuthTokenByHashedAccessToken(token string) storage.StoredOAuthToken {
	rc := StoredOAuthToken{}
	s.db.Where("hashed_access_token = ? AND access_token_expires >= ?", token, time.Now().UTC().Unix()).First(&rc)
	return rc.toStorageOAuthToken()
}

func (s *SQLiteStorage) GetOAuthTokenByHashedRefreshToken(token string) storage.StoredOAuthToken {
	rc := StoredOAuthToken{}
	s.db.Where("hashed_refresh_token = ? AND refresh_token_expires >= ?", token, time.Now().UTC().Unix()).First(&rc)
	return rc.toStorageOAuthToken()
}

func (s *SQLiteStorage) InvalidateOAuthTokenByHashedAccessToken(token string) error {
	rc := s.db.Where("hashed_access_token = ?", token).Delete(&StoredOAuthToken{})
	return rc.Error
}
