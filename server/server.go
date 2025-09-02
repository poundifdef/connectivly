package server

import (
	"connectivly/storage"
	"context"
	"embed"
	"encoding/base64"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/MicahParks/jwkset"
	"github.com/gofiber/adaptor/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/template/html/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/ugurcsen/gods-generic/sets/hashset"
)

//go:embed templates/*
var embedDirTemplates embed.FS

type AuthServer struct {
	Storage     storage.Storage
	Issuer      string
	UserinfoURL string
}

// GenerateIDToken creates a signed JWT representing information about
// the end user. This is required for OIDC. Satisfies this spec:
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
func (a *AuthServer) GenerateIDToken(ctx context.Context, user_id string, client_id string, nonce string) string {
	key, key_id, err := a.Storage.GetRSAPrivateKey(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get private key")
		return ""
	}

	claims := make(jwt.MapClaims)
	// TODO: make this user-configurable
	claims["iss"] = a.Issuer
	claims["sub"] = user_id
	claims["aud"] = client_id
	if nonce != "" {
		claims["nonce"] = nonce
	}
	claims["iat"] = time.Now().UTC().Unix()
	claims["auth_time"] = time.Now().UTC().Unix()

	// Expiration hard-coded to 30 minutes. TODO: make configurable
	claims["exp"] = time.Now().UTC().Add(30 * time.Minute).Unix()

	j := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	j.Header["kid"] = key_id

	token, err := j.SignedString(key)
	if err != nil {
		log.Error().Err(err).Msg("Failed to sign ID token")
		return ""
	}

	return token
}

// GenerateJWT creates JWTs that will be used as OAuth Bearer tokens
func (a *AuthServer) GenerateJWT(ctx context.Context, user_id string, scopes []string, app storage.App, expiration time.Duration) string {
	key, _, err := a.Storage.GetRSAPrivateKey(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get private key")
		return ""
	}

	claims := make(jwt.MapClaims)

	claims["sub"] = user_id
	claims["scopes"] = scopes
	claims["app"] = app
	claims["exp"] = time.Now().UTC().Add(expiration).Unix()

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		log.Error().Err(err).Msg("Failed to sign JWT")
		return ""
	}

	return token
}

func (a *AuthServer) APIKeyMiddleware(c *fiber.Ctx) error {
	provider := a.Storage.GetProvider(c.Context())

	if provider == nil {
		return c.SendStatus(400)
	}

	api_key := c.Get("X-API-KEY")
	if !a.Storage.ValidateAPIKey(c.Context(), api_key) {
		return c.SendStatus(401)
	}

	return c.Next()
}

func (a *AuthServer) GetAuthSession(c *fiber.Ctx) error {
	session_id := c.Params("id")

	ctx := c.Context()
	session := a.Storage.GetAuthRequest(ctx, session_id, false)
	app := a.Storage.GetApp(ctx, session.ClientID)

	if session.ID == "" || app.ID == 0 {
		return c.SendStatus(404)
	}

	rc := storage.AuthSession{
		ID:     session.ID,
		App:    app,
		Scopes: session.Scopes(),
	}

	return c.JSON(rc)
}

func (a *AuthServer) ApproveAuthSession(c *fiber.Ctx) error {
	session_id := c.Params("id")

	type ApproveInput struct {
		User string `json:"user"`
	}

	approve_input := ApproveInput{}

	if err := c.BodyParser(&approve_input); err != nil {
		log.Error().Err(err).Msg("Failed to parse approve input")
		return err
	}

	err := a.Storage.ApproveAuthRequest(c.Context(), session_id, approve_input.User)
	if err != nil {
		return err
	}

	location, err := c.GetRouteURL("oauth.consent", fiber.Map{"id": session_id})
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"redirect_uri": c.Protocol() + "://" + c.Hostname() + location,
	})
}

func (a *AuthServer) IntrospectToken(c *fiber.Ctx) error {
	// This is NOT an oauth endpoint, it is an API endpoint for the provider

	ctx := c.Context()
	token := c.FormValue("token")

	t := a.Storage.GetOAuthTokenByHashedAccessToken(ctx, a.Storage.Hash(token))
	if t.HashedAccessToken != "" {
		return c.JSON(fiber.Map{
			"active": true,
		})
	}

	t = a.Storage.GetOAuthTokenByHashedRefreshToken(ctx, a.Storage.Hash(token))
	if t.HashedAccessToken != "" {
		return c.JSON(fiber.Map{
			"active": true,
		})
	}

	return c.JSON(fiber.Map{"active": false})
}

func (a *AuthServer) DenyAuthSession(c *fiber.Ctx) error {
	session_id := c.Params("id")

	a.Storage.DeleteAuthRequest(c.Context(), session_id)

	location, err := c.GetRouteURL("oauth.consent", fiber.Map{"id": session_id})
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"redirect_uri": c.Protocol() + "://" + c.Hostname() + location,
	})
}

func (a *AuthServer) JWKS(c *fiber.Ctx) error {
	ctx := c.Context()

	key, key_name, err := a.Storage.GetRSAPublicKey(ctx)
	if err != nil {
		return err
	}

	set := jwkset.NewMemoryStorage()

	marshal := jwkset.JWKMarshalOptions{
		Private: true,
	}
	metadata := jwkset.JWKMetadataOptions{
		KID: key_name,
	}
	options := jwkset.JWKOptions{
		Marshal:  marshal,
		Metadata: metadata,
	}
	jwk, err := jwkset.NewJWKFromKey(key, options)
	if err != nil {
		return err
	}

	err = set.KeyWrite(ctx, jwk)
	if err != nil {
		return err
	}

	response, err := set.JSONPublic(ctx)
	if err != nil {
		return err
	}

	return c.JSON(response)
}

func (a *AuthServer) ShowConsent(c *fiber.Ctx) error {
	ctx := c.Context()
	session_id := c.Params("id")

	session := a.Storage.GetAuthRequest(ctx, session_id, true)
	if session.ID == "" {
		return c.SendStatus(404)
	}

	app := a.Storage.GetApp(ctx, session.ClientID)
	if app.ID == 0 {
		return c.SendStatus(404)
	}

	provider := a.Storage.GetProvider(ctx)
	if provider == nil {
		return c.SendStatus(404)
	}

	available_scopes := hashset.New[string]()
	for _, s := range provider.Scopes(ctx) {
		available_scopes.Add(s.ID)
	}
	if !available_scopes.Contains(session.Scopes()...) {
		return c.SendStatus(400)
	}

	location, err := c.GetRouteURL("oauth.finalize_consent", fiber.Map{"id": session_id})
	if err != nil {
		return err
	}

	return c.Render("consent", fiber.Map{
		"app":          app,
		"session":      session,
		"providerName": provider.Name(ctx),
		"post_url":     c.Protocol() + "://" + c.Hostname() + location,
	})
}

func (a *AuthServer) FinalizeConsent(c *fiber.Ctx) error {
	// TODO: update scopes if they were modified

	ctx := c.Context()
	session_id := c.Params("id")
	session := a.Storage.GetAuthRequest(ctx, session_id, true)

	var redirect_params string
	if c.FormValue("accept") != "" {
		redirect_params = ("?code=" + session.Code +
			"&grant_type=" + session.ResponseType +
			"&redirect_uri=" + session.RedirectURI +
			"&state=" + session.State)
	} else {
		redirect_params = ("?error=access_denied" +
			"&state=" + session.State)
		a.Storage.DeleteAuthRequest(ctx, session_id)
	}

	return c.Redirect(session.RedirectURI + redirect_params)
}

func (a *AuthServer) Authorize(c *fiber.Ctx) error {
	// TODO: check client_id
	ctx := c.Context()

	providerParams := a.Storage.GetOAuthProviderParams(ctx)

	oauth_request := storage.OAuthRequest{}
	err := c.QueryParser(&oauth_request)
	if err != nil {
		params := url.Values{}
		params.Add("error", "invalid_request")
		params.Add("error_description", err.Error())
		return c.Redirect(oauth_request.RedirectURI + "?" + params.Encode())
	}

	log.Debug().Interface("oauth_request", oauth_request).Msg("OAuth request")

	app := a.Storage.GetApp(ctx, oauth_request.ClientID)
	log.Debug().Interface("app", app).Msg("app")

	found := slices.ContainsFunc(app.RedirectURI, func(s string) bool {
		return strings.EqualFold(s, oauth_request.RedirectURI)
	})

	if !found {
		return fiber.NewError(fiber.StatusBadRequest, "invalid redirect_uri")
	}

	if oauth_request.Prompt == "none" {
		params := url.Values{}
		params.Add("error", "login_required")
		// params.Add("error_description", "Only code response type supported")

		if oauth_request.State != "" {
			params.Add("state", oauth_request.State)
		}

		return c.Redirect(oauth_request.RedirectURI + "?" + params.Encode())
	}

	if oauth_request.ResponseType != "code" {
		params := url.Values{}
		params.Add("error", "invalid_request")
		params.Add("error_description", "Only code response type supported")

		if oauth_request.State != "" {
			params.Add("state", oauth_request.State)
		}

		return c.Redirect(oauth_request.RedirectURI + "?" + params.Encode())
	}

	// TODO: validate that all params are there
	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
	// https://auth0.com/docs/authenticate/protocols/oauth#authorization-endpoint

	// TODO: return error format

	oauth_request.Expires = time.Now().Add(10 * time.Minute).UTC().Unix()
	oauth_request.ID = a.Storage.GenerateRandomString(32)
	oauth_request.Code = a.Storage.GenerateRandomString(32)

	// TODO: return error format
	err = a.Storage.SaveOAuthRequest(ctx, oauth_request.ID, oauth_request)
	if err != nil {
		return err
	}

	return c.Redirect(providerParams.ProviderRedirectURL + "?token=" + oauth_request.ID)
}

func (a *AuthServer) Token(c *fiber.Ctx) error {
	// TODO: update scopes if they were modified
	ctx := c.Context()

	token_request := storage.TokenRequest{}
	err := c.BodyParser(&token_request)
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse token request")
		return c.Status(400).JSON(fiber.Map{
			"error":             "invalid_request",
			"error_description": "Unable to parse POST body",
		})
	}

	client_id, client_secret := a.getClientCreds(c)
	app := a.Storage.GetApp(ctx, client_id)

	if app.ID == 0 {
		return c.Status(400).JSON(fiber.Map{
			"error":             "invalid_client",
			"error_description": "Unauthorized",
		})
	}

	if app.ClientID != client_id {
		return c.Status(400).JSON(fiber.Map{
			"error":             "invalid_client",
			"error_description": "Unauthorized",
		})
	}

	if app.ClientSecret != a.Storage.Hash(client_secret) {
		return c.Status(400).JSON(fiber.Map{
			"error":             "invalid_client",
			"error_description": "Unauthorized",
		})
	}

	// expiration := 5 * time.Second
	expiration := 30 * time.Minute
	refresh_expiration := 24 * 7 * time.Hour

	if token_request.GrantType == "authorization_code" {

		session := a.Storage.GetAuthRequestByCode(ctx, token_request.Code)
		a.Storage.DeleteAuthRequest(ctx, session.ID)

		if session.ID == "" {
			return c.Status(400).JSON(fiber.Map{
				"error":             "invalid_grant",
				"error_description": "Invalid auth code",
			})
		}

		access_token := a.GenerateJWT(ctx, session.UserID, session.Scopes(), app, expiration)

		refresh_token := a.Storage.GenerateRandomString(32)
		if session.MaxAge != "" {
			expiration_seconds, _ := strconv.Atoi(session.MaxAge)
			expiration = time.Duration(expiration_seconds) * time.Second
		}

		token := storage.OAuthToken{
			AccessToken:  access_token,
			TokenType:    "bearer",
			ExpiresIn:    int(expiration.Seconds()),
			State:        session.State,
			Scope:        session.Scope,
			UserID:       session.UserID,
			RefreshToken: refresh_token,

			// For OIDC
			IDToken: a.GenerateIDToken(c.Context(), session.UserID, client_id, session.Nonce),
		}

		stored_token := storage.StoredOAuthToken{
			HashedAccessToken:   a.Storage.Hash(token.AccessToken),
			AccessTokenExpires:  time.Now().UTC().Add(expiration).Unix(),
			HashedRefreshToken:  a.Storage.Hash(token.RefreshToken),
			RefreshTokenExpires: time.Now().UTC().Add(refresh_expiration).Unix(),
			TokenType:           token.TokenType,
			Scopes:              token.Scopes(),
			UserID:              token.UserID,
		}

		a.Storage.SaveOAuthToken(ctx, stored_token)

		return c.JSON(token)
	} else if token_request.GrantType == "refresh_token" {
		session := a.Storage.GetOAuthTokenByHashedRefreshToken(ctx, a.Storage.Hash(token_request.RefreshToken))
		if session.HashedAccessToken == "" {
			return c.JSON(fiber.Map{
				"error":             "invalid_grant",
				"error_description": "Expired refresh code",
			})
		}

		access_token := a.GenerateJWT(ctx, session.UserID, session.Scopes, app, expiration)
		refresh_token := a.Storage.GenerateRandomString(32)

		token := storage.OAuthToken{
			AccessToken:  access_token,
			TokenType:    "Bearer",
			ExpiresIn:    int(expiration.Seconds()),
			Scope:        strings.Join(session.Scopes, " "),
			UserID:       session.UserID,
			RefreshToken: refresh_token,
		}

		// Save hashed stored token
		stored_token := storage.StoredOAuthToken{
			HashedAccessToken:   a.Storage.Hash(token.AccessToken),
			AccessTokenExpires:  time.Now().UTC().Add(expiration).Unix(),
			HashedRefreshToken:  a.Storage.Hash(token.RefreshToken),
			RefreshTokenExpires: time.Now().UTC().Add(refresh_expiration).Unix(),
			TokenType:           token.TokenType,
			Scopes:              token.Scopes(),
			UserID:              token.UserID,
		}

		a.Storage.SaveOAuthToken(ctx, stored_token)

		// Invalidate previous token
		a.Storage.InvalidateOAuthTokenByHashedAccessToken(ctx, session.HashedAccessToken)

		// Return new token
		c.Append("Cache-Control", "no-store")
		return c.JSON(token)
	}

	return c.Status(400).JSON(fiber.Map{
		"error":             "invalid_request",
		"error_description": "Error",
	})
}

func (a *AuthServer) OpenIDConfiguration(c *fiber.Ctx) error {

	authorize_route, _ := c.GetRouteURL("oauth.authorize", fiber.Map{})
	token_route, _ := c.GetRouteURL("oauth.token", fiber.Map{})
	userinfo_route, _ := c.GetRouteURL("oauth.userinfo", fiber.Map{})
	jwks_route, _ := c.GetRouteURL("oauth.jwks", fiber.Map{})

	base_url := c.Protocol() + "://" + c.Hostname()

	return c.JSON(fiber.Map{
		"issuer":                 a.Issuer,
		"authorization_endpoint": base_url + authorize_route,
		"token_endpoint":         base_url + token_route,

		// Optional accoring to spec, but required for certification
		"userinfo_endpoint": base_url + userinfo_route,

		"jwks_uri":                              base_url + jwks_route,
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (a *AuthServer) getBearerToken(c *fiber.Ctx) string {
	bearer := ""

	auth_headers := c.GetReqHeaders()["Authorization"]
	if len(auth_headers) != 1 {
		return bearer
	}

	auth_header := auth_headers[0]
	tokens := strings.Split(auth_header, " ")
	if len(tokens) == 2 {
		bearer = strings.Split(auth_header, " ")[1]
	}

	if bearer == "" {
		bearer = c.FormValue("access_token")
	}

	return bearer
}

func (a *AuthServer) Userinfo(c *fiber.Ctx) error {
	token := a.getBearerToken(c)

	t := a.Storage.GetOAuthTokenByHashedAccessToken(c.Context(), a.Storage.Hash(token))
	if t.HashedAccessToken == "" {
		c.Append("WWW-Authenticate", "error=\"invalid_token\"")
		return c.SendStatus(401)
	}

	if a.UserinfoURL == "" {
		return c.JSON(fiber.Map{
			"sub": t.UserID,
		})
	}

	req, err := http.NewRequest("GET", a.UserinfoURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	resp.Body.Close()

	return c.Status(resp.StatusCode).Type("application/json").Send([]byte(body))

}

func (a *AuthServer) getClientCreds(c *fiber.Ctx) (client_id string, client_secret string) {
	auth_headers := c.GetReqHeaders()["Authorization"]
	if len(auth_headers) != 1 {
		return
	}

	auth_header := auth_headers[0]
	bearer := strings.Split(auth_header, " ")[1]
	client_token, err := base64.StdEncoding.DecodeString(bearer)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decode client credentials")
		return
	}
	clientid_secret := strings.Split(string(client_token), ":")

	client_id = string(clientid_secret[0])
	client_secret = string(clientid_secret[1])
	return
}

func (a *AuthServer) CreateApp(c *fiber.Ctx) error {
	var createInput struct {
		AppName     string   `json:"app_name"`
		OwnerID     string   `json:"owner_id"`
		RedirectURI []string `json:"redirect_uri"`
	}
	if err := c.BodyParser(&createInput); err != nil {
		return err
	}
	new_app, err := a.Storage.CreateApp(c.Context(), storage.App{
		Name:         createInput.AppName,
		ClientID:     uuid.New().String(),
		ClientSecret: uuid.New().String(),
		RedirectURI:  createInput.RedirectURI,
		OwnerID:      createInput.OwnerID,
	})

	if err != nil {
		return err
	}
	return c.JSON(new_app)
}

func (a *AuthServer) ErrorHandler(c *fiber.Ctx, err error) error {
	return c.Status(500).JSON(fiber.Map{
		"error": err.Error(),
	})
}

func (a *AuthServer) GetApp() http.HandlerFunc {
	return adaptor.FiberApp(a.GetAppFiber())
}

func (a *AuthServer) GetAppFiber() *fiber.App {
	serverRoot, err := fs.Sub(embedDirTemplates, "templates")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load templates")
	}
	engine := html.NewFileSystem(http.FS(serverRoot), ".html")
	app := fiber.New(fiber.Config{
		Views:        engine,
		Immutable:    true,
		ErrorHandler: a.ErrorHandler,
	})

	app.Use(logger.New())

	app.Use("/static", filesystem.New(filesystem.Config{
		Root:       http.FS(serverRoot),
		PathPrefix: "static",
	}))

	// Endpoints intended for the provider for manging sessions
	api := app.Group("/api", a.APIKeyMiddleware)
	api.Post("/app", a.CreateApp)

	// Introspect and validate an OAuth token
	api.Post("/introspect", a.IntrospectToken)

	// Endpoints for allowing/denying ann end-user to perform an auth flow
	auth_session := api.Group("/auth_session/:id")
	auth_session.Get("/", a.GetAuthSession)
	auth_session.Post("/approve", a.ApproveAuthSession)
	auth_session.Post("/deny", a.DenyAuthSession)

	// End-user facing auth-related enpoints. Not directly related to OAuth flow
	auth := app.Group("/auth")
	auth.Get("/jwks.json", a.JWKS).Name("oauth.jwks")
	auth.Get("/consent/:id", a.ShowConsent).Name("oauth.consent")
	auth.Post("/consent/:id", a.FinalizeConsent).Name("oauth.finalize_consent")

	oauth := auth.Group("/oauth2")
	oauth.Get("/authorize", a.Authorize).Name("oauth.authorize")
	oauth.Post("/token", a.Token).Name("oauth.token")
	oauth.Get("/.well-known/openid-configuration", a.OpenIDConfiguration)
	oauth.Get("/userinfo", a.Userinfo).Name("oauth.userinfo")
	oauth.Post("/userinfo", a.Userinfo)

	return app
}
