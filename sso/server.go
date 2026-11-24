// SSO server: the central login service.
//
//	POST /login                  {"username","password"} -> signed access token
//	POST /logout                 ends the SSO session and notifies every app
//	GET  /.well-known/jwks.json  public key used by the apps to verify tokens

package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const tokenTTL = time.Hour

// App is an application that trusts the SSO server.
type App struct {
	ID      string // used as token audience
	BaseURL string // where the back-channel logout notification is sent
}

// ParseApps parses "id=url,id=url", e.g. "catalog=http://localhost:8081".
func ParseApps(s string) ([]App, error) {
	var apps []App
	for item := range strings.SplitSeq(s, ",") {
		id, url, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok || id == "" || url == "" {
			return nil, fmt.Errorf("invalid app entry %q, expected id=url", item)
		}
		apps = append(apps, App{ID: id, BaseURL: strings.TrimRight(url, "/")})
	}
	return apps, nil
}

type account struct {
	username, name, email string
	roles                 []string
	passwordHash          []byte // bcrypt; the password itself is never stored
}

// Server is the SSO server. Users and sessions are kept in memory.
type Server struct {
	issuer string
	apps   []App
	key    *rsa.PrivateKey // signs the tokens; never leaves this process
	kid    string          // key ID, lets the apps pick the right public key
	jwks   []byte          // public key in JWKS format, served to the apps

	mu       sync.Mutex
	users    map[string]account
	sessions map[string]string // active SSO sessions: SID -> username
}

// NewServer creates the SSO server with a fresh RSA signing key. Sessions live in
// memory, so a restart logs everyone out; tokens signed with the old key are
// then rejected by the apps as well.
func NewServer(issuer string, apps []App) (*Server, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	kid := randomString(8)

	// Publish the public half of the key as a JSON Web Key Set.
	jwk, err := jwkset.NewJWKFromKey(&key.PublicKey, jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{KID: kid, ALG: jwkset.AlgRS256, USE: jwkset.UseSig},
	})
	if err != nil {
		return nil, err
	}
	set := jwkset.NewMemoryStorage()
	if err := set.KeyWrite(context.Background(), jwk); err != nil {
		return nil, err
	}
	jwks, err := set.JSONPublic(context.Background())
	if err != nil {
		return nil, err
	}

	return &Server{
		issuer: issuer, apps: apps, key: key, kid: kid, jwks: jwks,
		users: make(map[string]account), sessions: make(map[string]string),
	}, nil
}

// AddUser creates an account. The password is hashed with bcrypt right away.
func (s *Server) AddUser(username, password, name, email string, roles ...string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[username] = account{username, name, email, roles, hash}
	return nil
}

// Router returns the HTTP routes of the SSO server.
func (s *Server) Router() *gin.Engine {
	r := gin.Default()
	r.POST("/login", s.login)
	r.POST("/logout", s.logout)
	r.GET(PathJWKS, func(c *gin.Context) { c.Data(http.StatusOK, "application/json", s.jwks) })
	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })
	return r
}

// login checks the credentials, opens an SSO session and returns one signed
// token that every application accepts.
func (s *Server) login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": `body must be {"username": "...", "password": "..."}`})
		return
	}

	s.mu.Lock()
	u, ok := s.users[req.Username]
	s.mu.Unlock()
	if !ok || bcrypt.CompareHashAndPassword(u.passwordHash, []byte(req.Password)) != nil {
		slog.Warn("login failed", "user", req.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}

	now := time.Now()
	sid := randomString(16)
	audience := make([]string, len(s.apps))
	for i, a := range s.apps {
		audience[i] = a.ID
	}
	token, err := s.sign("JWT", Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   u.username,
			Audience:  audience,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)),
		},
		SID: sid, Name: u.name, Email: u.email, Roles: u.roles,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not sign token"})
		return
	}

	s.mu.Lock()
	s.sessions[sid] = u.username
	s.mu.Unlock()

	slog.Info("login succeeded", "user", u.username, "sid", sid)
	c.JSON(http.StatusOK, gin.H{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(tokenTTL.Seconds()),
		"sid":          sid,
		"valid_for":    audience,
	})
}

// logout ends the SSO session of the presented token and sends a signed
// logout token to every application (back-channel logout). From then on the
// applications reject the token, although it has not expired yet.
func (s *Server) logout(c *gin.Context) {
	raw, _ := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer ")
	var claims Claims
	_, err := jwt.ParseWithClaims(raw, &claims,
		func(*jwt.Token) (any, error) { return &s.key.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(s.issuer), jwt.WithExpirationRequired())
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token: " + err.Error()})
		return
	}

	s.mu.Lock()
	_, active := s.sessions[claims.SID]
	delete(s.sessions, claims.SID)
	s.mu.Unlock()
	if !active {
		c.JSON(http.StatusConflict, gin.H{"error": "session already logged out"})
		return
	}

	slog.Info("sso session ended", "user", claims.Subject, "sid", claims.SID)
	c.JSON(http.StatusOK, gin.H{
		"logged_out":    claims.Subject,
		"sid":           claims.SID,
		"apps_notified": s.notifyApps(claims.Subject, claims.SID),
	})
}

// notifyApps calls every application in parallel and returns the outcome per app.
func (s *Server) notifyApps(username, sid string) map[string]string {
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results = make(map[string]string)
	)
	for _, app := range s.apps {
		wg.Go(func() {
			result := "ok"
			if err := s.sendLogoutToken(app, username, sid); err != nil {
				result = "error: " + err.Error()
			}
			slog.Info("back-channel logout", "app", app.ID, "sid", sid, "result", result)
			mu.Lock()
			results[app.ID] = result
			mu.Unlock()
		})
	}
	wg.Wait()
	return results
}

func (s *Server) sendLogoutToken(app App, username, sid string) error {
	now := time.Now()
	token, err := s.sign("logout+jwt", LogoutClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   username,
			Audience:  jwt.ClaimStrings{app.ID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(2 * time.Minute)),
		},
		SID:    sid,
		Events: map[string]map[string]any{BackchannelLogoutEvent: {}},
	})
	if err != nil {
		return err
	}
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.PostForm(app.BaseURL+PathBackchannelLogout, url.Values{"logout_token": {token}})
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %s", resp.Status)
	}
	return nil
}

// sign creates an RS256 JWT with the given "typ" header.
func (s *Server) sign(typ string, claims jwt.Claims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = s.kid
	t.Header["typ"] = typ
	return t.SignedString(s.key)
}
