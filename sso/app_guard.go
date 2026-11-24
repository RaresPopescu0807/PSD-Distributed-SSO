// App guard: what every application uses to trust the SSO server. It verifies
// access tokens locally with the server's public key and receives the
// back-channel logout notifications that revoke a session.

package sso

import (
	"cmp"
	"context"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// User is the authenticated caller, taken from the verified token.
type User struct {
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
	SID      string   `json:"sid"`
}

// HasRole reports whether the user has at least one of the roles.
func (u *User) HasRole(roles ...string) bool {
	return slices.ContainsFunc(roles, func(r string) bool { return slices.Contains(u.Roles, r) })
}

// AppGuard protects one application: it only lets in requests that carry a
// valid token issued by the SSO server.
type AppGuard struct {
	appID  string          // must appear in the token audience ("aud")
	issuer string          // expected "iss" claim
	keys   keyfunc.Keyfunc // downloads, caches and refreshes the SSO public key

	mu      sync.Mutex
	revoked map[string]bool // SIDs logged out at the SSO server
}

// NewAppGuard creates the guard. The public key is downloaded in the
// background, so the application may start before the SSO server.
func NewAppGuard(appID, issuer, jwksURL string) (*AppGuard, error) {
	keys, err := keyfunc.NewDefaultCtx(context.Background(), []string{jwksURL})
	if err != nil {
		return nil, err
	}
	return &AppGuard{appID: appID, issuer: issuer, keys: keys, revoked: make(map[string]bool)}, nil
}

// AppGuardFromEnv uses SSO_ISSUER_URL (public address of the SSO server,
// default http://localhost:8080) and SSO_INTERNAL_URL (address used to
// download the key; inside Docker http://sso-server:8080).
func AppGuardFromEnv(appID string) (*AppGuard, error) {
	issuer := cmp.Or(os.Getenv("SSO_ISSUER_URL"), "http://localhost:8080")
	internal := cmp.Or(os.Getenv("SSO_INTERNAL_URL"), issuer)
	return NewAppGuard(appID, issuer, internal+PathJWKS)
}

// Register adds the SSO routes to the application:
//
//	GET  /me                        the authenticated user
//	POST /auth/backchannel-logout   called by the SSO server at logout
func (g *AppGuard) Register(r *gin.Engine) {
	r.GET("/me", g.Require(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"app": g.appID, "user": CurrentUser(c)})
	})
	r.POST(PathBackchannelLogout, g.backchannelLogout)
}

// Require is a middleware that only lets through requests with a valid,
// non-revoked token. The user is then available through CurrentUser.
func (g *AppGuard) Require() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, ok := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer ")
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing header: Authorization: Bearer <token> (get one from POST /login on the SSO server)"})
			return
		}
		var claims Claims
		if _, err := g.parse(raw, &claims); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token: " + err.Error()})
			return
		}
		g.mu.Lock()
		revoked := g.revoked[claims.SID]
		g.mu.Unlock()
		if revoked {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "session was logged out at the SSO server"})
			return
		}
		c.Set("user", &User{claims.Subject, claims.Name, claims.Email, claims.Roles, claims.SID})
		c.Next()
	}
}

// CurrentUser returns the user set by Require.
func CurrentUser(c *gin.Context) *User {
	return c.MustGet("user").(*User)
}

// backchannelLogout receives the logout token from the SSO server and revokes
// the session. The token is signed, so nobody else can log users out.
func (g *AppGuard) backchannelLogout(c *gin.Context) {
	var claims LogoutClaims
	tok, err := g.parse(c.PostForm("logout_token"), &claims)
	if err != nil || tok.Header["typ"] != "logout+jwt" || claims.Events[BackchannelLogoutEvent] == nil || claims.SID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid logout token"})
		return
	}
	g.mu.Lock()
	g.revoked[claims.SID] = true
	g.mu.Unlock()

	slog.Info("back-channel logout received", "app", g.appID, "user", claims.Subject, "sid", claims.SID)
	c.JSON(http.StatusOK, gin.H{"revoked_sid": claims.SID})
}

// parse verifies signature (RS256), issuer, audience and expiry.
func (g *AppGuard) parse(raw string, claims jwt.Claims) (*jwt.Token, error) {
	return jwt.ParseWithClaims(raw, claims, g.keys.Keyfunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(g.issuer),
		jwt.WithAudience(g.appID),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
	)
}
