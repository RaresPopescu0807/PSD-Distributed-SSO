// Package sso is all the single sign-on code:
//
//	server.go     the SSO server: login, logout, signs the tokens
//	app_guard.go  used by every application to accept those tokens
//	tokens.go     what both sides share: token content and endpoint paths
package sso

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/golang-jwt/jwt/v5"
)

// BackchannelLogoutEvent marks a logout token (OpenID Connect Back-Channel Logout).
const BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// Paths shared by the services.
const (
	PathJWKS              = "/.well-known/jwks.json"   // public key of the SSO server
	PathBackchannelLogout = "/auth/backchannel-logout" // logout notification, on every app
)

// Claims is the content of the access token issued at login. The same token
// is accepted by every application listed in its audience ("aud").
type Claims struct {
	jwt.RegisteredClaims
	SID   string   `json:"sid"` // SSO session ID, used to revoke the token at logout
	Name  string   `json:"name"`
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// LogoutClaims is the content of the logout token sent by the SSO server
// to each application when an SSO session ends.
type LogoutClaims struct {
	jwt.RegisteredClaims
	SID    string                    `json:"sid"`
	Events map[string]map[string]any `json:"events"`
}

// randomString returns a URL-safe string encoding n random bytes.
func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
