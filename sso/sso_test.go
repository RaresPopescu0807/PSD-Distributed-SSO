// Package sso_test starts the SSO server and two applications on separate HTTP
// servers and checks single sign-on and single logout through their APIs.
package sso_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"psd/sso"
)

// lazy lets a server start before its handler exists (handlers need the URLs).
type lazy struct{ h http.Handler }

func (l *lazy) ServeHTTP(w http.ResponseWriter, r *http.Request) { l.h.ServeHTTP(w, r) }

type system struct{ ssoServer, app1, app2 string }

func start(t *testing.T) system {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := [3]*lazy{{}, {}, {}}
	var urls [3]string
	for i := range h {
		srv := httptest.NewServer(h[i])
		t.Cleanup(srv.Close)
		urls[i] = srv.URL
	}
	s := system{urls[0], urls[1], urls[2]}

	server, err := sso.NewServer(s.ssoServer, []sso.App{{ID: "app1", BaseURL: s.app1}, {ID: "app2", BaseURL: s.app2}})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.AddUser("alice", "alice123", "Alice", "alice@example.com", "student"); err != nil {
		t.Fatal(err)
	}
	h[0].h = server.Router()

	for i, id := range []string{"app1", "app2"} {
		guard, err := sso.NewAppGuard(id, s.ssoServer, s.ssoServer+sso.PathJWKS)
		if err != nil {
			t.Fatal(err)
		}
		r := gin.New()
		guard.Register(r)
		h[i+1].h = r
	}
	return s
}

func call(t *testing.T, method, url, token, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func login(t *testing.T, s system) string {
	t.Helper()
	status, body := call(t, "POST", s.ssoServer+"/login", "", `{"username":"alice","password":"alice123"}`)
	if status != http.StatusOK {
		t.Fatalf("login: %d %v", status, body)
	}
	return body["access_token"].(string)
}

func TestSingleSignOnAndLogout(t *testing.T) {
	s := start(t)

	if status, _ := call(t, "POST", s.ssoServer+"/login", "", `{"username":"alice","password":"wrong"}`); status != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d, want 401", status)
	}
	if status, _ := call(t, "GET", s.app1+"/me", "", ""); status != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", status)
	}

	// One login, the same token works in both applications.
	token := login(t, s)
	for _, app := range []string{s.app1, s.app2} {
		status, body := call(t, "GET", app+"/me", token, "")
		if status != http.StatusOK || body["user"].(map[string]any)["username"] != "alice" {
			t.Fatalf("%s/me: %d %v", app, status, body)
		}
	}

	// Logout at the SSO server notifies both applications...
	status, body := call(t, "POST", s.ssoServer+"/logout", token, "")
	if status != http.StatusOK {
		t.Fatalf("logout: %d %v", status, body)
	}
	notified := body["apps_notified"].(map[string]any)
	if notified["app1"] != "ok" || notified["app2"] != "ok" {
		t.Fatalf("apps not notified: %v", notified)
	}
	// ...which now reject the token although it has not expired.
	for _, app := range []string{s.app1, s.app2} {
		if status, _ := call(t, "GET", app+"/me", token, ""); status != http.StatusUnauthorized {
			t.Fatalf("%s accepted a logged-out token: %d", app, status)
		}
	}
	// A new login works again.
	if status, _ := call(t, "GET", s.app1+"/me", login(t, s), ""); status != http.StatusOK {
		t.Fatalf("after new login: %d", status)
	}
}

func TestForgedTokensAreRejected(t *testing.T) {
	s := start(t)
	token := login(t, s)

	// Tampered payload: the signature no longer matches.
	parts := strings.Split(token, ".")
	parts[1] = parts[1][:len(parts[1])-2] + "xx"
	if status, _ := call(t, "GET", s.app1+"/me", strings.Join(parts, "."), ""); status != http.StatusUnauthorized {
		t.Fatalf("tampered token: got %d", status)
	}

	// A fake back-channel logout (an access token instead of a logout token) is refused.
	resp, err := http.PostForm(s.app1+sso.PathBackchannelLogout, url.Values{"logout_token": {token}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("access token accepted as logout token: %d", resp.StatusCode)
	}
	if status, _ := call(t, "GET", s.app1+"/me", token, ""); status != http.StatusOK {
		t.Fatalf("session must still be valid: %d", status)
	}
}
