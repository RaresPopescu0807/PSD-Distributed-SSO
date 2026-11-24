// Command sso-server runs the central SSO server on :8080.
//
// Environment variables:
//
//	ISSUER_URL  "iss" claim of the tokens        (default "http://localhost:8080")
//	APPS        applications to notify at logout (default local ports 8081-8083)
package main

import (
	"cmp"
	"log"
	"os"

	"psd/sso"
)

// users are the accounts of the system. The passwords are hashed with bcrypt
// when the server starts; only the hashes are kept in memory.
var users = []struct {
	username, password, name, email string
	roles                           []string
}{
	{"alice", "alice123", "Alice Ionescu", "alice@university.example", []string{"student"}},
	{"carol", "carol123", "Carol Dumitrescu", "carol@university.example", []string{"student"}},
	{"bob", "bob123", "Bob Marinescu", "bob@university.example", []string{"professor"}},
	{"admin", "admin123", "Administrator", "admin@university.example", []string{"admin", "professor"}},
}

func main() {
	apps, err := sso.ParseApps(cmp.Or(os.Getenv("APPS"),
		"catalog=http://localhost:8081,library=http://localhost:8082,forum=http://localhost:8083"))
	if err != nil {
		log.Fatal(err)
	}
	srv, err := sso.NewServer(cmp.Or(os.Getenv("ISSUER_URL"), "http://localhost:8080"), apps)
	if err != nil {
		log.Fatal(err)
	}
	for _, u := range users {
		if err := srv.AddUser(u.username, u.password, u.name, u.email, u.roles...); err != nil {
			log.Fatal(err)
		}
	}
	log.Fatal(srv.Router().Run(":8080"))
}
