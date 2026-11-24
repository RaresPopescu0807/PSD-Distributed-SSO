#!/usr/bin/env bash
# Console demo of single sign-on and single logout. Start the services first
# (docker compose up --build -d  or  ./scripts/run-local.sh), then run:
#   ./scripts/demo.sh
set -uo pipefail

IDP=http://localhost:8080
CATALOG=http://localhost:8081
LIBRARY=http://localhost:8082
FORUM=http://localhost:8083

step() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
show() { printf '\033[2m$ %s\033[0m\n' "$(echo "$*" | sed -E 's/eyJ[A-Za-z0-9._-]+/<token>/g')"; "$@"; echo; }
api()  { curl -s -w '  [HTTP %{http_code}]' "$@"; }
token_of() { grep -o '"access_token": *"[^"]*"' | cut -d'"' -f4; }

step "1. Call an application without a token -> 401"
show api "$CATALOG/me"

step "2. Log in ONCE at the SSO server as bob (professor)"
RESPONSE=$(curl -s -X POST "$IDP/login" -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"bob123"}')
echo "$RESPONSE"
TOKEN=$(printf '%s' "$RESPONSE" | token_of)
AUTH="Authorization: Bearer $TOKEN"

step "3. The same token works in all three applications"
show api -H "$AUTH" "$CATALOG/grades"
show api -H "$AUTH" -X POST "$CATALOG/grades" -d '{"student":"alice","course":"Security","value":10}'
show api -H "$AUTH" -X POST "$LIBRARY/books/2/borrow"
show api -H "$AUTH" -X POST "$FORUM/posts" -d '{"title":"Hello","body":"Posted with the SSO token"}'

step "4. A student cannot add grades (roles come from the token) -> 403"
STUDENT=$(curl -s -X POST "$IDP/login" -d '{"username":"alice","password":"alice123"}' | token_of)
show api -H "Authorization: Bearer $STUDENT" -X POST "$CATALOG/grades" -d '{"student":"alice","course":"X","value":10}'

step "5. Log out at the SSO server -> it notifies every application"
show api -H "$AUTH" -X POST "$IDP/logout"

step "6. The token is now rejected everywhere -> 401"
show api -H "$AUTH" "$CATALOG/me"
show api -H "$AUTH" "$LIBRARY/me"
show api -H "$AUTH" "$FORUM/me"
