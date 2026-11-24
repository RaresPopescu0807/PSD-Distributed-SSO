# Sistem Single Sign-On pentru trei aplicații distribuite

Implementare în Go a unui sistem **Single Sign-On (SSO)** cu patru servicii
independente, fiecare în containerul lui. Toate expun doar **API-uri JSON**,
apelabile din Postman sau din consolă (`curl`).

| Serviciu     | Port | Rol                                                     |
|--------------|------|---------------------------------------------------------|
| `sso-server` | 8080 | Serverul central de autentificare (Identity Provider)   |
| `catalog`    | 8081 | Aplicația 1: catalog de note                            |
| `library`    | 8082 | Aplicația 2: bibliotecă (împrumut/returnare cărți)      |
| `forum`      | 8083 | Aplicația 3: forum (postări)                            |

**Ideea:** utilizatorul se autentifică **o singură dată** la `sso-server` și
primește un token. Același token este acceptat de toate cele trei aplicații.
La logout, serverul SSO **anunță toate aplicațiile**, care resping apoi token-ul.

## Cum funcționează

```text
Postman/curl         sso-server            catalog         library          forum
      |                   |                   |               |               |
      |- POST /login ---->|                   |               |               |
      |< access_token ----|                   |               |               |
      |                   |                   |               |               |
  -- the same token in every app --
      |- GET /grades (Bearer token) --------->|               |               |
      |                   |< GET jwks.json ---|               |               |       (first time)
      |< 200 OK ------------------------------|               |               |
      |- POST /books/2/borrow (same token) ------------------>|               |
      |< 200 OK ----------------------------------------------|               |
      |- POST /posts (same token) ------------------------------------------->|
      |< 201 Created ---------------------------------------------------------|
      |                   |                   |               |               |
  -- single logout --
      |- POST /logout --->|                   |               |               |
      |                   |- logout_token --->|               |               |
      |                   |- logout_token ------------------->|               |
      |                   |- logout_token ----------------------------------->|
      |< apps_notified ---|                   |               |               |
      |- GET /me (same token) ----------------------------------------------->|
      |< 401 logged out ------------------------------------------------------|
```

1. **Login.** `sso-server` verifică parola (stocată cu **bcrypt**) și emite un
   **JWT semnat cu cheia privată RSA**. Token-ul conține utilizatorul, rolurile,
   un ID de sesiune (`sid`), expirarea (1 oră) și lista aplicațiilor care îl
   acceptă (`aud`).
2. **Verificare distribuită.** Aplicațiile nu întreabă serverul SSO la fiecare
   cerere. Ele descarcă o singură dată **cheia publică**
   (`/.well-known/jwks.json`) și verifică local semnătura, emitentul (`iss`),
   audiența (`aud`) și expirarea (`exp`). Nimeni nu poate falsifica un token fără
   cheia privată, care există doar pe serverul SSO.
3. **Autorizare.** Fiecare aplicație decide ce poate face utilizatorul pe baza
   rolurilor din token (de exemplu, doar `professor` poate adăuga note).
4. **Single logout.** `POST /logout` închide sesiunea și trimite în paralel
   fiecărei aplicații un **logout token semnat** cu `sid`-ul sesiunii.
   Aplicațiile rețin `sid`-ul ca revocat și resping token-ul, chiar dacă nu a
   expirat încă. O notificare falsă (nesemnată de serverul SSO) este refuzată.

## API

**sso-server** (`:8080`)

| Metodă | Cale                     | Body / Header                           |
|--------|--------------------------|-----------------------------------------|
| POST   | `/login`                 | `{"username":"bob","password":"bob123"}` |
| POST   | `/logout`                | `Authorization: Bearer <token>`          |
| GET    | `/.well-known/jwks.json` | cheia publică                            |

**Toate aplicațiile** au `GET /me`, care întoarce utilizatorul din token.
Toate cererile către aplicații cer header-ul `Authorization: Bearer <token>`.

| Aplicație | Metodă | Cale                   | Observații                                  |
|-----------|--------|------------------------|---------------------------------------------|
| catalog   | GET    | `/grades`              | studentul își vede notele, profesorul pe toate |
| catalog   | POST   | `/grades`              | `{"student":"alice","course":"...","value":10}`, doar profesor |
| library   | GET    | `/books`               |                                             |
| library   | POST   | `/books/{id}/borrow`   |                                             |
| library   | POST   | `/books/{id}/return`   | cel care a împrumutat sau admin             |
| forum     | GET    | `/posts`               |                                             |
| forum     | POST   | `/posts`               | `{"title":"...","body":"..."}`              |
| forum     | DELETE | `/posts/{id}`          | autorul sau admin                           |

## Conturi demo

| Utilizator | Parolă     | Roluri           |
|------------|------------|------------------|
| `alice`    | `alice123` | student          |
| `carol`    | `carol123` | student          |
| `bob`      | `bob123`   | professor        |
| `admin`    | `admin123` | admin, professor |

Conturile sunt definite în [services/sso-server/main.go](services/sso-server/main.go), cu
parola în clar. La pornire, serverul calculează hash-ul bcrypt al fiecărei
parole și păstrează în memorie doar hash-ul. Pentru un cont nou adaugi o linie
în lista `users`.

## Biblioteci folosite

Go nu are în biblioteca standard un framework de autentificare. Proiectul
combină câteva pachete consacrate, fiecare cu un singur rol:

| Pachet | Rol |
|---|---|
| `golang.org/x/crypto/bcrypt` | hash-uirea și verificarea parolelor (întreținut de echipa Go) |
| `github.com/gin-gonic/gin` | framework web: rutare, răspunsuri JSON, validarea datelor, logging |
| `github.com/golang-jwt/jwt/v5` | crearea, semnarea și verificarea token-urilor JWT |
| `github.com/MicahParks/jwkset` | publicarea cheii publice a serverului SSO în format JWKS |
| `github.com/MicahParks/keyfunc/v3` | descărcarea, cache-ul și reîmprospătarea cheii publice în aplicații |

Codul scris de mână se ocupă doar de SSO: sesiunile, emiterea token-urilor,
verificarea lor în aplicații și back-channel logout-ul.

## Rulare

Cu Docker (fiecare serviciu în container separat):

```bash
docker compose up --build -d
```

Sau local, fără Docker:

```bash
./scripts/run-local.sh
```

Oprire Docker:

```bash
docker compose down
```

## Demo

**Din consolă**, scriptul rulează tot scenariul (login, apeluri în cele trei
aplicații, verificarea rolurilor, logout și respingerea token-ului):

```bash
./scripts/demo.sh
```

**Din Postman:** *Import* → `postman/sso-demo.postman_collection.json`, apoi
rulezi request-urile din folderele 1 → 6. Request-ul *Login as bob* salvează
automat token-ul în variabila `{{token}}`, pe care o folosesc toate celelalte.

Ce urmărești în demo:

1. `GET /me` fără token → **401**.
2. Login o singură dată → primești `access_token`.
3. Același token merge în **catalog**, **library** și **forum**.
4. Studentul `alice` primește **403** când încearcă să adauge o notă.
5. `POST /logout` → răspunsul arată `apps_notified` cu `ok` pentru fiecare aplicație.
6. Același token → **401** în toate aplicațiile.

Ca să vezi mesajele `back-channel logout` schimbate între servicii:

```bash
docker compose logs -f
```

## Teste

```bash
go test -race ./...
```

`sso/sso_test.go` pornește serverul SSO și două aplicații pe servere HTTP
separate și verifică: parolă greșită → 401, cerere fără token → 401, același
token acceptat de ambele aplicații, logout cu notificarea ambelor aplicații,
respingerea token-ului după logout, respingerea unui token modificat și a unei
notificări de logout false.

## Structura proiectului

```
services/                 programele care rulează (câte unul pe port)
  sso-server/main.go      serverul SSO (:8080) + conturile demo
  catalog/main.go         aplicația 1, note (:8081)
  library/main.go         aplicația 2, bibliotecă (:8082)
  forum/main.go           aplicația 3, forum (:8083)
sso/                      tot codul de single sign-on
  server.go               serverul SSO: login, logout, semnează token-urile
  app_guard.go            folosit de fiecare aplicație: verifică token-ul, primește logout-ul
  tokens.go               ce au în comun: conținutul token-urilor, căile
  sso_test.go             teste end-to-end
postman/                  colecția Postman
scripts/                  run-local.sh, demo.sh
```

## Limitări

* Datele (note, cărți, postări, sesiuni) sunt ținute în memorie și se pierd la
  repornire. Serverul SSO generează la fiecare pornire o cheie de semnare nouă,
  deci după o repornire toate token-urile vechi devin invalide și utilizatorii
  trebuie să se logheze din nou.
* Dacă o aplicație este oprită în momentul logout-ului, ea nu primește
  notificarea și acceptă token-ul până la expirare (maximum 1 oră). Răspunsul
  de la `/logout` arată ce aplicații nu au putut fi anunțate.
* Fiind un demo, comunicarea se face prin HTTP; în producție toate serviciile
  ar trebui să ruleze pe HTTPS.
