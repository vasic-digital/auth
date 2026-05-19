# Auth

Generic, reusable Go module for authentication and authorization.

**Module**: `digital.vasic.auth`

## Packages

- **pkg/jwt** — JWT token creation, validation, and refresh with configurable signing methods
- **pkg/apikey** — API key generation with configurable prefixes, validation, pluggable storage, scope helpers, and masking
- **pkg/oauth** — Generic OAuth2 credential management with file-based reading, HTTP token refresh, auto-refresh with caching and rate limiting
- **pkg/middleware** — HTTP authentication middleware for Bearer tokens, API keys, scope validation, and middleware chaining
- **pkg/token** — Token interface, Claims map with helpers, and in-memory store with TTL support and revocation
- **pkg/i18n** — Locale-aware Translator interface (CONST-046 compliant) — `NoopTranslator` default keeps the module fully decoupled and project-not-aware while consuming projects inject a real LLM- / catalogue-backed translator at runtime

## Installation

```bash
go get digital.vasic.auth
```

## Quick Start

### JWT Token Management

```go
import "digital.vasic.auth/pkg/jwt"

cfg := jwt.DefaultConfig("your-secret-key")
cfg.Issuer = "my-service"
manager := jwt.NewManager(cfg)

// Create a token
tokenStr, err := manager.Create(map[string]interface{}{
    "sub":  "user-123",
    "role": "admin",
})

// Validate a token
token, err := manager.Validate(tokenStr)
fmt.Println(token.Claims["sub"]) // "user-123"

// Refresh a token (preserves all custom claims)
newToken, err := manager.Refresh(tokenStr)
```

### API Key Authentication

```go
import "digital.vasic.auth/pkg/apikey"

gen := apikey.NewGenerator(&apikey.GeneratorConfig{
    Prefix: "sk-",
    Length: 32,
})

store := apikey.NewInMemoryStore()

key, err := gen.Generate("my-key", []string{"read", "write"}, time.Time{})
store.Store(key)

validated, err := apikey.Validate(store, key.Key)
masked := apikey.MaskKey(key.Key) // safe to display
```

### OAuth2 Credential Management

```go
import "digital.vasic.auth/pkg/oauth"

reader := oauth.NewFileCredentialReader(map[string]string{
    "github": "/path/to/github-creds.json",
})

refresher := oauth.NewHTTPTokenRefresher(nil, "client-id", nil)

ar := oauth.NewAutoRefresher(reader, refresher, nil, map[string]string{
    "github": "https://github.com/login/oauth/access_token",
})

creds, err := ar.GetCredentials("github")
```

### HTTP Middleware

```go
import "digital.vasic.auth/pkg/middleware"

// Bearer token authentication
handler := middleware.BearerToken(myValidator)(myHandler)

// API key authentication
handler := middleware.APIKeyHeader(myKeyValidator, "X-API-Key")(myHandler)

// Chain middleware
handler := middleware.Chain(
    middleware.BearerToken(myValidator),
    middleware.RequireScopes("read", "write"),
)(myHandler)
```

### i18n Pass-Through (CONST-046)

```go
import "digital.vasic.auth/pkg/i18n"

// Default: NoopTranslator returns key + 0x1F + args verbatim
// — bytes preserved, no English baked in.
msg := i18n.T("auth_apikey_expired") // "auth_apikey_expired"

// Consuming project swaps the global at startup:
i18n.SetGlobal(myCatalogueBackedTranslator)
```

## Testing

```bash
go test ./... -count=1 -race
```

## Round-248 — Deep-doc + Bilingual Anti-bluff Challenge

This round adds a paired-mutation deep-doc gate plus a real-Auth bilingual exerciser:

- `docs/test-coverage.md` — exhaustive symbol-to-test cross-reference ledger for every exported `func`/`type` across `pkg/{jwt,apikey,oauth,middleware,token,i18n}`.
- `tests/fixtures/i18n/payloads.json` — 5-locale fixture (`en`, `sr` Cyrillic, `ja` Han, `ar` Arabic RTL, `zh-CN` Han) carrying non-ASCII JWT subjects, claim roles, API key labels, and scopes.
- `challenges/runner/main.go` — real Auth exerciser. Per-locale: `jwt.Manager.Create + Validate + Refresh`, `apikey.Generator.Generate + InMemoryStore.Store + apikey.Validate + HasScope + HasAllScopes + MaskKey`, `i18n.NoopTranslator.T(key, arg)` pass-through. Asserts byte-equality on every round-trip.
- `challenges/scripts/auth_describe_challenge.sh` — mechanically enforces the ledger against the live source tree (every exported symbol must cross-reference) AND ships a paired `--anti-bluff-mutate` mode that plants a `MaskKey → MaskKeyBogus_MUTATED` rename in a tmp ledger copy, reruns the gate, and asserts exit 99.

### Anti-bluff guarantees (round-248)

1. **No metadata-only PASS.** Every `PASS` line in the runner output carries the actual JWT bytes, the actual stored API key ID + name, and the actual translator output observed — Article XI §11.9 forensic anchor compliance.
2. **Paired mutation proves the gate has teeth.** `bash challenges/scripts/auth_describe_challenge.sh --anti-bluff-mutate` MUST exit 99 — a 0 exit there would be a CONST-035 bluff.
3. **No mocks beyond unit tests.** The runner exercises real HMAC-SHA256, real `crypto/rand`, real `sync.RWMutex` in-memory store, real `golang-jwt/v5` parser — CONST-050(A) compliant.
4. **UTF-8 byte-preservation proven across 5 locales.** Cyrillic / Han / Arabic RTL / CJK all survive the full create/store/retrieve cycle byte-for-byte. A drift on any locale fails the gate.
5. **Decoupling preserved (CONST-051(B)).** The runner imports only `digital.vasic.auth/pkg/*` — no consuming-project hardcoding. `i18n.SetGlobal(NoopTranslator{})` resets to the project-not-aware default so the assertion is deterministic.

### Running round-248 locally

```bash
# Clean mode — expects exit 0
bash challenges/scripts/auth_describe_challenge.sh

# Paired-mutation mode — expects exit 99
bash challenges/scripts/auth_describe_challenge.sh --anti-bluff-mutate

# Runner directly
go run ./challenges/runner -fixtures tests/fixtures/i18n/payloads.json

# Race-detector unit + integration sweep
go test -count=1 -race ./...
```

## License

Proprietary - All rights reserved.
