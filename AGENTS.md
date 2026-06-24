# AGENTS.md - Auth Module Multi-Agent Coordination

## INHERITED FROM constitution/AGENTS.md

All rules in `constitution/AGENTS.md` (and the `constitution/Constitution.md` it references) apply unconditionally. This file's rules below extend them — they MUST NOT weaken any inherited rule. See parent root `CLAUDE.md` §6.AD for the Lava-specific incorporation context (29th §6.L cycle, 2026-05-14) and §6.AD-debt for the implementation-gap inventory. Use `constitution/find_constitution.sh` from the parent project root to resolve the absolute path of the submodule from any nested location.

## INHERITED FROM the Helix Constitution

This module is governed by the Helix Constitution. All rules in the
constitution's `AGENTS.md` and the `Constitution.md` it references apply
unconditionally. Locate the constitution from any nested depth via its
`find_constitution.sh` helper — do NOT hardcode a path (this module stays
fully decoupled and project-agnostic per §11.4.28).

Canonical reference: https://github.com/HelixDevelopment/HelixConstitution

## Module Identity

- **Module**: `digital.vasic.auth`
- **Role**: Generic authentication and authorization library
- **Packages**: `jwt`, `apikey`, `oauth`, `middleware`, `token`
- **Go Version**: 1.24+

## Agent Responsibilities

### Auth Agent

The Auth agent owns all five packages in this module. It is responsible for:

1. **Token Abstractions** (`pkg/token`) -- Defines the core `Token` interface, `Claims` map type, `Store` interface, `InMemoryStore`, and `SimpleToken` implementation. This is the foundational package that other packages depend on.

2. **JWT Management** (`pkg/jwt`) -- Handles JWT creation, validation, and refresh using `github.com/golang-jwt/jwt/v5`. Provides `Manager` with configurable `Config` (signing method, secret, expiration, issuer).

3. **API Key Management** (`pkg/apikey`) -- Generates cryptographically random API keys with configurable prefixes and lengths. Provides `KeyStore` interface, `InMemoryStore`, validation, and key masking.

4. **OAuth2 Credential Management** (`pkg/oauth`) -- Reads OAuth2 credentials from files, refreshes tokens via HTTP endpoints, and auto-refreshes with caching and rate limiting. Core types: `CredentialReader`, `TokenRefresher`, `AutoRefresher`.

5. **HTTP Middleware** (`pkg/middleware`) -- Provides `BearerToken`, `APIKeyHeader`, `RequireScopes`, and `Chain` middleware for standard `net/http` handlers. Stores validated claims, scopes, and API keys in request context.

## Cross-Agent Coordination

### Upstream Consumers

Any service that imports `digital.vasic.auth` should coordinate with the Auth agent when:

- Adding a new authentication scheme or token type
- Changing the `Token`, `Store`, `KeyStore`, `CredentialReader`, `TokenRefresher`, `TokenValidator`, or `APIKeyValidator` interfaces
- Modifying context key constants (`ClaimsKey`, `ScopesKey`, `APIKeyKey`)
- Changing JWT claim semantics or signing algorithms

### Integration Points

| Consumer | Package Used | Purpose |
|----------|-------------|---------|
| The consuming project | `middleware`, `jwt`, `apikey` | HTTP endpoint authentication |
| LLMsVerifier | `oauth` | Provider OAuth2 credential management |
| CLI tools | `apikey` | API key generation and validation |

## Conventions

### Interface Ownership

Each interface has a single owning package:

| Interface | Owner Package | Implementors |
|-----------|--------------|-------------|
| `token.Token` | `pkg/token` | `token.SimpleToken`, external types |
| `token.Store` | `pkg/token` | `token.InMemoryStore`, external stores |
| `apikey.KeyStore` | `pkg/apikey` | `apikey.InMemoryStore`, external stores |
| `oauth.CredentialReader` | `pkg/oauth` | `oauth.FileCredentialReader`, external readers |
| `oauth.TokenRefresher` | `pkg/oauth` | `oauth.HTTPTokenRefresher`, external refreshers |
| `middleware.TokenValidator` | `pkg/middleware` | JWT adapters, external validators |
| `middleware.APIKeyValidator` | `pkg/middleware` | API key adapters, external validators |

### Dependency Direction

```
middleware --> token (context keys, claims)
middleware --> (consumers implement TokenValidator, APIKeyValidator)
jwt       --> (standalone, no internal deps)
apikey    --> (standalone, no internal deps)
oauth     --> (standalone, no internal deps)
token     --> (foundation, no deps)
```

Packages do not import each other. Each is independently usable. The `middleware` package uses context keys of type `contextKey` (unexported) and provides accessor functions (`ClaimsFromContext`, `ScopesFromContext`, `APIKeyFromContext`).

### Testing Standards

- Table-driven tests using `testify`
- Test naming: `Test<Struct>_<Method>_<Scenario>`
- Race detection: `go test -race ./...`
- No mocks in integration or E2E tests
- All exported functions and methods must have test coverage

### Error Handling

- All errors are wrapped with `fmt.Errorf("...: %w", err)` for chain inspection
- Middleware returns JSON error responses with appropriate HTTP status codes
- Token store operations return descriptive errors (not found, revoked, expired)

## Communication Protocol

When modifying this module, agents must:

1. Run `go test ./... -count=1 -race` before proposing changes
2. Verify no breaking changes to exported interfaces
3. Update CLAUDE.md if package structure or key interfaces change
4. Follow conventional commits: `feat(jwt): ...`, `fix(oauth): ...`, etc.
5. Ensure backward compatibility -- interface changes require a major version bump
