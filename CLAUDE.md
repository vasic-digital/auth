# CLAUDE.md - Auth Module

## INHERITED FROM constitution/CLAUDE.md

All rules in `constitution/CLAUDE.md` (and the `constitution/Constitution.md` it references) apply unconditionally. This file's rules below extend them — they MUST NOT weaken any inherited rule. See parent root `CLAUDE.md` §6.AD for the Lava-specific incorporation context (29th §6.L cycle, 2026-05-14) and §6.AD-debt for the implementation-gap inventory. Use `constitution/find_constitution.sh` from the parent project root to resolve the absolute path of the submodule from any nested location.

## INHERITED FROM the Helix Constitution

This module is governed by the Helix Constitution. All rules in the
constitution's `CLAUDE.md` and the `Constitution.md` it references apply
unconditionally. Locate the constitution from any nested depth via its
`find_constitution.sh` helper — do NOT hardcode a path (this module stays
fully decoupled and project-agnostic per §11.4.28).

Canonical reference: https://github.com/HelixDevelopment/HelixConstitution

## Overview

`digital.vasic.auth` is a generic, reusable Go module for authentication and authorization, providing JWT management, API key authentication, OAuth2 credential management, HTTP middleware, and token utilities.

**Module**: `digital.vasic.auth` (Go 1.24+)

### Acceptance demo for this module

```bash
# JWT create/validate/refresh, API-key generate/validate, OAuth auto-refresh, HTTP middleware
cd Auth && GOMAXPROCS=2 nice -n 19 go test -count=1 -race -v ./tests/integration/...
```
Expect: PASS; exercises `jwt.NewManager`, `apikey.NewGenerator`, `oauth.NewAutoRefresher`, and `middleware.BearerToken/APIKeyHeader` per `Auth/README.md` Quick Start.

## Build & Test

```bash
go build ./...
go test ./... -count=1 -race
go test ./... -short              # Unit tests only
go test -bench=. ./...            # Benchmarks
go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out
```

## Code Style

- Standard Go conventions, `gofmt` formatting
- Imports grouped: stdlib, third-party, internal (blank line separated)
- Line length <= 100 chars
- Naming: `camelCase` private, `PascalCase` exported, acronyms all-caps
- Errors: always check, wrap with `fmt.Errorf("...: %w", err)`
- Tests: table-driven, `testify`, naming `Test<Struct>_<Method>_<Scenario>`

## Package Structure

| Package | Purpose |
|---------|---------|
| `pkg/jwt` | JWT token creation, validation, and refresh |
| `pkg/apikey` | API key generation, validation, and storage |
| `pkg/oauth` | Generic OAuth2 credential reading, token refresh, auto-refresh |
| `pkg/middleware` | HTTP auth middleware (Bearer, API key, scopes, chaining) |
| `pkg/token` | Token interface, Claims map, in-memory store with TTL |

## Key Interfaces

- `token.Token` - Generic token with access/refresh/expiry
- `token.Store` - Token storage (Get, Set, Delete, Revoke)
- `oauth.CredentialReader` - Read OAuth2 credentials by provider name
- `oauth.TokenRefresher` - Refresh OAuth2 tokens via endpoint
- `apikey.KeyStore` - Pluggable API key storage backend
- `middleware.TokenValidator` - Validate bearer tokens
- `middleware.APIKeyValidator` - Validate API keys

## Dependencies

- `github.com/golang-jwt/jwt/v5` - JWT parsing and signing
- `github.com/google/uuid` - UUID generation for API key IDs
- `github.com/stretchr/testify` - Test assertions

## Commit Style

Conventional Commits: `feat(jwt): add RS256 signing support`

## Integration Seams

| Direction | Sibling modules |
|-----------|-----------------|
| Upstream (this module imports) | none |
| Downstream (these import this module) | HelixLLM |

*Siblings* means other project-owned modules at the parent project's repo root. The root project app and external systems are not listed here — the list above is intentionally scoped to module-to-module seams, because drift *between* sibling modules is where the "tests pass, product broken" class of bug most often lives. See root `CLAUDE.md` for the rules that keep these seams contract-tested.
