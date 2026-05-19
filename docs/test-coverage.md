# Auth — Test Coverage Ledger (round-248)

Round-248 deep-doc ledger for the `digital.vasic.auth` Go module.

> Verbatim 2026-05-19 operator mandate (Article XI §11.9, CONST-035):
> "all existing tests and Challenges do work in anti-bluff manner — they
> MUST confirm that all tested codebase really works as expected! We had
> been in position that all tests do execute with success and all
> Challenges as well, but in reality the most of the features does not
> work and can't be used! This MUST NOT be the case and execution of
> tests and Challenges MUST guarantee the quality, the completition
> and full usability by end users of the product!"
>
> (Single-line anchor for grep gate: execution of tests and Challenges MUST guarantee the quality, the completion and full usability by end users of the product!)

This document is the load-bearing cross-reference between the module's
exported surface and the test/Challenge coverage that proves each
symbol actually works for end users. Pair it with `challenges/scripts/
auth_describe_challenge.sh` which mechanically enforces freshness via
symbol-rename mutation (exit 99 = anti-bluff guard works).

---

## Exported surface (round-248 snapshot)

### `pkg/jwt`

| Symbol           | Kind   | Anti-bluff coverage |
|------------------|--------|----------------------|
| `Config`         | type   | `pkg/jwt/jwt_test.go` (TestDefaultConfig); runner exercises every field via `DefaultConfig` |
| `DefaultConfig`  | func   | TestDefaultConfig + runner (HS256 + 1h expiration verified end-to-end) |
| `Token`          | type   | TestManager_Validate_Valid populates every field; runner asserts byte-clean claims |
| `Parser`         | type   | TestManager_SetParser proves injection seam; default `defaultParser` exercised in every Validate path |
| `Manager`        | type   | Every Test* below + round-248 runner JWT cycle |
| `NewManager`     | func   | Every Manager test + runner |
| `SetParser`      | method | TestManager_SetParser |
| `Create`         | method | TestManager_Create* (12 scenarios incl. nil claims, Unicode usernames, RS256, expiration edges); runner 5-locale |
| `Validate`       | method | TestManager_Validate* (15 scenarios incl. expired, wrong-secret, wrong-method, extra whitespace, malformed); runner 5-locale |
| `Refresh`        | method | TestManager_Refresh* (4 scenarios); runner asserts custom-claim preservation across refresh |
| `Parse` (Parser) | method | exercised transitively via every Validate path |

### `pkg/apikey`

| Symbol                  | Kind   | Anti-bluff coverage |
|-------------------------|--------|----------------------|
| `APIKey`                | type   | TestAPIKey_* + runner (Name byte-preservation, Scopes round-trip) |
| `IsExpired`             | method | TestAPIKey_IsExpired (zero/past/future) |
| `HasScope`              | method | TestAPIKey_HasScope + runner (non-ASCII scopes) |
| `HasAllScopes`          | method | TestAPIKey_HasAllScopes + runner |
| `GeneratorConfig`       | type   | TestGenerator_Generate exercises Prefix + Length |
| `DefaultGeneratorConfig`| func   | TestGenerator_Generate (default-path) |
| `Generator`             | type   | TestGenerator_* + runner |
| `NewGenerator`          | func   | TestGenerator_Generate + runner (nil config defaults verified) |
| `Generate`              | method | TestGenerator_Generate{,_Uniqueness,_RandReadError,_RestoreRandReader} + runner |
| `KeyStore`              | type   | InMemoryStore satisfies; runner exercises via Validate(store,...) |
| `Validate` (pkg-level)  | func   | TestValidate (happy + expired); runner per-locale |
| `InMemoryStore`         | type   | TestInMemoryStore_* (Store/Get/GetByID/Delete/List) + runner population sanity |
| `NewInMemoryStore`      | func   | Every InMemoryStore test + runner |
| `Store`                 | method | TestInMemoryStore_Store + runner (duplicate-key path is i18n-bundled per CONST-046) |
| `Get`                   | method | TestInMemoryStore_Get + runner |
| `GetByID`               | method | TestInMemoryStore_GetByID |
| `Delete`                | method | TestInMemoryStore_Delete + runner store-population sanity |
| `List`                  | method | TestInMemoryStore_List + runner (asserts len == subject count) |
| `MaskKey`               | func   | TestMaskKey* (5 scenarios incl. no-dash, exact-8, 9-char, dash-at-end); runner per-locale render |

### `pkg/oauth`

| Symbol                   | Kind     | Anti-bluff coverage |
|--------------------------|----------|----------------------|
| `Credentials`            | type     | TestCredentials_IsExpired + TestCredentials_NeedsRefresh + integration tests |
| `IsExpired`              | method   | TestIsExpired + TestCredentials_IsExpired |
| `NeedsRefresh`           | method   | TestNeedsRefresh + TestCredentials_NeedsRefresh |
| `CredentialReader`       | type     | TestFileCredentialReader_ReadCredentials + integration |
| `ReadCredentials`        | method   | TestFileCredentialReader_ReadCredentials{,_ReadError} |
| `FileCredentialReader`   | type     | Same as above |
| `NewFileCredentialReader`| func     | Same as above |
| `TokenRefresher`         | type     | TestHTTPTokenRefresher_Refresh* — 8 scenarios incl. network error, invalid endpoint, body-read error, no client ID, no expires-in, extra params |
| `Refresh`                | method   | Same |
| `HTTPTokenRefresher`     | type     | Same |
| `NewHTTPTokenRefresher`  | func     | Same |
| `RefreshResponse`        | type     | Exercised via every Refresh test (JSON decode path) |
| `RoundTrip`              | method   | Exercised transitively via HTTPTokenRefresher tests |
| `Config`                 | type     | TestDefaultConfig_Values |
| `DefaultConfig`          | func     | TestDefaultConfig_Values |
| `AutoRefresher`          | type     | TestAutoRefresher_* — 10 scenarios incl. caching, expired-no-refresh, rate-limited, scope+metadata carryover |
| `NewAutoRefresher`       | func     | Same |
| `GetCredentials`         | method   | TestAutoRefresher_GetCredentials_* |
| `ClearCache`             | method   | TestAutoRefresher_ClearCache |
| `ClearCacheFor`          | method   | TestAutoRefresher_ClearCacheFor |
| `Close`                  | method   | Exercised in every AutoRefresher test (defer Close()) |
| `Read`                   | method   | Exercised via FileCredentialReader file-IO path |

### `pkg/middleware`

| Symbol               | Kind   | Anti-bluff coverage |
|----------------------|--------|----------------------|
| `Middleware`         | type   | Every BearerToken/APIKeyHeader/Chain test composes Middleware values |
| `TokenValidator`     | type   | TestBearerToken_* — Valid, ClaimsInContext, InvalidToken, InvalidScheme, MissingHeader, EmptyToken, ScopesExtraction (slice + non-slice) |
| `ValidateToken`      | method | Same |
| `APIKeyValidator`    | type   | TestAPIKeyHeader_* — Valid, InvalidKey, MissingHeader, ScopesAndKeyInContext |
| `ValidateKey`        | method | Same |
| `BearerToken`        | func   | TestBearerToken_* (8 scenarios) |
| `APIKeyHeader`       | func   | TestAPIKeyHeader_* (4 scenarios) |
| `RequireScopes`      | func   | TestRequireScopes_* — HasAll, MissingScope, NoScopes, InvalidScopesType (slice/int/map) |
| `Chain`              | func   | TestChain + TestChain_Empty + TestChain_FailsAtFirstMiddleware |
| `ClaimsFromContext`  | func   | TestClaimsFromContext_Empty + TestBearerToken_ClaimsInContext |
| `ScopesFromContext`  | func   | TestScopesFromContext_Empty + TestBearerToken_ScopesExtraction_ValidSlice |
| `APIKeyFromContext`  | func   | TestAPIKeyFromContext_Empty + TestAPIKeyHeader_ScopesAndKeyInContext |

### `pkg/token`

| Symbol            | Kind   | Anti-bluff coverage |
|-------------------|--------|----------------------|
| `Token`           | type   | TestSimpleToken_* (AccessToken, RefreshToken, ExpiresAt, IsExpired, NeedsRefresh) |
| `AccessToken`     | method | TestSimpleToken_AccessToken |
| `RefreshToken`    | method | TestSimpleToken_RefreshToken |
| `ExpiresAt`       | method | TestSimpleToken_ExpiresAt + TestClaims_ExpiresAt |
| `IsExpired`       | method | TestSimpleToken_IsExpired |
| `NeedsRefresh`    | method | TestSimpleToken_NeedsRefresh |
| `SimpleToken`     | type   | Every SimpleToken test |
| `NewSimpleToken`  | func   | Every SimpleToken test |
| `Claims`          | type   | TestClaims_* (Get, GetString, Subject, Audience, Issuer, IssuedAt, ExpiresAt) |
| `Get`             | method | TestClaims_Get + TestInMemoryStore_Get* |
| `GetString`       | method | TestClaims_GetString |
| `Subject`         | method | TestClaims_Subject |
| `Audience`        | method | TestClaims_Audience |
| `Issuer`          | method | TestClaims_Issuer |
| `IssuedAt`        | method | TestClaims_IssuedAt |
| `Store`           | type   | TestInMemoryStore_* (token-pkg store, separate from apikey) |
| `InMemoryStore`   | type   | TestInMemoryStore_SetAndGet, _Get_NotFound, _Get_Expired, _Get_ZeroTTL, _Delete, _Delete_NotFound, _Revoke, _Revoke_NotFound, _Cleanup, _Len |
| `NewInMemoryStore`| func   | Every InMemoryStore test |
| `Set`             | method | TestInMemoryStore_SetAndGet |
| `Delete`          | method | TestInMemoryStore_Delete{,_NotFound} |
| `Revoke`          | method | TestInMemoryStore_Revoke{,_NotFound} |
| `Cleanup`         | method | TestInMemoryStore_Cleanup (TTL eviction proven) |
| `Len`             | method | TestInMemoryStore_Len |

### `pkg/i18n`

| Symbol           | Kind   | Anti-bluff coverage |
|------------------|--------|----------------------|
| `Translator`     | type   | TestSetGlobal_CustomTranslatorIsCalled proves injection seam |
| `NoopTranslator` | type   | TestNoopTranslator_KeyOnly + TestNoopTranslator_KeyWithArgs + runner per-locale |
| `T` (Translator) | method | Same |
| `SetGlobal`      | func   | TestSetGlobal_CustomTranslatorIsCalled + TestSetGlobal_NilFallsBackToNoop |
| `Global`         | func   | TestGlobal_DefaultIsNoop + runner deterministic reset |
| `T` (pkg-level)  | func   | TestNoopTranslator_KeyWithArgs + runner (verbatim key+0x1F+arg) |
| `Hits`           | (other)| Exposed for translator-test instrumentation; cross-referenced via test |
| `TestMutation_NoopReturnsKey` | meta-test | Paired-mutation guard — proves NoopTranslator does NOT secretly translate |

---

## Round-248 anti-bluff guarantees

1. **Symbol cross-reference is mechanically enforced.** `auth_describe_challenge.sh` extracts every exported `func`/`type` from `pkg/{jwt,apikey,oauth,middleware,token,i18n}` and asserts each appears in THIS ledger by word-boundary match. Adding a new exported symbol without updating this ledger fails the gate (exit 1).
2. **Paired mutation proves the gate has teeth.** `auth_describe_challenge.sh --anti-bluff-mutate` plants a `MaskKey → MaskKeyBogus_MUTATED` rename in a tmp copy of this ledger, reruns validation, and asserts the gate FAILS with exit 99. A gate that exits 0 on the mutated ledger would be a CONST-035 bluff.
3. **The runner is a real Auth exerciser.** `challenges/runner/main.go` builds against the real `pkg/{jwt,apikey,i18n}` packages, exercises HMAC-SHA256 signing/verification, in-memory store concurrency primitives, and the NoopTranslator pass-through — no mocks, no stubs, no `// for now` placeholders (CONST-050(A)).
4. **Bilingual fixture proves UTF-8 byte-preservation.** `tests/fixtures/i18n/payloads.json` covers 5 locales (`en`, `sr` Cyrillic, `ja` Han, `ar` Arabic RTL, `zh-CN` Han) — every locale runs the full JWT create/validate/refresh + API key generate/store/retrieve + i18n pass-through cycle.
5. **Article XI §11.9 mandate carried verbatim.** This file opens with the 2026-05-19 operator quote; the describe challenge greps for the closing fragment to refuse PASS if the mandate is stripped.

---

## Test-type coverage (CONST-050(B))

| Test type     | Status | Evidence |
|---------------|--------|----------|
| Unit          | PASS   | `go test -race ./...` — 80+ test functions across 6 packages |
| Integration   | PASS   | `tests/integration/` middleware + JWT end-to-end |
| Security      | PASS   | `tests/security/` (auth_middleware_security path) |
| Stress        | PASS   | `tests/stress/` (sustained-load harness) |
| Benchmark     | PASS   | `tests/benchmark/` (per-pkg micro-benchmarks) |
| Challenges    | PASS   | `challenges/scripts/auth_*_challenge.sh` (11 scripts) + `auth_describe_challenge.sh` round-248 |
| Round-248 runner | PASS | `challenges/runner/main.go` — 16 PASS / 0 FAIL across 5 locales |

---

*Round-248 close-out: ledger generated 2026-05-19, mirrors EventBus round-245 / Database round-244 / Concurrency round-243 / Cache round-242 / round-220 pattern.*
