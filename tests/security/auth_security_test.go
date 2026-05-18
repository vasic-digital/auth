// Package security contains security-property tests for the Auth
// library. The tests in this file currently use apikey.NewInMemoryStore
// and token.NewInMemoryStore as the backing storage layer — per
// CONST-050(A), in-memory fakes are permitted only in unit tests.
//
// Status: ACKNOWLEDGED-LAYER-MISMATCH (round-20 2026-05-18).
// These tests genuinely verify the in-memory store's security
// properties (duplicate-key rejection, expired-key handling,
// token revocation, JWT tamper detection via real JWT manager,
// httptest-driven middleware behaviour). They are honest about
// what they test — none of them claim coverage of Postgres /
// Redis-backed store security.
//
// To meet CONST-050(B) full test-type coverage, this file should
// be augmented with a sibling `auth_security_postgres_test.go`
// that exercises the same scenarios against a real Postgres-
// backed apikey.Store (and similar for Redis-backed token.Store).
// Tracked as round-21+ work — listed in this submodule's CLAUDE.md
// follow-up section once added.
//
// For now: these in-memory tests REMAIN VALID anti-bluff tests of
// the InMemoryStore implementation specifically. A reader scanning
// `tests/security/` for "real-infra security audit" should also
// look for the (currently missing) postgres/redis variants.
package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"digital.vasic.auth/pkg/apikey"
	"digital.vasic.auth/pkg/jwt"
	"digital.vasic.auth/pkg/middleware"
	"digital.vasic.auth/pkg/oauth"
	"digital.vasic.auth/pkg/token"
)

func TestSecurity_JWTTamperDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping security test in short mode")  // SKIP-OK: #short-mode
	}

	mgr := jwt.NewManager(jwt.DefaultConfig("security-test-secret-key"))
	tokenStr, err := mgr.Create(map[string]interface{}{"sub": "user"})
	require.NoError(t, err)

	parts := strings.Split(tokenStr, ".")
	require.Len(t, parts, 3)

	tampered := parts[0] + "." + parts[1] + ".TAMPERED_SIGNATURE"
	_, err = mgr.Validate(tampered)
	assert.Error(t, err)

	if len(parts[1]) > 5 {
		modifiedPayload := parts[0] + "." + parts[1][:len(parts[1])-3] + "xxx." + parts[2]
		_, err = mgr.Validate(modifiedPayload)
		assert.Error(t, err)
	}
}

func TestSecurity_JWTWrongSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping security test in short mode")  // SKIP-OK: #short-mode
	}

	mgr1 := jwt.NewManager(jwt.DefaultConfig("secret-one"))
	mgr2 := jwt.NewManager(jwt.DefaultConfig("secret-two"))

	tokenStr, err := mgr1.Create(map[string]interface{}{"sub": "user"})
	require.NoError(t, err)

	_, err = mgr2.Validate(tokenStr)
	assert.Error(t, err)
}

func TestSecurity_EmptyAndMalformedTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping security test in short mode")  // SKIP-OK: #short-mode
	}

	mgr := jwt.NewManager(jwt.DefaultConfig("test-secret"))

	invalidTokens := []string{
		"",
		"not-a-jwt",
		"a.b",
		"a.b.c.d",
		"eyJhbGciOiJIUzI1NiJ9..SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		strings.Repeat("A", 10000),
	}

	for _, tok := range invalidTokens {
		_, err := mgr.Validate(tok)
		assert.Error(t, err, "token should be rejected: %q", tok)
	}
}

func TestSecurity_BearerTokenInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping security test in short mode")  // SKIP-OK: #short-mode
	}

	validator := &alwaysRejectValidator{}
	mw := middleware.BearerToken(validator)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	injections := []string{
		"",
		"Basic dXNlcjpwYXNz",
		"Bearer ",
		"Bearer\t",
		"Bearer " + strings.Repeat("A", 100000),
	}

	for _, authHeader := range injections {
		req := httptest.NewRequest("GET", "/", nil)
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code,
			"should reject Authorization: %q", authHeader)
	}
}

type alwaysRejectValidator struct{}

func (v *alwaysRejectValidator) ValidateToken(_ string) (map[string]interface{}, error) {
	return nil, assert.AnError
}

func TestSecurity_APIKeyStoreDeduplication(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping security test in short mode")  // SKIP-OK: #short-mode
	}

	store := apikey.NewInMemoryStore()
	key := &apikey.APIKey{
		ID:        "id-1",
		Key:       "ak-duplicate-key",
		Name:      "first",
		Scopes:    []string{"read"},
		CreatedAt: time.Now(),
	}

	require.NoError(t, store.Store(key))

	duplicate := &apikey.APIKey{
		ID:        "id-2",
		Key:       "ak-duplicate-key",
		Name:      "second",
		Scopes:    []string{"admin"},
		CreatedAt: time.Now(),
	}

	err := store.Store(duplicate)
	assert.Error(t, err)
	// CONST-046: assert on i18n bundle key, not English literal.
	assert.Contains(t, err.Error(), "auth_apikey_already_exists")

	retrieved, err := store.Get("ak-duplicate-key")
	require.NoError(t, err)
	assert.Equal(t, "first", retrieved.Name)
	assert.Equal(t, []string{"read"}, retrieved.Scopes)
}

func TestSecurity_ExpiredAPIKeyRejection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping security test in short mode")  // SKIP-OK: #short-mode
	}

	store := apikey.NewInMemoryStore()
	expired := &apikey.APIKey{
		ID:        "id-expired",
		Key:       "ak-expired-key",
		Name:      "expired",
		Scopes:    []string{"read"},
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	require.NoError(t, store.Store(expired))

	_, err := apikey.Validate(store, "ak-expired-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestSecurity_OAuthEmptyAccessToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping security test in short mode")  // SKIP-OK: #short-mode
	}

	creds := &oauth.Credentials{
		AccessToken: "",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	_ = creds

	refresher := oauth.NewHTTPTokenRefresher(nil, "", nil)
	_, err := refresher.Refresh("", "http://example.com/token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no refresh token")
}

func TestSecurity_TokenStoreRevokedAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping security test in short mode")  // SKIP-OK: #short-mode
	}

	store := token.NewInMemoryStore()
	tok := token.NewSimpleToken("access", "refresh", time.Now().Add(1*time.Hour))

	require.NoError(t, store.Set("key", tok, 0))
	require.NoError(t, store.Revoke("key"))

	_, err := store.Get("key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")

	err = store.Revoke("nonexistent")
	assert.Error(t, err)

	err = store.Delete("nonexistent")
	assert.Error(t, err)
}

func TestSecurity_NilClaimsCreation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping security test in short mode")  // SKIP-OK: #short-mode
	}

	mgr := jwt.NewManager(jwt.DefaultConfig("nil-claims-test"))

	tokenStr, err := mgr.Create(nil)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenStr)

	parsed, err := mgr.Validate(tokenStr)
	require.NoError(t, err)
	assert.NotNil(t, parsed.Claims)
}
