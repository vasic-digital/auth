package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestE2E_FullAuthenticationPipeline(t *testing.T) {
	// Article XI §11.5 classification: this test wraps the JWT
	// bearer-token middleware in an httptest.NewServer to exercise
	// it exactly as a downstream consumer would (the middleware IS
	// HTTP middleware — there is no separate "real Auth service"
	// to point at; the library is the unit under test, and httptest
	// is its canonical integration harness). Therefore httptest is
	// the real-system-under-test, NOT a bluff stand-in for an
	// external service. The bluff ledger entry below is for the
	// scanner's file-level exemption of the line-level finding.
	//
	// SKIP-OK: #BLUFF-AUTH-E2E-001 — httptest.NewServer is the
	// correct integration harness for an HTTP middleware library
	// (no external service exists to point at). Reclassify this
	// file under tests/integration/ in a follow-up to remove the
	// scanner ambiguity. Real-system path: pkg/middleware exposes
	// BearerToken which is exercised by every downstream consumer's
	// own e2e suite (catalog-api, HelixLLM, …) — those tests cover
	// the wider integration boundary.
	if testing.Short() {
		t.Skip("skipping e2e test in short mode") // SKIP-OK: #short-mode
	}

	jwtMgr := jwt.NewManager(&jwt.Config{
		SigningMethod: jwt.DefaultConfig("x").SigningMethod,
		Secret:        []byte("e2e-test-secret-for-jwt-signing!"),
		Expiration:    30 * time.Minute,
		Issuer:        "helix-e2e",
	})

	tokenStr, err := jwtMgr.Create(map[string]interface{}{
		"sub":    "e2e-user",
		"scopes": []string{"read", "write"},
	})
	require.NoError(t, err)

	validator := &jwtValidator{mgr: jwtMgr}
	mw := middleware.Chain(
		middleware.BearerToken(validator),
		middleware.RequireScopes("read"),
	)

	protectedHandler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFromContext(r.Context())
		resp := map[string]interface{}{
			"user":    claims["sub"],
			"message": "access granted",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))

	mux := http.NewServeMux()
	mux.Handle("/api/protected", protectedHandler)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL+"/api/protected", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokenStr)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "e2e-user", body["user"])
	assert.Equal(t, "access granted", body["message"])
}

type jwtValidator struct {
	mgr *jwt.Manager
}

func (v *jwtValidator) ValidateToken(tokenStr string) (map[string]interface{}, error) {
	tok, err := v.mgr.Validate(tokenStr)
	if err != nil {
		return nil, err
	}
	return tok.Claims, nil
}

func TestE2E_APIKeyProtectedEndpoint(t *testing.T) {
	// SKIP-OK: #BLUFF-AUTH-E2E-001 — see TestE2E_FullAuthenticationPipeline.
	if testing.Short() {
		t.Skip("skipping e2e test in short mode") // SKIP-OK: #short-mode
	}

	gen := apikey.NewGenerator(apikey.DefaultGeneratorConfig())
	store := apikey.NewInMemoryStore()

	key, err := gen.Generate("e2e-service", []string{"api:read", "api:write"}, time.Time{})
	require.NoError(t, err)
	require.NoError(t, store.Store(key))

	keyValidator := &apiKeyValidator{store: store}
	mw := middleware.Chain(
		middleware.APIKeyHeader(keyValidator, "X-API-Key"),
		middleware.RequireScopes("api:read"),
	)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scopes := middleware.ScopesFromContext(r.Context())
		json.NewEncoder(w).Encode(map[string]interface{}{
			"scopes": scopes,
		})
	}))

	srv := httptest.NewServer(handler)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("X-API-Key", key.Key)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	req2, _ := http.NewRequest("GET", srv.URL, nil)
	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

type apiKeyValidator struct {
	store apikey.KeyStore
}

func (v *apiKeyValidator) ValidateKey(keyStr string) ([]string, error) {
	key, err := apikey.Validate(v.store, keyStr)
	if err != nil {
		return nil, err
	}
	return key.Scopes, nil
}

func TestE2E_TokenRefreshCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")  // SKIP-OK: #short-mode
	}

	mgr := jwt.NewManager(&jwt.Config{
		SigningMethod: jwt.DefaultConfig("x").SigningMethod,
		Secret:        []byte("refresh-cycle-secret-key-123456!"),
		Expiration:    5 * time.Minute,
		Issuer:        "helix",
	})

	original, err := mgr.Create(map[string]interface{}{
		"sub":  "refresh-user",
		"role": "viewer",
	})
	require.NoError(t, err)

	current := original
	for i := 0; i < 5; i++ {
		refreshed, err := mgr.Refresh(current)
		require.NoError(t, err)
		require.NotEmpty(t, refreshed, "refresh #%d must return a non-empty token", i)

		// Note: don't assert inequality between `current` and `refreshed`.
		// JWT refresh is deterministic — same input token + same
		// second-granularity iat/exp claims produce identical signatures.
		// The real invariants are (1) refresh succeeds, (2) the output
		// validates, (3) claims round-trip correctly.
		tok, err := mgr.Validate(refreshed)
		require.NoError(t, err)
		assert.Equal(t, "refresh-user", tok.Claims["sub"])
		assert.Equal(t, "viewer", tok.Claims["role"])

		current = refreshed
	}
}

func TestE2E_OAuthCredentialLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")  // SKIP-OK: #short-mode
	}

	creds := &oauth.Credentials{
		AccessToken:  "initial-access-token",
		RefreshToken: "initial-refresh-token",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Scopes:       []string{"read", "write"},
		Metadata: map[string]interface{}{
			"provider": "test-oauth",
		},
	}

	assert.False(t, creds.IsExpired())
	assert.False(t, creds.NeedsRefresh(5*time.Minute))
	assert.True(t, creds.NeedsRefresh(2*time.Hour))

	expiredCreds := &oauth.Credentials{
		AccessToken: "expired-token",
		ExpiresAt:   time.Now().Add(-1 * time.Minute),
	}
	assert.True(t, expiredCreds.IsExpired())
	assert.True(t, oauth.IsExpired(expiredCreds.ExpiresAt))
	assert.True(t, oauth.NeedsRefresh(expiredCreds.ExpiresAt, 0))
}

func TestE2E_TokenStoreCompleteLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")  // SKIP-OK: #short-mode
	}

	store := token.NewInMemoryStore()

	tokens := make([]*token.SimpleToken, 10)
	for i := 0; i < 10; i++ {
		tokens[i] = token.NewSimpleToken(
			"access-"+string(rune('A'+i)),
			"refresh-"+string(rune('A'+i)),
			time.Now().Add(time.Duration(i+1)*time.Minute),
		)
		require.NoError(t, store.Set(
			"key-"+string(rune('A'+i)),
			tokens[i],
			0,
		))
	}
	assert.Equal(t, 10, store.Len())

	retrieved, err := store.Get("key-A")
	require.NoError(t, err)
	assert.Equal(t, "access-A", retrieved.AccessToken())

	require.NoError(t, store.Delete("key-A"))
	assert.Equal(t, 9, store.Len())

	_, err = store.Get("key-A")
	assert.Error(t, err)

	require.NoError(t, store.Revoke("key-B"))
	_, err = store.Get("key-B")
	assert.Error(t, err)
	assert.Equal(t, 9, store.Len())
}

func TestE2E_MaskedKeyDisplay(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")  // SKIP-OK: #short-mode
	}

	gen := apikey.NewGenerator(&apikey.GeneratorConfig{
		Prefix: "sk-",
		Length: 32,
	})

	key, err := gen.Generate("display-test", nil, time.Time{})
	require.NoError(t, err)

	masked := apikey.MaskKey(key.Key)
	assert.Contains(t, masked, "sk-")
	assert.Contains(t, masked, "****")
	assert.True(t, len(masked) == len(key.Key))
	last4 := key.Key[len(key.Key)-4:]
	assert.Contains(t, masked, last4)
}
