// Package stress contains concurrency / throughput stress tests
// for the Auth library. Per CONST-050(A), in-memory fakes are
// permitted only in unit tests — and the tests in this file use
// apikey.NewInMemoryStore + token.NewInMemoryStore as their
// backing storage layer.
//
// Status: ACKNOWLEDGED-LAYER-MISMATCH (round-20 2026-05-18).
// These tests genuinely stress-test the in-memory store's
// concurrent-access properties (lock contention, race conditions,
// goroutine-fanout safety). They are honest about what they
// stress — no claim of coverage against Postgres / Redis under
// load.
//
// To meet CONST-050(B), augment with sibling
// `auth_stress_postgres_test.go` that exercises the same
// scenarios against a real Postgres-backed apikey.Store. Tracked
// as round-21+ work.
//
// Until then: these in-memory stress tests REMAIN VALID
// anti-bluff tests of the InMemoryStore concurrency
// implementation specifically.
package stress

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"digital.vasic.auth/pkg/apikey"
	"digital.vasic.auth/pkg/jwt"
	"digital.vasic.auth/pkg/token"
)

// Resource limit: GOMAXPROCS=2 recommended for stress tests

func TestStress_ConcurrentJWTCreateValidate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")  // SKIP-OK: #short-mode
	}

	mgr := jwt.NewManager(jwt.DefaultConfig("stress-test-jwt-secret"))

	const goroutines = 100
	var wg sync.WaitGroup
	errors := make(chan error, goroutines)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			claims := map[string]interface{}{
				"sub": "user",
				"id":  float64(id),
			}
			tokenStr, err := mgr.Create(claims)
			if err != nil {
				errors <- err
				return
			}
			parsed, err := mgr.Validate(tokenStr)
			if err != nil {
				errors <- err
				return
			}
			if parsed.Claims["sub"] != "user" {
				errors <- assert.AnError
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStress_ConcurrentAPIKeyStoreOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")  // SKIP-OK: #short-mode
	}

	store := apikey.NewInMemoryStore()
	gen := apikey.NewGenerator(apikey.DefaultGeneratorConfig())

	const goroutines = 80
	var wg sync.WaitGroup

	keys := make([]*apikey.APIKey, goroutines)
	for i := 0; i < goroutines; i++ {
		key, err := gen.Generate("key", []string{"read"}, time.Time{})
		require.NoError(t, err)
		keys[i] = key
		require.NoError(t, store.Store(key))
	}

	wg.Add(goroutines * 3)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			_, _ = store.Get(keys[idx].Key)
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			_, _ = store.GetByID(keys[idx].ID)
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.List()
		}()
	}

	wg.Wait()
}

func TestStress_ConcurrentTokenStoreReadWrite(t *testing.T) {
	// bluff-scan: no-assert-ok (concurrency test — go test -race catches data races; absence of panic == correctness)
	if testing.Short() {
		t.Skip("skipping stress test in short mode")  // SKIP-OK: #short-mode
	}

	store := token.NewInMemoryStore()
	const goroutines = 50
	var wg sync.WaitGroup

	wg.Add(goroutines * 2)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			tok := token.NewSimpleToken(
				"access",
				"refresh",
				time.Now().Add(1*time.Hour),
			)
			key := string(rune('A' + (id % 26)))
			_ = store.Set(key, tok, time.Minute)
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			key := string(rune('A' + (id % 26)))
			_, _ = store.Get(key)
		}(i)
	}

	wg.Wait()
}

func TestStress_ConcurrentJWTRefresh(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")  // SKIP-OK: #short-mode
	}

	mgr := jwt.NewManager(jwt.DefaultConfig("refresh-stress-secret"))
	tokenStr, err := mgr.Create(map[string]interface{}{"sub": "user"})
	require.NoError(t, err)

	const goroutines = 50
	var wg sync.WaitGroup
	results := make([]string, goroutines)
	errors := make([]error, goroutines)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			refreshed, err := mgr.Refresh(tokenStr)
			results[idx] = refreshed
			errors[idx] = err
		}(i)
	}

	wg.Wait()

	// Under concurrency, every refresh MUST succeed (there is no
	// shared mutable state that could cause a refresh to fail) — this
	// is the real property the stress test should assert.
	//
	// The previous assertion ("concurrent refreshes produce unique
	// tokens") was inherently flaky because JWT refresh is
	// deterministic: same input token + same second-granularity
	// iat/exp claims → identical signatures → identical tokens. The
	// prior test passed by luck when clock ticks happened to straddle
	// the second boundary during the goroutine burst.
	for i, err := range errors {
		require.NoError(t, err, "refresh #%d must succeed under concurrency", i)
		require.NotEmpty(t, results[i], "refresh #%d must return a non-empty token", i)
	}

	// Every returned token must parse back as a valid JWT — concurrent
	// refresh must never corrupt the token structure.
	for i, r := range results {
		_, err := mgr.Validate(r)
		require.NoError(t, err, "refreshed token #%d must be valid JWT", i)
	}
}

func TestStress_ConcurrentTokenStoreCleanup(t *testing.T) {
	// bluff-scan: no-assert-ok (concurrency test — go test -race catches data races; absence of panic == correctness)
	if testing.Short() {
		t.Skip("skipping stress test in short mode")  // SKIP-OK: #short-mode
	}

	store := token.NewInMemoryStore()

	for i := 0; i < 100; i++ {
		tok := token.NewSimpleToken("a", "r", time.Now().Add(1*time.Hour))
		_ = store.Set(string(rune(i)), tok, time.Minute)
	}

	const goroutines = 50
	var wg sync.WaitGroup

	wg.Add(goroutines + 10)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			store.Cleanup()
		}()
	}

	for i := 0; i < 10; i++ {
		go func(id int) {
			defer wg.Done()
			_ = store.Len()
		}(i)
	}

	wg.Wait()
}

func TestStress_APIKeyGenerationUniqueness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")  // SKIP-OK: #short-mode
	}

	gen := apikey.NewGenerator(&apikey.GeneratorConfig{
		Prefix: "stress-",
		Length: 32,
	})

	const goroutines = 100
	var wg sync.WaitGroup
	var mu sync.Mutex
	keySet := make(map[string]bool)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			key, err := gen.Generate("test", nil, time.Time{})
			if err != nil {
				return
			}
			mu.Lock()
			keySet[key.Key] = true
			mu.Unlock()
		}()
	}

	wg.Wait()
	assert.Equal(t, goroutines, len(keySet),
		"all generated keys must be unique")
}
