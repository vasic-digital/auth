package apikey

import (
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errorReader is a reader that always returns an error.
type errorReaderForRand struct {
	err error
}

func (e *errorReaderForRand) Read(_ []byte) (int, error) {
	return 0, e.err
}

func TestAPIKey_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(time.Hour),
			expected:  false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().Add(-time.Hour),
			expected:  true,
		},
		{
			name:      "zero time never expires",
			expiresAt: time.Time{},
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &APIKey{ExpiresAt: tt.expiresAt}
			assert.Equal(t, tt.expected, key.IsExpired())
		})
	}
}

func TestAPIKey_HasScope(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		scope    string
		expected bool
	}{
		{
			name:     "has scope",
			scopes:   []string{"read", "write"},
			scope:    "read",
			expected: true,
		},
		{
			name:     "missing scope",
			scopes:   []string{"read"},
			scope:    "write",
			expected: false,
		},
		{
			name:     "empty scopes",
			scopes:   nil,
			scope:    "read",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &APIKey{Scopes: tt.scopes}
			assert.Equal(t, tt.expected, key.HasScope(tt.scope))
		})
	}
}

func TestAPIKey_HasAllScopes(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		required []string
		expected bool
	}{
		{
			name:     "has all",
			scopes:   []string{"read", "write", "admin"},
			required: []string{"read", "write"},
			expected: true,
		},
		{
			name:     "missing one",
			scopes:   []string{"read"},
			required: []string{"read", "write"},
			expected: false,
		},
		{
			name:     "empty required",
			scopes:   []string{"read"},
			required: []string{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &APIKey{Scopes: tt.scopes}
			assert.Equal(t, tt.expected, key.HasAllScopes(tt.required))
		})
	}
}

func TestGenerator_Generate(t *testing.T) {
	tests := []struct {
		name      string
		config    *GeneratorConfig
		keyName   string
		scopes    []string
		expiresAt time.Time
	}{
		{
			name:      "default config",
			config:    nil,
			keyName:   "test-key",
			scopes:    []string{"read", "write"},
			expiresAt: time.Now().Add(24 * time.Hour),
		},
		{
			name:      "custom prefix",
			config:    &GeneratorConfig{Prefix: "sk-", Length: 16},
			keyName:   "secret-key",
			scopes:    []string{"admin"},
			expiresAt: time.Time{},
		},
		{
			name:      "no scopes",
			config:    DefaultGeneratorConfig(),
			keyName:   "basic-key",
			scopes:    nil,
			expiresAt: time.Time{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewGenerator(tt.config)
			key, err := gen.Generate(tt.keyName, tt.scopes, tt.expiresAt)
			require.NoError(t, err)

			assert.NotEmpty(t, key.ID)
			assert.NotEmpty(t, key.Key)
			assert.Equal(t, tt.keyName, key.Name)
			assert.Equal(t, tt.scopes, key.Scopes)
			assert.Equal(t, tt.expiresAt, key.ExpiresAt)
			assert.False(t, key.CreatedAt.IsZero())

			// Verify prefix
			cfg := tt.config
			if cfg == nil {
				cfg = DefaultGeneratorConfig()
			}
			assert.True(t, strings.HasPrefix(key.Key, cfg.Prefix))
		})
	}
}

func TestGenerator_Generate_Uniqueness(t *testing.T) {
	gen := NewGenerator(nil)
	keys := make(map[string]bool)

	for i := 0; i < 100; i++ {
		key, err := gen.Generate("test", nil, time.Time{})
		require.NoError(t, err)
		assert.False(t, keys[key.Key], "duplicate key generated")
		keys[key.Key] = true
	}
}

func TestValidate(t *testing.T) {
	store := NewInMemoryStore()
	gen := NewGenerator(nil)

	// Generate and store a valid key
	validKey, err := gen.Generate(
		"valid", []string{"read"}, time.Now().Add(time.Hour),
	)
	require.NoError(t, err)
	require.NoError(t, store.Store(validKey))

	// Generate and store an expired key
	expiredKey, err := gen.Generate(
		"expired", []string{"read"}, time.Now().Add(-time.Hour),
	)
	require.NoError(t, err)
	require.NoError(t, store.Store(expiredKey))

	tests := []struct {
		name       string
		keyString  string
		wantErr    bool
		errContain string
	}{
		{
			name:      "valid key",
			keyString: validKey.Key,
			wantErr:   false,
		},
		{
			name:       "expired key",
			keyString:  expiredKey.Key,
			wantErr:    true,
			errContain: "expired",
		},
		{
			name:       "nonexistent key",
			keyString:  "ak-nonexistent",
			wantErr:    true,
			errContain: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := Validate(store, tt.keyString)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContain)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, key)
			}
		})
	}
}

func TestInMemoryStore_Store(t *testing.T) {
	store := NewInMemoryStore()
	key := &APIKey{
		ID:   "id-1",
		Key:  "ak-test123",
		Name: "test",
	}

	err := store.Store(key)
	require.NoError(t, err)

	// Duplicate should fail. CONST-046: assert on the i18n bundle key
	// (`auth_apikey_already_exists`), not on hardcoded English text.
	// The Noop translator (default) surfaces the key verbatim, which
	// keeps this test stable across locale backends.
	err = store.Store(key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auth_apikey_already_exists")
	assert.Contains(t, err.Error(), "ak-test123")
}

func TestInMemoryStore_Get(t *testing.T) {
	store := NewInMemoryStore()
	key := &APIKey{
		ID:   "id-1",
		Key:  "ak-test123",
		Name: "test",
	}
	require.NoError(t, store.Store(key))

	got, err := store.Get("ak-test123")
	require.NoError(t, err)
	assert.Equal(t, "test", got.Name)

	_, err = store.Get("nonexistent")
	assert.Error(t, err)
}

func TestInMemoryStore_GetByID(t *testing.T) {
	store := NewInMemoryStore()
	key := &APIKey{
		ID:   "id-1",
		Key:  "ak-test123",
		Name: "test",
	}
	require.NoError(t, store.Store(key))

	got, err := store.GetByID("id-1")
	require.NoError(t, err)
	assert.Equal(t, "test", got.Name)

	_, err = store.GetByID("nonexistent")
	assert.Error(t, err)
}

func TestInMemoryStore_Delete(t *testing.T) {
	store := NewInMemoryStore()
	key := &APIKey{
		ID:   "id-1",
		Key:  "ak-test123",
		Name: "test",
	}
	require.NoError(t, store.Store(key))

	err := store.Delete("ak-test123")
	require.NoError(t, err)

	_, err = store.Get("ak-test123")
	assert.Error(t, err)

	_, err = store.GetByID("id-1")
	assert.Error(t, err)

	// Delete nonexistent
	err = store.Delete("nonexistent")
	assert.Error(t, err)
}

func TestInMemoryStore_List(t *testing.T) {
	store := NewInMemoryStore()

	keys, err := store.List()
	require.NoError(t, err)
	assert.Empty(t, keys)

	for i := 0; i < 3; i++ {
		key := &APIKey{
			ID:   "id-" + string(rune('0'+i)),
			Key:  "ak-key" + string(rune('0'+i)),
			Name: "key-" + string(rune('0'+i)),
		}
		require.NoError(t, store.Store(key))
	}

	keys, err = store.List()
	require.NoError(t, err)
	assert.Len(t, keys, 3)
}

func TestMaskKey(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{
			name:     "standard key",
			key:      "ak-abcdef1234567890",
			expected: "ak-************7890",
		},
		{
			name:     "short key",
			key:      "short",
			expected: "*****",
		},
		{
			name:     "sk prefix",
			key:      "sk-1234567890abcdef",
			expected: "sk-************cdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			masked := MaskKey(tt.key)
			assert.Equal(t, tt.expected, masked)
		})
	}
}

func TestMaskKey_NoDash(t *testing.T) {
	// Test key without dash prefix (prefixEnd will be 0, then set to 3)
	key := "1234567890abcdef"
	masked := MaskKey(key)

	// Should show first 3 chars, mask middle, show last 4
	assert.Equal(t, "123*********cdef", masked)
}

func TestMaskKey_ExactlyEightChars(t *testing.T) {
	// Test key with exactly 8 characters (edge case)
	key := "12345678"
	masked := MaskKey(key)

	// Should return all asterisks
	assert.Equal(t, "********", masked)
}

func TestMaskKey_NineChars(t *testing.T) {
	// Test key with 9 characters (just over 8)
	key := "123456789"
	masked := MaskKey(key)

	// prefixEnd will be 0 (no dash), then set to 3
	// First 3: "123", last 4: "6789", middle: 2 chars
	assert.Equal(t, "123**6789", masked)
}

func TestMaskKey_DashAtEnd(t *testing.T) {
	// Test key with dash at end
	key := "abcdefghij-"
	masked := MaskKey(key)

	// prefixEnd should be 11 (position after the dash)
	// This will cause the mask to be negative, which is handled
	assert.NotEmpty(t, masked)
}

func TestGenerator_Generate_RandReadError(t *testing.T) {
	// Save the original randReader
	origReader := randReader
	defer func() { randReader = origReader }()

	// Replace with error reader
	randReader = &errorReaderForRand{err: errors.New("random source unavailable")}

	gen := NewGenerator(nil)
	key, err := gen.Generate("test", []string{"read"}, time.Time{})

	require.Error(t, err)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "failed to generate random bytes")
	assert.Contains(t, err.Error(), "random source unavailable")
}

func TestGenerator_Generate_RestoreRandReader(t *testing.T) {
	// Verify that randReader is still the default after previous test
	// This ensures the defer worked correctly
	gen := NewGenerator(nil)
	key, err := gen.Generate("restore-test", []string{"read"}, time.Time{})
	require.NoError(t, err)
	assert.NotNil(t, key)
}

// Ensure we use the standard crypto/rand.Reader by default
var _ io.Reader = rand.Reader
