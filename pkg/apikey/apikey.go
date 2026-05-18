// Package apikey provides API key generation, validation, and storage
// for authenticating API clients. It supports configurable key prefixes,
// lengths, scopes, and pluggable storage backends.
package apikey

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"digital.vasic.auth/pkg/i18n"
)

// APIKey represents an API key with its metadata.
type APIKey struct {
	// ID is the unique identifier for this API key.
	ID string

	// Key is the full API key string including prefix.
	Key string

	// Name is a human-readable name for this API key.
	Name string

	// Scopes is the list of permission scopes granted to this key.
	Scopes []string

	// ExpiresAt is the optional expiration time. Zero means no expiration.
	ExpiresAt time.Time

	// CreatedAt is the time the key was created.
	CreatedAt time.Time
}

// IsExpired returns true if the API key has expired.
func (k *APIKey) IsExpired() bool {
	if k.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(k.ExpiresAt)
}

// HasScope returns true if the API key has the given scope.
func (k *APIKey) HasScope(scope string) bool {
	for _, s := range k.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAllScopes returns true if the API key has all the given scopes.
func (k *APIKey) HasAllScopes(scopes []string) bool {
	for _, scope := range scopes {
		if !k.HasScope(scope) {
			return false
		}
	}
	return true
}

// GeneratorConfig holds configuration for API key generation.
type GeneratorConfig struct {
	// Prefix is prepended to generated keys (e.g., "sk-", "pk-").
	Prefix string

	// Length is the number of random bytes used (hex-encoded result
	// will be twice this length).
	Length int
}

// DefaultGeneratorConfig returns a GeneratorConfig with sensible
// defaults: "ak-" prefix and 32-byte key length.
func DefaultGeneratorConfig() *GeneratorConfig {
	return &GeneratorConfig{
		Prefix: "ak-",
		Length: 32,
	}
}

// Generator creates new API keys with configurable prefix and length.
type Generator struct {
	config *GeneratorConfig
}

// NewGenerator creates a new Generator with the given configuration.
func NewGenerator(config *GeneratorConfig) *Generator {
	if config == nil {
		config = DefaultGeneratorConfig()
	}
	return &Generator{config: config}
}

// randReader is the random reader used by Generate. Exposed for testing.
var randReader = rand.Reader

// Generate creates a new API key with the given name, scopes, and
// optional expiration. Returns the full APIKey struct including the
// generated key string.
func (g *Generator) Generate(
	name string, scopes []string, expiresAt time.Time,
) (*APIKey, error) {
	randomBytes := make([]byte, g.config.Length)
	if _, err := randReader.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	key := g.config.Prefix + hex.EncodeToString(randomBytes)

	return &APIKey{
		ID:        uuid.New().String(),
		Key:       key,
		Name:      name,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}, nil
}

// KeyStore provides an interface for pluggable API key storage backends.
type KeyStore interface {
	// Store saves an API key. Returns an error if the key already exists.
	Store(key *APIKey) error

	// Get retrieves an API key by its key string. Returns an error if
	// not found.
	Get(keyString string) (*APIKey, error)

	// GetByID retrieves an API key by its ID. Returns an error if not
	// found.
	GetByID(id string) (*APIKey, error)

	// Delete removes an API key by its key string.
	Delete(keyString string) error

	// List returns all stored API keys.
	List() ([]*APIKey, error)
}

// Validate checks if the given key string is valid by looking it up
// in the store and checking expiration.
func Validate(store KeyStore, keyString string) (*APIKey, error) {
	key, err := store.Get(keyString)
	if err != nil {
		return nil, fmt.Errorf("invalid API key: %w", err)
	}

	if key.IsExpired() {
		// CONST-046: user-facing text via Translator (bundle key `auth_apikey_expired`).
		return nil, errors.New(i18n.T("auth_apikey_expired"))
	}

	return key, nil
}

// InMemoryStore is a thread-safe in-memory implementation of KeyStore.
type InMemoryStore struct {
	mu    sync.RWMutex
	byKey map[string]*APIKey
	byID  map[string]*APIKey
}

// NewInMemoryStore creates a new InMemoryStore.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		byKey: make(map[string]*APIKey),
		byID:  make(map[string]*APIKey),
	}
}

// Store saves an API key. Returns an error if the key already exists.
func (s *InMemoryStore) Store(key *APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byKey[key.Key]; exists {
		// CONST-046: bundle key `auth_apikey_already_exists` + opaque key arg.
		return errors.New(i18n.T("auth_apikey_already_exists", key.Key))
	}

	s.byKey[key.Key] = key
	s.byID[key.ID] = key
	return nil
}

// Get retrieves an API key by its key string.
func (s *InMemoryStore) Get(keyString string) (*APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.byKey[keyString]
	if !ok {
		// CONST-046: bundle key `auth_apikey_not_found`.
		return nil, errors.New(i18n.T("auth_apikey_not_found"))
	}
	return key, nil
}

// GetByID retrieves an API key by its ID.
func (s *InMemoryStore) GetByID(id string) (*APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.byID[id]
	if !ok {
		// CONST-046: bundle key `auth_apikey_not_found_for_id` + opaque id arg.
		return nil, errors.New(i18n.T("auth_apikey_not_found_for_id", id))
	}
	return key, nil
}

// Delete removes an API key by its key string.
func (s *InMemoryStore) Delete(keyString string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, ok := s.byKey[keyString]
	if !ok {
		// CONST-046: bundle key `auth_apikey_not_found_for_delete` + opaque key arg.
		return errors.New(i18n.T("auth_apikey_not_found_for_delete", keyString))
	}

	delete(s.byKey, keyString)
	delete(s.byID, key.ID)
	return nil
}

// List returns all stored API keys.
func (s *InMemoryStore) List() ([]*APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]*APIKey, 0, len(s.byKey))
	for _, key := range s.byKey {
		keys = append(keys, key)
	}
	return keys, nil
}

// MaskKey returns a masked version of the API key for display purposes,
// showing only the prefix and last 4 characters.
func MaskKey(key string) string {
	if len(key) <= 8 {
		return strings.Repeat("*", len(key))
	}
	// Find prefix (up to first dash after prefix)
	prefixEnd := 0
	for i, c := range key {
		if c == '-' {
			prefixEnd = i + 1
			break
		}
	}
	if prefixEnd == 0 {
		prefixEnd = 3
	}

	// Handle edge case where prefix is too close to end
	maskLen := len(key) - prefixEnd - 4
	if maskLen < 0 {
		// Not enough room for prefix + mask + suffix
		// Just mask everything after short prefix
		return key[:min(3, len(key))] + strings.Repeat("*", max(0, len(key)-3))
	}

	masked := key[:prefixEnd] +
		strings.Repeat("*", maskLen) +
		key[len(key)-4:]
	return masked
}
