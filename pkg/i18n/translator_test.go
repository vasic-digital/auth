package i18n

import (
	"strings"
	"sync"
	"testing"
)

func TestNoopTranslator_KeyOnly(t *testing.T) {
	tr := NoopTranslator{}
	if got := tr.T("auth_apikey_expired"); got != "auth_apikey_expired" {
		t.Fatalf("expected key verbatim, got %q", got)
	}
}

func TestNoopTranslator_KeyWithArgs(t *testing.T) {
	tr := NoopTranslator{}
	got := tr.T("auth_apikey_not_found_for_id", "abc-123")
	// Sentinel: key present, arg present, separator is unit-separator (not ASCII space).
	if !strings.Contains(got, "auth_apikey_not_found_for_id") {
		t.Fatalf("expected key in output, got %q", got)
	}
	if !strings.Contains(got, "abc-123") {
		t.Fatalf("expected arg in output, got %q", got)
	}
	if !strings.Contains(got, "\x1f") {
		t.Fatalf("expected ASCII unit-separator in output, got %q", got)
	}
	if strings.Contains(got, " ") {
		t.Fatalf("Noop output must not contain ASCII space (would leak English-ish format), got %q", got)
	}
}

func TestGlobal_DefaultIsNoop(t *testing.T) {
	// Reset to default before this test; other tests may have replaced it.
	SetGlobal(NoopTranslator{})
	if got := T("auth_token_expired"); got != "auth_token_expired" {
		t.Fatalf("default Global() must be NoopTranslator; got %q", got)
	}
}

func TestSetGlobal_NilFallsBackToNoop(t *testing.T) {
	SetGlobal(nil)
	if _, ok := Global().(NoopTranslator); !ok {
		t.Fatalf("nil SetGlobal must fall back to NoopTranslator, got %T", Global())
	}
}

// sentinelTranslator is a unit-test-only Translator that records every
// invocation so we can assert which keys call sites really emit. It
// proves the Translator hook is wired through, not a dead path.
type sentinelTranslator struct {
	mu   sync.Mutex
	hits []string
}

func (s *sentinelTranslator) T(key string, args ...string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits = append(s.hits, key)
	out := key
	for _, a := range args {
		out += "|" + a
	}
	return out
}

func (s *sentinelTranslator) Hits() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.hits))
	copy(out, s.hits)
	return out
}

func TestSetGlobal_CustomTranslatorIsCalled(t *testing.T) {
	st := &sentinelTranslator{}
	SetGlobal(st)
	t.Cleanup(func() { SetGlobal(NoopTranslator{}) })

	_ = T("auth_apikey_expired")
	_ = T("auth_apikey_not_found_for_id", "abc-123")

	hits := st.Hits()
	if len(hits) != 2 || hits[0] != "auth_apikey_expired" || hits[1] != "auth_apikey_not_found_for_id" {
		t.Fatalf("sentinel did not capture expected calls; got %v", hits)
	}
}

// TestMutation_NoopReturnsKey is the §1.1 paired mutation: if a future
// edit makes NoopTranslator.T return an empty string or a hardcoded
// English literal, this test fails. Documents the contract that the
// Noop default MUST surface the key unchanged so debugging is possible.
func TestMutation_NoopReturnsKey(t *testing.T) {
	tr := NoopTranslator{}
	key := "auth_mutation_canary_unique_key_xyz"
	out := tr.T(key)
	if out != key {
		t.Fatalf("mutation guard tripped: Noop must return key verbatim; got %q", out)
	}
	if out == "" {
		t.Fatalf("mutation guard tripped: Noop must never return empty")
	}
	// CONST-046 / CONST-035: detect any future English drift.
	for _, banned := range []string{"not found", "expired", "invalid", "missing"} {
		if strings.Contains(strings.ToLower(out), banned) {
			t.Fatalf("CONST-046 violation: Noop output leaked English phrase %q in %q", banned, out)
		}
	}
}
