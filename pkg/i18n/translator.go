// Package i18n provides the locale-aware Translator interface used across
// the Auth module to keep user-facing strings out of source literals per
// CONST-046 (No-Hardcoded-Content). The package ships a NoopTranslator
// default that returns the bundle key verbatim — keeping the module fully
// decoupled (CONST-051(B)) and standalone-testable while letting consuming
// projects inject a real LLM- / catalogue-backed translator at runtime.
//
// Contract:
//   - Bundle keys for this module are prefixed `auth_` (e.g.
//     `auth_apikey_expired`, `auth_apikey_not_found`).
//   - Args are positional and OPTIONAL; a NoopTranslator concatenates
//     them with the key separated by ASCII unit-separator so the literal
//     remains debuggable in test output without baking English in.
//   - SetGlobal / Global expose a process-wide handle for call sites
//     that cannot accept a Translator parameter directly (existing
//     stdlib-error returns in tight scopes). New code SHOULD accept
//     a Translator parameter explicitly.
package i18n

import (
	"strings"
	"sync"
)

// Translator resolves a bundle key + positional arguments into the
// caller-locale string. Implementations live in the consuming project
// (i18n catalogues, LLM-backed translation services, etc.); this module
// stays project-not-aware per CONST-051(B).
type Translator interface {
	// T resolves the key + args into the locale-appropriate string.
	// Returning the key verbatim on miss is acceptable; panicking
	// on miss is forbidden (call sites use this in error paths).
	T(key string, args ...string) string
}

// NoopTranslator is the zero-config default. It returns the key (with
// args concatenated via ASCII unit-separator) so production code can
// safely default to this implementation without leaking English text.
// Consuming projects swap it for a real backend via SetGlobal.
type NoopTranslator struct{}

// T returns the key verbatim, with args joined by `\x1f` (ASCII unit
// separator) — chosen so test assertions can still find the args
// without falsely matching natural-language separators.
func (NoopTranslator) T(key string, args ...string) string {
	if len(args) == 0 {
		return key
	}
	var b strings.Builder
	b.Grow(len(key) + len(args)*8)
	b.WriteString(key)
	for _, a := range args {
		b.WriteByte(0x1f)
		b.WriteString(a)
	}
	return b.String()
}

var (
	globalMu sync.RWMutex
	global   Translator = NoopTranslator{}
)

// SetGlobal installs the process-wide Translator. Safe for concurrent
// use; the consuming project calls this once at startup.
func SetGlobal(t Translator) {
	if t == nil {
		t = NoopTranslator{}
	}
	globalMu.Lock()
	global = t
	globalMu.Unlock()
}

// Global returns the currently-installed Translator. Defaults to
// NoopTranslator{}.
func Global() Translator {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return global
}

// T is a package-level shorthand for `Global().T(key, args...)`.
func T(key string, args ...string) string {
	return Global().T(key, args...)
}
