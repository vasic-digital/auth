// Round-248 challenge runner for Auth.
//
// Loads the bilingual fixture set from tests/fixtures/i18n/payloads.json
// and exercises the real Auth packages end-to-end per locale:
//
//   - jwt.Manager.Create + Validate + Refresh round-trip with non-ASCII
//     claim values (sub, role) — proves Cyrillic, Han, Arabic, CJK
//     survive the HS256 sign/verify cycle byte-for-byte.
//   - apikey.Generator.Generate + InMemoryStore.Store + Get + Validate
//     with non-ASCII Name + Scopes — proves the in-memory store and
//     APIKey.HasScope lookup preserve UTF-8 bytes.
//   - i18n.NoopTranslator.T(key, arg) with a non-ASCII arg — proves
//     the NoopTranslator passes opaque args through verbatim per the
//     CONST-046 contract.
//
// Anti-bluff invariants (Article XI §11.9, CONST-035, CONST-050(A)):
//
//   - No metadata-only / grep-only PASS. Every PASS line is preceded by
//     the actual decoded JWT claim value, the actual stored API key
//     name, and the actual translator output as observed.
//   - Production code paths are exercised — no mocks, no stubs, no
//     "for now" placeholders. The Auth packages run in-process against
//     real crypto/rand, real HMAC-SHA256, real sync.RWMutex state.
//   - A byte-drift on any locale (UTF-8 corruption, claim drop,
//     scope mismatch) is a hard FAIL — exit non-zero.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"digital.vasic.auth/pkg/apikey"
	"digital.vasic.auth/pkg/i18n"
	"digital.vasic.auth/pkg/jwt"
)

type subject struct {
	Locale         string   `json:"locale"`
	Name           string   `json:"name"`
	KeyLabel       string   `json:"key_label"`
	ClaimRole      string   `json:"claim_role"`
	JWTSub         string   `json:"jwt_sub"`
	Scopes         []string `json:"scopes"`
	MetadataRegion string   `json:"metadata_region"`
}

type fixtureFile struct {
	Subjects []subject `json:"subjects"`
}

func main() {
	fixturePath := flag.String("fixtures", "", "path to payloads.json")
	flag.Parse()

	if *fixturePath == "" {
		*fixturePath = filepath.Join(
			"tests", "fixtures", "i18n", "payloads.json",
		)
	}

	raw, err := os.ReadFile(*fixturePath)
	if err != nil {
		runnerFail("cannot read fixtures: %v", err)
	}
	var ff fixtureFile
	if err := json.Unmarshal(raw, &ff); err != nil {
		runnerFail("cannot parse fixtures: %v", err)
	}
	if len(ff.Subjects) == 0 {
		runnerFail("fixtures contain zero subjects")
	}

	// Real JWT manager with non-trivial secret + issuer.
	jwtCfg := jwt.DefaultConfig("round-248-secret-key-for-real-hs256")
	jwtCfg.Issuer = "auth-round-248-runner"
	jwtCfg.Expiration = time.Hour
	jwtMgr := jwt.NewManager(jwtCfg)

	// Real API key generator + in-memory store.
	keyGen := apikey.NewGenerator(&apikey.GeneratorConfig{
		Prefix: "ak-",
		Length: 16,
	})
	keyStore := apikey.NewInMemoryStore()

	// Reset to default NoopTranslator to make the i18n pass-through
	// assertion deterministic (consuming projects may have replaced it).
	i18n.SetGlobal(i18n.NoopTranslator{})

	pass := 0
	failures := 0
	totalChecks := 0

	for _, s := range ff.Subjects {
		// --- JWT round-trip with non-ASCII claim values ---
		totalChecks++
		claims := map[string]interface{}{
			"sub":    s.JWTSub,
			"role":   s.ClaimRole,
			"locale": s.Locale,
			"region": s.MetadataRegion,
		}
		tokenStr, err := jwtMgr.Create(claims)
		if err != nil {
			fmt.Printf("FAIL [%s] jwt.Create: %v\n", s.Locale, err)
			failures++
			continue
		}
		tok, err := jwtMgr.Validate(tokenStr)
		if err != nil {
			fmt.Printf("FAIL [%s] jwt.Validate: %v\n", s.Locale, err)
			failures++
			continue
		}
		gotSub, _ := tok.Claims["sub"].(string)
		gotRole, _ := tok.Claims["role"].(string)
		if gotSub != s.JWTSub || gotRole != s.ClaimRole {
			fmt.Printf(
				"FAIL [%s] jwt byte-drift: want sub=%q role=%q got sub=%q role=%q\n",
				s.Locale, s.JWTSub, s.ClaimRole, gotSub, gotRole,
			)
			failures++
			continue
		}
		// Refresh and re-validate; custom claims must survive.
		refreshed, err := jwtMgr.Refresh(tokenStr)
		if err != nil {
			fmt.Printf("FAIL [%s] jwt.Refresh: %v\n", s.Locale, err)
			failures++
			continue
		}
		tok2, err := jwtMgr.Validate(refreshed)
		if err != nil {
			fmt.Printf("FAIL [%s] jwt.Validate(refreshed): %v\n", s.Locale, err)
			failures++
			continue
		}
		gotSub2, _ := tok2.Claims["sub"].(string)
		gotRole2, _ := tok2.Claims["role"].(string)
		if gotSub2 != s.JWTSub || gotRole2 != s.ClaimRole {
			fmt.Printf(
				"FAIL [%s] jwt-refresh drift: want sub=%q role=%q got sub=%q role=%q\n",
				s.Locale, s.JWTSub, s.ClaimRole, gotSub2, gotRole2,
			)
			failures++
			continue
		}
		fmt.Printf(
			"PASS [%s] jwt round-trip sub=%q role=%q raw_bytes=%d refreshed_bytes=%d\n",
			s.Locale, gotSub, gotRole, len(tokenStr), len(refreshed),
		)
		pass++

		// --- API key with non-ASCII Name + Scopes ---
		totalChecks++
		key, err := keyGen.Generate(s.KeyLabel, s.Scopes, time.Time{})
		if err != nil {
			fmt.Printf("FAIL [%s] apikey.Generate: %v\n", s.Locale, err)
			failures++
			continue
		}
		if err := keyStore.Store(key); err != nil {
			fmt.Printf("FAIL [%s] apikey.Store: %v\n", s.Locale, err)
			failures++
			continue
		}
		fetched, err := apikey.Validate(keyStore, key.Key)
		if err != nil {
			fmt.Printf("FAIL [%s] apikey.Validate: %v\n", s.Locale, err)
			failures++
			continue
		}
		if fetched.Name != s.KeyLabel {
			fmt.Printf(
				"FAIL [%s] apikey name byte-drift: want=%q got=%q\n",
				s.Locale, s.KeyLabel, fetched.Name,
			)
			failures++
			continue
		}
		// Scope round-trip — every fixture scope must answer HasScope=true.
		allOk := true
		for _, sc := range s.Scopes {
			if !fetched.HasScope(sc) {
				fmt.Printf(
					"FAIL [%s] apikey scope missing after store: %q\n",
					s.Locale, sc,
				)
				allOk = false
				break
			}
		}
		if !allOk {
			failures++
			continue
		}
		if !fetched.HasAllScopes(s.Scopes) {
			fmt.Printf("FAIL [%s] apikey.HasAllScopes false\n", s.Locale)
			failures++
			continue
		}
		fmt.Printf(
			"PASS [%s] apikey id=%s name=%q scopes=%v masked=%s\n",
			s.Locale, fetched.ID, fetched.Name, fetched.Scopes,
			apikey.MaskKey(fetched.Key),
		)
		pass++

		// --- i18n.NoopTranslator pass-through with non-ASCII arg ---
		totalChecks++
		const bundleKey = "auth_apikey_label"
		out := i18n.T(bundleKey, s.KeyLabel)
		// Expected form: key + 0x1F + arg
		want := bundleKey + "\x1f" + s.KeyLabel
		if out != want {
			fmt.Printf(
				"FAIL [%s] i18n pass-through mismatch: want=%q got=%q\n",
				s.Locale, want, out,
			)
			failures++
			continue
		}
		fmt.Printf("PASS [%s] i18n noop pass-through label=%q\n",
			s.Locale, s.KeyLabel)
		pass++
	}

	// Sanity: in-memory store should now contain one key per subject.
	listed, err := keyStore.List()
	if err != nil {
		fmt.Printf("FAIL store.List: %v\n", err)
		failures++
	} else if len(listed) != len(ff.Subjects) {
		fmt.Printf(
			"FAIL store population: want=%d got=%d\n",
			len(ff.Subjects), len(listed),
		)
		failures++
	} else {
		fmt.Printf("PASS store population: %d/%d keys persisted\n",
			len(listed), len(ff.Subjects))
		pass++
		totalChecks++
	}

	fmt.Printf("\nSummary: %d PASS, %d FAIL of %d checks across %d subjects\n",
		pass, failures, totalChecks, len(ff.Subjects))
	if failures > 0 {
		os.Exit(1)
	}
}

func runnerFail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "runner-error: "+format+"\n", args...)
	os.Exit(2)
}
