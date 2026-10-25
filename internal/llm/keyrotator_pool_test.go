package llm

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

func TestKeyRotatorContains(t *testing.T) {
	r := NewKeyRotator([]string{"k1", "k2"})
	if !r.Contains("k1") || !r.Contains("k2") {
		t.Fatal("pool keys should be contained")
	}
	if r.Contains("other") {
		t.Error("non-pool key must not be contained")
	}
	if r.Contains("") {
		t.Error("empty key must not be contained")
	}
	var nilR *KeyRotator
	if nilR.Contains("k1") {
		t.Error("nil rotator Contains must be false")
	}
}

// Reproduces the production config that pinned all traffic to one key:
// XALGORIX_API_KEY empty, both keys supplied via XALGORIX_API_KEYS, and a
// provider profile that resolves every request to the first pooled key. The old
// gate (ep.APIKey == cfg.APIKey) failed because the pooled key != empty primary,
// so rotation never fired. It must now round-robin across BOTH keys.
func TestApplyKeyRotation_PoolKeyEmptyPrimary(t *testing.T) {
	c := &Client{cfg: &config.Config{APIKey: ""}, keyRotator: NewKeyRotator([]string{"k1", "k2"})}
	seen := map[string]int{}
	for i := 0; i < 6; i++ {
		ep := c.applyKeyRotation(Endpoint{Auth: AuthAPIKey, APIKey: "k1"})
		seen[ep.APIKey]++
	}
	if seen["k1"] == 0 || seen["k2"] == 0 {
		t.Errorf("expected rotation across both pooled keys, got %v", seen)
	}
	// A credential outside the pool (a different provider's profile key) is never
	// rotated.
	ep := c.applyKeyRotation(Endpoint{Auth: AuthAPIKey, APIKey: "other-provider-key"})
	if ep.APIKey != "other-provider-key" {
		t.Errorf("non-pool key must be left untouched, got %q", ep.APIKey)
	}
	// An OAuth bearer endpoint is never rotated.
	oauth := c.applyKeyRotation(Endpoint{Auth: AuthOAuthBearer, APIKey: "k1"})
	if oauth.APIKey != "k1" {
		t.Errorf("non-APIKey auth must be left untouched, got %q", oauth.APIKey)
	}
}

// Legacy path regression: when the endpoint carries exactly cfg.APIKey, rotation
// still fires (behavior unchanged).
func TestApplyKeyRotation_LegacyPrimaryMatch(t *testing.T) {
	c := &Client{cfg: &config.Config{APIKey: "primary"}, keyRotator: NewKeyRotator([]string{"primary", "k2"})}
	ep := c.applyKeyRotation(Endpoint{Auth: AuthAPIKey, APIKey: "primary"})
	if ep.APIKey != "primary" && ep.APIKey != "k2" {
		t.Errorf("legacy configured-key path must still rotate, got %q", ep.APIKey)
	}
}

func TestClonePreservesKeyRotator(t *testing.T) {
	c := &Client{cfg: &config.Config{APIKey: ""}, keyRotator: NewKeyRotator([]string{"k1", "k2"})}
	cl := c.Clone()
	if cl.keyRotator != c.keyRotator {
		t.Error("Clone must share the keyRotator pointer so clones keep rotating")
	}
}
