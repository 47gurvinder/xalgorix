package tools

import (
	"strings"
	"testing"
)

func TestSecretEnvKey(t *testing.T) {
	// Operator secrets — must be reported true so they are stripped from every
	// tool subprocess environment. Includes the non-namespaced ones that a plain
	// XALGORIX_* scrub would miss (the gap this closes for the terminal tool).
	secret := []string{
		"GEMINI_API_KEY", "AGENTMAIL_API_KEY", "AGENTMAIL_POD",
		"CAIDO_API_TOKEN", "INBOUND_EMAIL_SECRET",
		"XALGORIX_API_KEY", "XALGORIX_API_KEYS", "XALGORIX_API_TOKEN",
		"XALGORIX_USERNAME", "XALGORIX_PASSWORD", "XALGORIX_PASSWORD_HASH",
		"XALGORIX_PROXY_URL", "XALGORIX_TARGET_AUTH", "XALGORIX_OOB_API_KEY",
		"agentmail_api_key", "Caido_Api_Token", // case-insensitive
	}
	for _, k := range secret {
		if !SecretEnvKey(k) {
			t.Errorf("SecretEnvKey(%q) = false, want true (operator secret)", k)
		}
	}

	// Must be reported false. Third-party recon tools read their own source keys
	// from the environment, so those must survive; generic shell vars and the
	// non-secret XALGORIX_* config (stripped separately by each caller's
	// namespace catch-all, not by this predicate) must too.
	keep := []string{
		"PATH", "HOME", "TMPDIR", "GOPATH", "LANG",
		"GITHUB_TOKEN", "SHODAN_API_KEY", "CHAOS_KEY", "AWS_SECRET_ACCESS_KEY",
		"XALGORIX_WORKSPACE", "XALGORIX_RATE_DELAY_MS", "XALGORIX_API_BASE",
		"XALGORIX_LLM_PROVIDER", "",
	}
	for _, k := range keep {
		if SecretEnvKey(k) {
			t.Errorf("SecretEnvKey(%q) = true, want false", k)
		}
	}
}

func TestSanitizeEnviron(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"XALGORIX_API_KEYS=k1,k2",
		"GITHUB_TOKEN=ghp_keepme",
		"AGENTMAIL_API_KEY=am_secret",
		"GEMINI_API_KEY=gm_secret",
		"MALFORMED_NO_EQUALS",
		"XALGORIX_WORKSPACE=/work",
	}
	got := SanitizeEnviron(in)
	joined := strings.Join(got, "\n")

	for _, must := range []string{"PATH=/usr/bin", "GITHUB_TOKEN=ghp_keepme", "MALFORMED_NO_EQUALS", "XALGORIX_WORKSPACE=/work"} {
		if !containsExact(got, must) {
			t.Errorf("SanitizeEnviron dropped %q; kept:\n%s", must, joined)
		}
	}
	for _, gone := range []string{"XALGORIX_API_KEYS", "AGENTMAIL_API_KEY", "GEMINI_API_KEY"} {
		if strings.Contains(joined, gone+"=") {
			t.Errorf("SanitizeEnviron leaked secret %q; kept:\n%s", gone, joined)
		}
	}
}

func containsExact(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
