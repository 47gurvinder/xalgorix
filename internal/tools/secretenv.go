package tools

import "strings"

// The scan agent runs arbitrary security tools (terminal_execute, the Python
// tool) as child processes against untrusted targets, and those children
// inherit the scanner's environment. Without filtering, a single `env`/
// `printenv`, an `import os; os.environ`, or any tool coerced into echoing its
// environment would disclose the operator's own credentials (model/provider
// keys, admin-console login, proxy and integration tokens) to code running
// against a target.
//
// SecretEnvKey is the single source of truth for which inherited variables are
// operator secrets, shared by every tool that builds a subprocess environment so
// the deny-lists cannot drift apart. Callers additionally drop the whole
// XALGORIX_* namespace (re-adding the few non-secret ones they need), so this
// set only needs to enumerate the secrets that live OUTSIDE that namespace plus,
// for completeness as a standalone predicate, the namespaced ones.
//
// Third-party recon tools read their OWN source credentials from the
// environment (e.g. GITHUB_TOKEN, SHODAN_API_KEY, CHAOS_KEY); those are
// deliberately absent here — stripping them would silently degrade enumeration.
//
// This is defense-in-depth. It does not replace running the scanner under
// OS-level isolation (an unprivileged user, a container/VM, a read-only root),
// which is the real boundary for executing tools against untrusted input.
var operatorSecretEnvKeys = map[string]bool{
	// Non-namespaced operator secrets — these are the ones a plain XALGORIX_*
	// namespace scrub does NOT catch, so enumerating them here is what keeps
	// every tool's environment free of them.
	"GEMINI_API_KEY":       true,
	"AGENTMAIL_API_KEY":    true,
	"AGENTMAIL_POD":        true,
	"CAIDO_API_TOKEN":      true,
	"INBOUND_EMAIL_SECRET": true,

	// Namespaced credentials — redundant with a XALGORIX_* scrub, listed so the
	// predicate (and SanitizeEnviron) is correct on its own.
	"XALGORIX_API_KEY":            true,
	"XALGORIX_API_KEYS":           true,
	"XALGORIX_API_TOKEN":          true,
	"XALGORIX_USERNAME":           true,
	"XALGORIX_PASSWORD":           true,
	"XALGORIX_PASSWORD_HASH":      true,
	"XALGORIX_PROXY_URL":          true,
	"XALGORIX_PROXY_FILE":         true,
	"XALGORIX_PROXY_ROTATION":     true,
	"XALGORIX_TARGET_AUTH":        true,
	"XALGORIX_TARGET_AUTH_B":      true,
	"XALGORIX_DISCORD_WEBHOOK":    true,
	"XALGORIX_TELEGRAM_BOT_TOKEN": true,
	"XALGORIX_TELEGRAM_CHAT_ID":   true,
	"XALGORIX_OOB_API_KEY":        true,
	"XALGORIX_OOB_HOST":           true,
}

// SecretEnvKey reports whether an environment variable name holds an operator
// secret that must be kept out of agent-run subprocess environments. Matching is
// case-insensitive.
func SecretEnvKey(key string) bool {
	u := strings.ToUpper(strings.TrimSpace(key))
	if u == "" {
		return false
	}
	return operatorSecretEnvKeys[u]
}

// SanitizeEnviron returns a copy of env with every SecretEnvKey entry removed.
// Entries without an '=' are preserved unchanged. It does NOT strip the wider
// XALGORIX_* namespace; callers that want that apply it alongside SecretEnvKey.
func SanitizeEnviron(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if key, _, ok := strings.Cut(kv, "="); ok && SecretEnvKey(key) {
			continue
		}
		out = append(out, kv)
	}
	return out
}
