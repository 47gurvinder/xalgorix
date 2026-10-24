package reporting

import (
	"strings"
	"testing"
)

// Target-wide classes (debug/stack-trace disclosure, missing security headers,
// version/tech disclosure, CORS policy, clickjacking) are a property of the
// server, not a per-endpoint bug. Production scans reported a SINGLE Laravel
// debug mode as four separate findings (one per path the stack trace surfaced
// on). These must collapse to one finding per (target, class) regardless of
// endpoint — while genuinely per-endpoint classes (sqli/xss/idor/...) on
// different paths must stay separate.

// TestDedupTargetWideDebugDisclosure: the same Laravel debug mode surfaced on
// different endpoints is ONE finding. The four production titles used different
// wording ("Debug Page Exposes Stack Trace", "Verbose Exception Disclosure")
// but all classify as debug_disclosure and must collapse.
func TestDedupTargetWideDebugDisclosure(t *testing.T) {
	const target = "https://zasidannia.example.gov"
	existing := []Vulnerability{{
		ID:       "XALG-1",
		Title:    "Production Laravel Debug Page Exposes Stack Trace via Participant Profile",
		Target:   target,
		Endpoint: target + "/participant/42/profile",
		Verified: true,
	}}

	// Same debug mode, a DIFFERENT endpoint, DIFFERENT wording — still a dup.
	for _, tc := range []struct {
		name, title, endpoint string
	}{
		{"verbose exception", "Public Verbose Laravel Exception Disclosure on Pagination", target + "/events?page=1"},
		{"array param stack trace", "Anonymous Array Parameter Exposes Laravel Debug Stack Trace", target + "/login"},
		{"type confusion traceback", "Unauthenticated Type-Confusion Input Exposes Full Traceback", target + "/api/search"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, msg, dup := findDuplicateVulnerability(existing, tc.title, "", "", "", target, tc.endpoint)
			if !dup {
				t.Fatalf("target-wide debug disclosure %q on %q should dedup against XALG-1 (type=%q vs %q)",
					tc.title, tc.endpoint,
					extractVulnType(tc.title, ""), extractVulnType(existing[0].Title, ""))
			}
			if !strings.Contains(msg, "XALG-1") {
				t.Errorf("duplicate message should name the existing finding: %q", msg)
			}
		})
	}
}

// TestDedupTargetWideMissingHeaderAndCORS: missing security headers and a CORS
// policy are server-wide — reporting them per path is a duplicate.
func TestDedupTargetWideMissingHeaderAndCORS(t *testing.T) {
	const target = "https://app.example.com"
	for _, tc := range []struct {
		name                    string
		existingTitle, newTitle string
		existingEP, newEP       string
	}{
		{"missing header on two paths",
			"Missing Content-Security-Policy header", "Missing HSTS Strict-Transport-Security header",
			target + "/", target + "/api/login"},
		{"cors on two paths",
			"CORS misconfiguration allows arbitrary origin", "Cross-Origin Resource Sharing reflects Origin",
			target + "/api/user", target + "/api/orders"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			existing := []Vulnerability{{ID: "XALG-2", Title: tc.existingTitle, Target: target, Endpoint: tc.existingEP, Verified: true}}
			_, _, dup := findDuplicateVulnerability(existing, tc.newTitle, "", "", "", target, tc.newEP)
			if !dup {
				t.Fatalf("%q on %q should dedup as a target-wide issue (types %q/%q)",
					tc.newTitle, tc.newEP, extractVulnType(tc.existingTitle, ""), extractVulnType(tc.newTitle, ""))
			}
		})
	}
}

// TestDedupTargetWideViaCWE209: a stack-trace/error disclosure whose title
// carries no class keyword still classifies as debug_disclosure via CWE-209
// ("error message containing sensitive information") and collapses target-wide.
func TestDedupTargetWideViaCWE209(t *testing.T) {
	const target = "https://api.example.com"
	existing := []Vulnerability{{
		ID: "XALG-3", Title: "Error response reveals server internals",
		Target: target, Endpoint: target + "/v1/orders", CWE: "CWE-209", Verified: true,
	}}
	if got := extractVulnTypeWithCWE(existing[0].Title, "", existing[0].CWE); got != "debug_disclosure" {
		t.Fatalf("CWE-209 with no keyword should classify as debug_disclosure, got %q", got)
	}
	_, _, dup := findDuplicateVulnerability(existing,
		"Unhandled error returns internals", "", "", "CWE-209", target, target+"/v1/users")
	if !dup {
		t.Fatal("CWE-209 error disclosure on another endpoint should dedup target-wide")
	}
}

// TestDedupEndpointlessSameClassNotMerged: two findings of the same class that
// both leave the endpoint field empty must NOT be merged on that basis — the
// endpoint often lives in the TITLE instead. Real scan: two distinct XXE sinks
// ("...POST /aide/doc/bnum" and "...POST /.env"), both with an empty endpoint
// field, are DIFFERENT vulnerabilities and must both survive.
func TestDedupEndpointlessSameClassNotMerged(t *testing.T) {
	const target = "https://bnum.example.gov"
	existing := []Vulnerability{{
		ID: "XALG-4", Title: "XXE external entity resolution at POST /aide/doc/bnum (DNS OOB confirmed)",
		Target: target, Endpoint: "", Verified: true,
	}}
	_, msg, dup := findDuplicateVulnerability(existing,
		"External entity resolution (XXE) in POST /.env via XML SYSTEM entity", "", "", "", target, "")
	if dup {
		t.Fatalf("two distinct XXE sinks with empty endpoint fields must NOT be merged: %q", msg)
	}
}

// TestDedupEmptyEndpointDoesNotCrossInstances is the safety contract for the
// empty-endpoint rule, drawn from a real scan: a target had an access-request
// IDOR on one endpoint and a notification IDOR reported without an endpoint.
// Merging the endpointless finding into the first same-class finding would
// DESTROY a distinct vulnerability. A finding that HAS an endpoint is never
// fused with one that lacks it.
func TestDedupEmptyEndpointDoesNotCrossInstances(t *testing.T) {
	const target = "https://studio.example.com"
	existing := []Vulnerability{{
		ID: "XALG-A", Title: "Access-request tracking key enables cross-account disclosure",
		Target: target, Endpoint: target + "/api/access-requests/{code}", CWE: "CWE-639", Verified: true,
	}}
	// A DIFFERENT idor (notification), reported with no endpoint, must NOT be
	// collapsed into the access-request idor just because both are idor.
	_, msg, dup := findDuplicateVulnerability(existing,
		"Authenticated notification IDOR lets a user mark another user's notification read",
		"", "", "CWE-639", target, "")
	if dup {
		t.Fatalf("distinct IDOR with an empty endpoint must NOT merge into the access-request IDOR: %q", msg)
	}
}

// TestDedupUserEnumerationSameEndpoint: user/account enumeration is now a
// classified type (keyword + CWE-203/204), so two enumeration reports on the
// same endpoint collapse via the same-endpoint rule (observed: member-ID
// enumeration reported twice on /member.php, once with a query string).
func TestDedupUserEnumerationSameEndpoint(t *testing.T) {
	const target = "https://kbizs.example.com"
	existing := []Vulnerability{{
		ID: "XALG-B", Title: "Unauthenticated member account enumeration through ID recovery",
		Target: target, Endpoint: target + "/chtml/member.php", CWE: "CWE-203", Verified: true,
	}}
	if got := extractVulnTypeWithCWE(existing[0].Title, "", existing[0].CWE); got != "user_enumeration" {
		t.Fatalf("expected user_enumeration, got %q", got)
	}
	// Same endpoint, different query string, different wording → dup.
	_, _, dup := findDuplicateVulnerability(existing,
		"Unauthenticated Member ID Enumeration via Duplicate-Check Endpoint",
		"", "", "CWE-203", target, target+"/chtml/member.php?com_member_basic=idcheck_form&x=1")
	if !dup {
		t.Fatal("two user-enumeration reports on the same endpoint should dedup")
	}
}

// TestDedupPerEndpointClassesStaySeparate is the safety contract: the
// target-wide and empty-endpoint rules must NOT suppress genuinely distinct
// vulnerabilities. Per-endpoint classes on DIFFERENT endpoints — and distinct
// non-target-wide info disclosures — must remain separate findings.
func TestDedupPerEndpointClassesStaySeparate(t *testing.T) {
	const target = "https://shop.example.com"
	for _, tc := range []struct {
		name                    string
		existingTitle, newTitle string
		existingEP, newEP       string
		cwe                     string
	}{
		{"distinct sqli on different paths",
			"SQL Injection in login form", "SQL Injection in product search",
			target + "/login", target + "/search", ""},
		{"distinct idor on different objects",
			"IDOR on orders", "IDOR on invoices",
			target + "/orders/1", target + "/invoices/5", ""},
		{"distinct xss on different sinks",
			"Reflected XSS in comment field", "Stored XSS in profile bio",
			target + "/comment", target + "/profile", ""},
		{"distinct info disclosures are NOT target-wide",
			"API key exposed in config.js", "Database credentials in backup.sql",
			target + "/config.js", target + "/backup.sql", ""},
		{"distinct ssrf on different params",
			"SSRF via webhook url", "SSRF via avatar import",
			target + "/webhook", target + "/import", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			existing := []Vulnerability{{ID: "XALG-X", Title: tc.existingTitle, Target: target, Endpoint: tc.existingEP, CWE: tc.cwe, Verified: true}}
			_, msg, dup := findDuplicateVulnerability(existing, tc.newTitle, "", "", tc.cwe, target, tc.newEP)
			if dup {
				t.Fatalf("distinct finding %q on %q must NOT be suppressed (collapsed into %q): %q",
					tc.newTitle, tc.newEP, tc.existingTitle, msg)
			}
		})
	}
}

// TestDebugDisclosureClassification locks in the keyword vocabulary that routes
// debug/stack-trace findings to the debug_disclosure class (ahead of the
// generic info_disclosure bucket).
func TestDebugDisclosureClassification(t *testing.T) {
	debug := []string{
		"Laravel Debug Page Exposes Stack Trace",
		"Full traceback leaked to anonymous user",
		"Verbose Exception Disclosure on /api",
		"Werkzeug debugger is enabled in production",
		"Django debug mode exposes settings",
	}
	for _, title := range debug {
		if got := extractVulnType(title, ""); got != "debug_disclosure" {
			t.Errorf("%q should classify as debug_disclosure, got %q", title, got)
		}
	}
	// A generic secret leak is info_disclosure, NOT debug_disclosure (so it is
	// not swept up by the target-wide debug rule).
	if got := extractVulnType("API key exposed in response", ""); got != "info_disclosure" {
		t.Errorf("secret leak should stay info_disclosure, got %q", got)
	}
}
