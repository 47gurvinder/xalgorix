package agent

import "testing"

func TestScannerToolConfigRe(t *testing.T) {
	for _, s := range []string{"/.config/httpx/config.yaml", "/.config/subfinder/provider-config.yaml", "/.config/nuclei/"} {
		if !scannerToolConfigRe.MatchString(s) {
			t.Errorf("scannerToolConfigRe should match scanner tool config %q", s)
		}
	}
	for _, s := range []string{"/.config/app/settings", "/config/httpx", "/api/.config/thing"} {
		if scannerToolConfigRe.MatchString(s) {
			t.Errorf("scannerToolConfigRe should NOT match %q", s)
		}
	}
}

func TestIsValidTargetEndpoint(t *testing.T) {
	for _, s := range []string{"/", "/api/users", "/login", "/api/v1/orders"} {
		if !isValidTargetEndpoint(s) {
			t.Errorf("isValidTargetEndpoint(%q) = false, want true (real route)", s)
		}
	}
	// Scanner-side noise: $-vars/shell metachars (via isProbeArtifactEndpoint),
	// OAST, and the engine's own tool-config paths (via scannerToolConfigRe).
	for _, s := range []string{"", "   ", "/$p", "/$u", "/$TOK.oast.live/x.png", "/.config/httpx/config.yaml", "/api/${FUZZ}"} {
		if isValidTargetEndpoint(s) {
			t.Errorf("isValidTargetEndpoint(%q) = true, want false (scanner noise)", s)
		}
	}
}

func TestSanitizeEndpointState(t *testing.T) {
	s := NewScanState()
	s.DiscoveredEndpoints = []string{"/api/users", "/$p", "/.config/httpx/config.yaml", "/login"}
	s.CoverageBaseline = []string{"/api/users", "/$u", "/.config/subfinder/config.yaml"}
	s.EndpointClassCoverage = map[string]map[string]bool{
		"/api/users":             {"sqli": true},
		"/$TOK.oast.live/x.png":  {"ssrf": true},
		"/.config/httpx/cfg.yml": {"xss": true},
	}
	sanitizeEndpointState(s)

	if got := len(s.DiscoveredEndpoints); got != 2 {
		t.Errorf("DiscoveredEndpoints: want 2 real routes, got %d (%v)", got, s.DiscoveredEndpoints)
	}
	if got := len(s.CoverageBaseline); got != 1 {
		t.Errorf("CoverageBaseline: want 1 real route, got %d (%v)", got, s.CoverageBaseline)
	}
	if _, ok := s.EndpointClassCoverage["/api/users"]; !ok {
		t.Error("sanitize dropped the real coverage entry /api/users")
	}
	if len(s.EndpointClassCoverage) != 1 {
		t.Errorf("EndpointClassCoverage: want only the real entry, got %v", s.EndpointClassCoverage)
	}
}

func TestMarkEndpointClassCoverageHygieneGate(t *testing.T) {
	on := NewScanState()
	on.EndpointHygiene = true
	markEndpointClassCoverage(on, "/$p", "sqli")
	if len(on.EndpointClassCoverage) != 0 {
		t.Errorf("hygiene on: junk endpoint must not enter the coverage map, got %v", on.EndpointClassCoverage)
	}
	if !on.VulnClassesTested["sqli"] {
		t.Error("hygiene on: the class must still be marked tested")
	}

	off := NewScanState()
	off.EndpointHygiene = false
	markEndpointClassCoverage(off, "/$p", "sqli")
	if len(off.EndpointClassCoverage) == 0 {
		t.Error("hygiene off: legacy path must still record the endpoint (no behavior change when flag off)")
	}
}
