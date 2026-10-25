package agent

import (
	"regexp"
	"strings"
)

// Endpoint accounting (DiscoveredEndpoints, CoverageBaseline, EndpointClassCoverage)
// must contain only real target routes. Scanner-side noise poisons convergence:
// a frozen CoverageBaseline full of non-endpoints holds class tasks open forever,
// because those bogus "endpoints" can never be tested for a class. Observed
// pollution on real scans:
//   - the scanner's own CLI tool-config paths (/.config/httpx/config.yaml, ...)
//   - unexpanded payload / shell template variables ($TOK, /$p, /$u, ${...})
//   - OAST callback URLs and probe artifacts
//
// isScanArtifactURL and isProbeArtifactEndpoint already reject OAST callbacks and
// payload/shell-metachar artifacts (the latter rejects any path containing `$`),
// but they are only applied when an endpoint is *promoted* — not in
// markEndpointClassCoverage, which is how the `$` noise reached the coverage map —
// and neither catches the engine's own tool-config paths. isValidTargetEndpoint
// is the single predicate that composes the existing filters and closes the
// tool-config gap; sanitizeEndpointState scrubs already-recorded state so a scan
// that froze a polluted baseline can still converge. All gated on
// state.EndpointHygiene (XALGORIX_ENDPOINT_HYGIENE, default off).

// scannerToolConfigRe matches the engine's own CLI tool config namespaces, which
// are never a target route (and which isProbeArtifactEndpoint does not catch).
var scannerToolConfigRe = regexp.MustCompile(`(?i)/\.config/(?:httpx|subfinder|nuclei|nuclei-templates|amass|katana|uncover|notify|naabu|dnsx|httprobe|ffuf|gobuster|feroxbuster|gau|chaos|interactsh)(?:/|$)`)

// isValidTargetEndpoint reports whether ep looks like a real target route rather
// than scanner-side noise. Pure predicate; callers gate on state.EndpointHygiene.
func isValidTargetEndpoint(ep string) bool {
	s := strings.TrimSpace(ep)
	if s == "" {
		return false
	}
	if isScanArtifactURL(s) || isProbeArtifactEndpoint(s) {
		return false
	}
	if scannerToolConfigRe.MatchString(s) {
		return false
	}
	return true
}

// filterValidEndpoints returns a new slice with scanner-side noise removed.
func filterValidEndpoints(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, 0, len(in))
	for _, e := range in {
		if isValidTargetEndpoint(e) {
			out = append(out, e)
		}
	}
	return out
}

// sanitizeEndpointState scrubs scanner-side noise from already-recorded endpoint
// accounting so a scan that froze a polluted baseline can still converge. It only
// drops entries isValidTargetEndpoint rejects — never a real route — so it can
// remove bogus obligations but never real coverage.
func sanitizeEndpointState(state *ScanState) {
	if state == nil {
		return
	}
	state.DiscoveredEndpoints = filterValidEndpoints(state.DiscoveredEndpoints)
	state.CoverageBaseline = filterValidEndpoints(state.CoverageBaseline)
	for ep := range state.EndpointClassCoverage {
		if !isValidTargetEndpoint(ep) {
			delete(state.EndpointClassCoverage, ep)
		}
	}
}
