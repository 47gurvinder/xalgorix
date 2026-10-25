package agent

// convergence_finish.go implements the OPTIONAL principled finish
// (XALGORIX_CONVERGE_FINISH, default off). It is inert unless the flag is on.
//
// Problem it solves
// -----------------
// taskCoverageComplete closes a generic per-endpoint class task only when EVERY
// applicable endpoint in the coverage denominator is tested for that class. The
// denominator (CoverageBaseline, frozen from DiscoveredEndpoints) is dominated by
// dirbust candidates — mostly non-injectable 404s, static files, VCS/config
// artifacts — so the bar is effectively "test every class on every path content
// discovery ever probed", which the agent never completes. The class tasks never
// reach "completed", the plan is never exhausted, the finish gate never opens, and
// the scan churns to a watchdog that cuts it off mid-coverage (dropping findings
// unpredictably, never firing the completion webhook). The exhaustive bar is the
// "miss nothing" mandate encoded, but taken literally it makes scans never
// converge.
//
// The fix: a principled finish
// ----------------------------
// Once a scan is SATURATED — the structured methodology (recon/dirbust/auth) is
// done, no targeted specific-endpoint hypothesis is still open, and the required
// injection classes have been exercised across the target past a breadth
// threshold — the remaining per-endpoint/whole-target class tasks close
// (DispositionCoverageSufficient) and class-less exploratory tasks close
// (DispositionCoverageComplete), but only after a no-new-finding tail
// (convergeFinishIdleLimit) confirms diminishing returns. The residual untested
// (route,class) pairs and any class not exercised target-wide are recorded in the
// report (completion.go), so the tradeoff is transparent rather than silent.
//
// Breadth, not per-route percentage, is the coverage gate on purpose: per-route
// coverage measured against the dirbust-polluted baseline is meaningless (reads
// single digits even on a thoroughly tested target), whereas VulnClassesTested is
// set only when a class is genuinely exercised, so class breadth is a reliable
// "the methodology actually ran" signal. Companion Lever A (surface.go) stops
// content-discovery artifacts from owing injection classes at all.
//
// Nothing concrete is abandoned: an open structured task or an open
// specific-endpoint LLM hypothesis makes the scan not-saturated, so the finish
// never fires while targeted or methodology work remains. With the flag off every
// function here is unreachable (callers are flag-gated) and behavior is the legacy
// path byte-for-byte.

import "strings"

const (
	// convergeFinishDefaultIdle is the no-new-finding tail (iterations) required
	// at saturation before the principled finish fires. Counted only while the
	// scan is saturated, so a still-productive scan (each new finding resets it)
	// is never cut.
	convergeFinishDefaultIdle = 150

	// convergeFinishClassBreadth is the minimum fraction of required injection
	// classes that must have been exercised target-wide (VulnClassesTested) before
	// a scan is considered saturated. Guards against finishing a scan that barely
	// started the methodology, using the reliable class-breadth signal rather than
	// the dirbust-polluted per-route denominator.
	convergeFinishClassBreadth = 0.60
)

// taskBlocksPrincipledFinish reports whether an open task is concrete work that
// must be settled before a principled finish: the foundational discovery
// (recon/dirbust — coverage is meaningless until the surface is mapped) or a
// targeted specific-endpoint LLM hypothesis. Everything else open (generic
// per-endpoint class tasks, whole-target class tasks, a stuck auth-session, and
// class-less exploratory tasks) is "soft" and may close at the finish.
//
// auth-session is deliberately NOT a hard blocker: on a target with a login but
// no ingested credentials it can never complete, so blocking on it holds the whole
// scan open forever. At a principled finish it closes as an honest blocked/residual
// disposition (closeSoftTasksForFinish) instead.
func taskBlocksPrincipledFinish(t *Task) bool {
	if t == nil {
		return false
	}
	switch t.ID {
	case "recon", "dirbust":
		return true
	}
	// A specific-endpoint hypothesis the model planned (not an engine "auto"
	// per-endpoint class task) names a concrete endpoint to test — settle it,
	// never skip it.
	if t.VulnClass != "" && !t.WholeTarget && t.Origin != "auto" && strings.TrimSpace(t.Endpoint) != "" {
		return true
	}
	return false
}

// classExercisedTargetWide reports whether a vuln class has coverage evidence at
// the target level (VulnClassesTested), tolerant of class-name normalization.
func classExercisedTargetWide(state *ScanState, class string) bool {
	if state == nil {
		return false
	}
	if canon := normalizeCoverageClass(class); canon != "" && state.VulnClassesTested[canon] {
		return true
	}
	return state.VulnClassesTested[class]
}

// classCoverageBreadth is the fraction of required injection classes exercised
// target-wide — the reliable coverage gate for the principled finish.
func classCoverageBreadth(state *ScanState) float64 {
	req := requiredCoverageClasses()
	if len(req) == 0 {
		return 1
	}
	tested := 0
	for _, c := range req {
		if classExercisedTargetWide(state, c) {
			tested++
		}
	}
	return float64(tested) / float64(len(req))
}

// saturatedForFinish reports whether a scan has done enough that a principled
// finish is warranted: the iteration floor has passed, no open task is concrete
// blocking work (so the structured methodology and all targeted hypotheses are
// settled), there is at least one soft task to close, and class breadth clears the
// threshold. It does NOT apply the finding-idle tail — the caller
// (autoFinalizeIfPlanComplete) owns that counter so a still-productive saturated
// scan is not cut.
func saturatedForFinish(state *ScanState) bool {
	if state == nil || !state.ConvergeFinish || state.Plan == nil {
		return false
	}
	if state.Iteration < state.MinIterations {
		return false
	}
	sawSoft := false
	for _, t := range state.Plan.Tasks {
		if t.Status != TaskPending && t.Status != TaskActive {
			continue
		}
		if taskBlocksPrincipledFinish(t) {
			return false
		}
		sawSoft = true
	}
	if !sawSoft {
		return false
	}
	return classCoverageBreadth(state) >= convergeFinishClassBreadth
}

// closeSoftTasksForFinish closes every remaining soft task at a principled finish:
// a task with a vuln class becomes DispositionCoverageSufficient (class exercised
// target-wide; residual endpoints recorded), a class-less exploratory task becomes
// DispositionCoverageComplete (not individually executed). Concrete blocking tasks
// are never touched. Returns the number closed. Only reached when saturatedForFinish
// held and the finding-idle tail elapsed.
func closeSoftTasksForFinish(state *ScanState) int {
	if state == nil || state.Plan == nil {
		return 0
	}
	closed := 0
	for _, t := range state.Plan.Tasks {
		if t.Status != TaskPending && t.Status != TaskActive {
			continue
		}
		if taskBlocksPrincipledFinish(t) {
			continue
		}
		t.Status = TaskSkipped
		switch {
		case t.ID == "auth-session":
			// A stuck auth lane is honest BLOCKED work, not "coverage sufficient":
			// surfacing it as blocked_* makes the terminal status
			// completed_with_blocked_work (resumable) rather than a silent success.
			if state.AuthContextAvailable {
				t.Disposition = DispositionExhausted
				if t.Notes == "" {
					t.Notes = "engine: authenticated testing did not converge within the scan; recorded as residual at principled finish"
				}
			} else {
				t.Disposition = DispositionBlockedMissingAuth
				if t.Notes == "" {
					t.Notes = "engine: authenticated testing not completed (no credentials ingested / auth flow not mapped); recorded as blocked residual at principled finish"
				}
			}
		case t.VulnClass != "":
			t.Disposition = DispositionCoverageSufficient
			if t.Notes == "" {
				t.Notes = "engine: injection classes exercised across the target past the breadth threshold with no new findings; residual untested endpoints recorded in the report, closed at principled finish"
			}
		default:
			t.Disposition = DispositionCoverageComplete
			if t.Notes == "" {
				t.Notes = "engine: systematic coverage complete; class-less exploratory task not individually executed, closed at principled finish"
			}
		}
		closed++
	}
	return closed
}

// hasCoverageSufficientTask reports whether the principled finish closed any
// class task — used to decide whether to emit the residual block in telemetry.
func hasCoverageSufficientTask(state *ScanState) bool {
	if state == nil || state.Plan == nil {
		return false
	}
	for _, t := range state.Plan.Tasks {
		if t.Disposition == DispositionCoverageSufficient {
			return true
		}
	}
	return false
}

// routeTouchCounts returns, over the coverage denominator, how many routes carry
// at least one applicable canonical injection class (applicable) and how many of
// those have been tested for at least one such class (touched). Reported in the
// finish telemetry for transparency; NOT used as a gate (the dirbust-polluted
// denominator makes the ratio unreliable — see the package comment).
func routeTouchCounts(state *ScanState) (touched, applicable int) {
	if state == nil {
		return 0, 0
	}
	for _, ep := range coverageDenominator(state) {
		var canon []string
		for _, c := range ApplicableClassesForEndpoint(state, ep) {
			if CanonicalVulnClassID(c) != "" {
				canon = append(canon, c)
			}
		}
		if len(canon) == 0 {
			continue
		}
		applicable++
		for _, c := range canon {
			if endpointTestedForClass(state, ep, c) {
				touched++
				break
			}
		}
	}
	return touched, applicable
}
