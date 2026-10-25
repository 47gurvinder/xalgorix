package agent

import "testing"

func TestTaskBlocksPrincipledFinish(t *testing.T) {
	cases := []struct {
		name string
		task *Task
		want bool
	}{
		{"recon blocks", &Task{ID: "recon"}, true},
		{"dirbust blocks", &Task{ID: "dirbust"}, true},
		{"auth-session does NOT block (closes as residual)", &Task{ID: "auth-session", VulnClass: "auth"}, false},
		{"specific-endpoint llm hypothesis blocks", &Task{ID: "x", VulnClass: "sqli", Origin: "llm", Endpoint: "/login"}, true},
		{"generic auto per-endpoint class task is soft", &Task{ID: "x", VulnClass: "sqli", Origin: "auto"}, false},
		{"llm per-endpoint class task with no endpoint is soft", &Task{ID: "x", VulnClass: "sqli", Origin: "llm", Endpoint: ""}, false},
		{"whole-target class task is soft", &Task{ID: "x", VulnClass: "redos", WholeTarget: true, Origin: "auto"}, false},
		{"class-less exploratory is soft", &Task{ID: "x", VulnClass: ""}, false},
	}
	for _, tc := range cases {
		if got := taskBlocksPrincipledFinish(tc.task); got != tc.want {
			t.Errorf("%s: taskBlocksPrincipledFinish = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// breadthState builds a state whose VulnClassesTested covers n of the required
// injection classes, with a plan of one pending generic sqli per-endpoint task.
func breadthState(n int, conv bool, iter int) *ScanState {
	req := requiredCoverageClasses()
	vct := map[string]bool{}
	for i := 0; i < n && i < len(req); i++ {
		vct[req[i]] = true
	}
	return &ScanState{
		ConvergeFinish:    conv,
		Iteration:         iter,
		MinIterations:     50,
		VulnClassesTested: vct,
		Plan: &Plan{Tasks: []*Task{
			{ID: "t-sqli", VulnClass: "sqli", Origin: "auto", Status: TaskPending},
		}},
	}
}

func TestSaturatedForFinish(t *testing.T) {
	// Flag off: never saturates.
	if saturatedForFinish(breadthState(11, false, 500)) {
		t.Error("flag off must not saturate")
	}
	// Before MinIterations: not yet.
	if saturatedForFinish(breadthState(11, true, 10)) {
		t.Error("below MinIterations must not saturate")
	}
	// Low class breadth (3/11 ≈ 27% < 60%): not saturated.
	if saturatedForFinish(breadthState(3, true, 500)) {
		t.Error("low class breadth must not saturate")
	}
	// Breadth ok (8/11 ≈ 73%), only soft tasks, past min-iter: saturated.
	if !saturatedForFinish(breadthState(8, true, 500)) {
		t.Error("broad coverage with only soft tasks should saturate")
	}
	// A pending recon task blocks even with full breadth.
	st := breadthState(11, true, 500)
	st.Plan.Tasks = append(st.Plan.Tasks, &Task{ID: "recon", Status: TaskPending})
	if saturatedForFinish(st) {
		t.Error("pending recon must block saturation")
	}
	// A pending specific-endpoint hypothesis blocks.
	st2 := breadthState(11, true, 500)
	st2.Plan.Tasks = append(st2.Plan.Tasks, &Task{ID: "h", VulnClass: "idor", Origin: "llm", Endpoint: "/x", Status: TaskPending})
	if saturatedForFinish(st2) {
		t.Error("pending specific-endpoint hypothesis must block saturation")
	}
	// No soft task at all (only completed): nothing to close → not saturated.
	st3 := breadthState(11, true, 500)
	st3.Plan.Tasks = []*Task{{ID: "t", VulnClass: "sqli", Origin: "auto", Status: TaskCompleted}}
	if saturatedForFinish(st3) {
		t.Error("no open soft task must not saturate (plan-exhausted path handles that)")
	}
}

func TestCloseSoftTasksForFinish(t *testing.T) {
	st := &ScanState{
		Plan: &Plan{Tasks: []*Task{
			{ID: "recon", Status: TaskPending},                                                          // blocker: untouched
			{ID: "h", VulnClass: "sqli", Origin: "llm", Endpoint: "/login", Status: TaskPending},        // blocker: untouched
			{ID: "t-sqli", VulnClass: "sqli", Origin: "auto", Status: TaskPending},                      // soft class → coverage_sufficient
			{ID: "t-redos", VulnClass: "redos", WholeTarget: true, Origin: "auto", Status: TaskPending}, // soft class
			{ID: "auth-session", VulnClass: "auth", Status: TaskActive},                                 // soft auth → blocked_missing_auth
			{ID: "explore", VulnClass: "", Status: TaskPending},                                         // class-less → coverage_complete
			{ID: "done", VulnClass: "xss", Origin: "auto", Status: TaskCompleted},                       // already terminal: untouched
		}},
	}
	closed := closeSoftTasksForFinish(st)
	if closed != 4 {
		t.Fatalf("closed = %d, want 4", closed)
	}
	by := map[string]*Task{}
	for _, tk := range st.Plan.Tasks {
		by[tk.ID] = tk
	}
	if by["recon"].Status != TaskPending {
		t.Error("recon (blocker) must be left pending")
	}
	if by["h"].Status != TaskPending {
		t.Error("specific-endpoint hypothesis (blocker) must be left pending")
	}
	if by["t-sqli"].Status != TaskSkipped || by["t-sqli"].Disposition != DispositionCoverageSufficient {
		t.Errorf("t-sqli = %v/%q, want skipped/coverage_sufficient", by["t-sqli"].Status, by["t-sqli"].Disposition)
	}
	if by["auth-session"].Disposition != DispositionBlockedMissingAuth {
		t.Errorf("auth-session disposition = %q, want blocked_missing_auth", by["auth-session"].Disposition)
	}
	if by["explore"].Disposition != DispositionCoverageComplete {
		t.Errorf("explore disposition = %q, want coverage_complete", by["explore"].Disposition)
	}
	if !hasCoverageSufficientTask(st) {
		t.Error("hasCoverageSufficientTask should be true after close")
	}
	// auth-session WITH an auth context closes as exhausted, not blocked.
	st2 := &ScanState{AuthContextAvailable: true, Plan: &Plan{Tasks: []*Task{
		{ID: "auth-session", VulnClass: "auth", Status: TaskPending},
	}}}
	closeSoftTasksForFinish(st2)
	if st2.Plan.Tasks[0].Disposition != DispositionExhausted {
		t.Errorf("auth-session (with auth ctx) disposition = %q, want exhausted", st2.Plan.Tasks[0].Disposition)
	}
}

// Lever A: a content-discovery artifact owes information-exposure only — and
// ONLY when the flag is on (legacy applicability is byte-identical when off).
func TestContentDiscoveryArtifactApplicability(t *testing.T) {
	const ep = "/.htaccess"

	off := buildSurfaceEndpoint(&ScanState{ConvergeFinish: false}, ep)
	offClasses := off.ApplicableClasses()
	sawInjection := false
	for _, c := range offClasses {
		if CanonicalVulnClassID(c) != "" {
			sawInjection = true
		}
	}
	if !sawInjection {
		t.Errorf("flag OFF: %s should still get the legacy injection floor, got %v", ep, offClasses)
	}

	on := buildSurfaceEndpoint(&ScanState{ConvergeFinish: true}, ep)
	onClasses := on.ApplicableClasses()
	if len(onClasses) != 1 || onClasses[0] != "information-exposure" {
		t.Errorf("flag ON: %s should owe only information-exposure, got %v", ep, onClasses)
	}
}

func TestIsContentDiscoveryArtifact(t *testing.T) {
	artifacts := []string{
		"/.git/config", "/.svn/entries", "/.htaccess", "/.htpasswd", "/Thumbs.db",
		"/.DS_Store", "/access.log", "/error_log", "/backup.sql", "/site.zip",
		"/db.bak", "/__xalgorix_nonexistent_control_71ab9", "/web.config",
	}
	for _, a := range artifacts {
		if !isContentDiscoveryArtifact(a) {
			t.Errorf("%q should be a content-discovery artifact", a)
		}
	}
	realRoutes := []string{
		"/account/login", "/cart/add", "/api/graphql", "/actuator/env",
		"/products", "/search", "/digit", "/login",
	}
	for _, r := range realRoutes {
		if isContentDiscoveryArtifact(r) {
			t.Errorf("%q is a real route, must NOT be flagged as an artifact", r)
		}
	}
}
