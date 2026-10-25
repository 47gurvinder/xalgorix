package agent

import "testing"

// With the flag off, every epoch helper is inert: the denominator is the live
// discovered set and no epoch state is ever created (legacy behavior).
func TestEpochCoverageInertWhenFlagOff(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"/a", "/b"}

	if got := coverageDenominator(state); len(got) != 2 {
		t.Fatalf("flag off: denominator must be the live discovered set, got %v", got)
	}
	ensureCoverageEpoch(state)
	if state.CoverageEpoch != 0 || state.CoverageBaseline != nil {
		t.Fatalf("flag off: no epoch state may be created, got epoch=%d baseline=%v", state.CoverageEpoch, state.CoverageBaseline)
	}
	if advanceCoverageEpoch(state) {
		t.Fatal("flag off: advance must be a no-op")
	}
}

// With the flag on, ensureCoverageEpoch freezes a baseline that later growth of
// DiscoveredEndpoints does not change — the denominator stays frozen.
func TestEnsureCoverageEpochFreezesDenominator(t *testing.T) {
	state := NewScanState()
	state.EpochCoverage = true

	// No surface yet: nothing to freeze.
	ensureCoverageEpoch(state)
	if state.CoverageEpoch != 0 {
		t.Fatalf("no surface: epoch must not open, got %d", state.CoverageEpoch)
	}

	state.DiscoveredEndpoints = []string{"/a", "/b"}
	ensureCoverageEpoch(state)
	if state.CoverageEpoch != 1 || len(state.CoverageBaseline) != 2 {
		t.Fatalf("expected epoch 1 with a 2-endpoint baseline, got epoch=%d baseline=%v", state.CoverageEpoch, state.CoverageBaseline)
	}
	// A second call is a no-op (epoch already open).
	ensureCoverageEpoch(state)
	if state.CoverageEpoch != 1 {
		t.Fatalf("ensure must not re-open an existing epoch, got %d", state.CoverageEpoch)
	}
	// Surface grows mid-epoch — the frozen denominator must not move.
	state.DiscoveredEndpoints = append(state.DiscoveredEndpoints, "/c")
	if got := coverageDenominator(state); len(got) != 2 {
		t.Fatalf("mid-epoch growth must not change the frozen denominator, got %v", got)
	}
	if !surfaceBeyondBaseline(state) {
		t.Fatal("surfaceBeyondBaseline must detect the new endpoint /c")
	}
}

// The core no-compromise guarantee: an endpoint discovered mid-epoch does not
// silently drop out of coverage. When the frozen epoch is fully covered and new
// surface exists, the epoch advances, folds the new endpoint into the baseline,
// and REOPENS the class task so the new endpoint is actually tested.
func TestAdvanceCoverageEpochReopensNewlyDiscoveredEndpoints(t *testing.T) {
	host := "https://app.example.com:9000"
	x, y, z := host+"/x", host+"/y", host+"/z"

	state := NewScanState()
	state.EpochCoverage = true
	state.ScanTargets = []string{host}
	state.DiscoveredEndpoints = []string{x, y}

	task := newCoverageTask("sqli", state.DiscoveredEndpoints)
	task.Status = TaskCompleted // epoch 1 already covered x, y
	state.Plan = NewPlan()
	state.Plan.Tasks = []*Task{task}
	state.CoverageEpoch = 1
	state.CoverageBaseline = []string{x, y}
	markEndpointClassCoverage(state, x, "sqli")
	markEndpointClassCoverage(state, y, "sqli")

	// Sanity: x and y must actually be SQLi obligations, else the test proves
	// nothing about convergence.
	if applicable := ApplicableEndpointsForClass(state, "sqli"); len(applicable) < 2 {
		t.Fatalf("test precondition: x and y must be SQLi obligations, got %v", applicable)
	}

	// A new endpoint appears mid-epoch, not yet covered.
	state.DiscoveredEndpoints = append(state.DiscoveredEndpoints, z)

	// Against the FROZEN baseline [x,y] the task stays complete — the new
	// endpoint cannot reopen the current epoch.
	if !taskCoverageComplete(state, task) {
		t.Fatal("frozen baseline [x,y] is fully covered; task must stay complete pre-advance")
	}

	// Advance: obligations met + new surface → epoch 2, z folded in, task reopened.
	if !advanceCoverageEpoch(state) {
		t.Fatal("expected an epoch advance when obligations are met and new surface exists")
	}
	if state.CoverageEpoch != 2 {
		t.Fatalf("expected epoch 2 after advance, got %d", state.CoverageEpoch)
	}
	foundZ := false
	for _, e := range state.CoverageBaseline {
		if e == z {
			foundZ = true
		}
	}
	if !foundZ {
		t.Fatal("no-compromise violation: the newly discovered endpoint was dropped from the baseline")
	}
	if task.Status != TaskPending {
		t.Fatalf("no-compromise violation: the class task must reopen for the untested endpoint, got %s", task.Status)
	}

	// Cover z → task completes, and with no surface beyond the baseline the scan
	// has converged (advance is a no-op).
	markEndpointClassCoverage(state, z, "sqli")
	task.Status = TaskCompleted
	if advanceCoverageEpoch(state) {
		t.Fatal("no surface remains beyond the baseline; advance must be a no-op (converged)")
	}
	if !taskCoverageComplete(state, task) {
		t.Fatal("every endpoint incl. z is covered; the task must be complete at convergence")
	}
}

// reconcilePlan opens the first epoch when the flag is on, so the whole
// reconcile path measures coverage against a frozen denominator.
func TestReconcilePlanOpensEpochWhenFlagOn(t *testing.T) {
	state := NewScanState()
	state.EpochCoverage = true
	state.DiscoveredEndpoints = []string{"/api/x", "/api/y"}
	state.Plan = AutoPlan(state.DiscoveredEndpoints, nil)

	reconcilePlan(state)
	if state.CoverageEpoch != 1 {
		t.Fatalf("reconcilePlan must open epoch 1 when the flag is on, got %d", state.CoverageEpoch)
	}
	if len(state.CoverageBaseline) != 2 {
		t.Fatalf("epoch baseline must freeze the 2 discovered endpoints, got %v", state.CoverageBaseline)
	}
}
