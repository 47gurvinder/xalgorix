package agent

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

// newIdleTestAgent builds a minimal root agent whose plan is fully exhausted
// (one completed task, nothing pending/active) with a small finding-idle limit.
func newIdleTestAgent(t *testing.T, limit int) *Agent {
	t.Helper()
	state := NewScanState()
	state.MinIterations = 0
	state.Plan = NewPlan()
	state.Plan.add(&Task{ID: "done", Phase: 6, VulnClass: "sqli", Endpoint: "/search", Status: TaskCompleted})
	return &Agent{
		state:      state,
		scanBudget: newScanBudget(),
		cfg:        &config.Config{PlanCompleteFindingIdle: limit},
		events:     make(chan Event, 64),
	}
}

func TestAutoFinalizeFiresAfterPlanCompleteFindingIdle(t *testing.T) {
	a := newIdleTestAgent(t, 5)
	// No scanCtx → zero findings throughout; plan is exhausted.
	for i := 0; i < 4; i++ {
		a.state.Iteration = i + 1
		if a.autoFinalizeIfPlanComplete() {
			t.Fatalf("finalized early at idle iteration %d (limit 5)", i+1)
		}
	}
	a.state.Iteration = 5
	if !a.autoFinalizeIfPlanComplete() {
		t.Fatalf("did not finalize once the finding-idle limit was reached (idle=%d)", a.state.FindingIdleIterations)
	}
	// The graceful terminal event must have been emitted.
	var finished bool
	for {
		select {
		case ev := <-a.events:
			if ev.Type == "finished" {
				finished = true
			}
			continue
		default:
		}
		break
	}
	if !finished {
		t.Fatal("auto-finalize did not emit a terminal finished event")
	}
}

func TestAutoFinalizeBlockedWhilePlanHasPendingWork(t *testing.T) {
	a := newIdleTestAgent(t, 3)
	a.state.Plan.add(&Task{ID: "pending", Phase: 7, VulnClass: "xss", Endpoint: "/q", Status: TaskActive})
	for i := 0; i < 50; i++ {
		a.state.Iteration = i + 1
		if a.autoFinalizeIfPlanComplete() {
			t.Fatalf("finalized with pending/active plan work at iteration %d", i+1)
		}
	}
	if a.state.FindingIdleIterations != 0 {
		t.Fatalf("idle counter advanced while plan work remained: %d", a.state.FindingIdleIterations)
	}
}

func TestAutoFinalizeResetsOnNewFinding(t *testing.T) {
	ctxID := "idle-reset-ctx"
	dir := t.TempDir()
	sctx := scanctx.New(ctxID, dir)
	t.Cleanup(sctx.Close)
	t.Cleanup(func() { reporting.CleanupContext(sctx.ID) })

	a := newIdleTestAgent(t, 5)
	a.scanCtx = sctx

	// Accrue idle up to just below the limit.
	for i := 0; i < 4; i++ {
		a.state.Iteration = i + 1
		if a.autoFinalizeIfPlanComplete() {
			t.Fatalf("finalized early at %d", i+1)
		}
	}
	// A new finding lands → the next check must reset the idle counter.
	if err := reporting.RestoreContext(sctx.ID, dir, []reporting.Vulnerability{
		{ID: "XALG-1", Title: "SQLi", Target: "https://t.invalid", Endpoint: "/search", Method: "GET"},
	}); err != nil {
		t.Fatal(err)
	}
	a.state.Iteration = 5
	if a.autoFinalizeIfPlanComplete() {
		t.Fatal("a brand-new finding failed to reset the finding-idle tail")
	}
	if a.state.FindingIdleIterations != 0 {
		t.Fatalf("new finding did not reset idle counter: %d", a.state.FindingIdleIterations)
	}
}

func TestAutoFinalizeGatedForSpecialistsAndWhenDisabled(t *testing.T) {
	// Delegated specialist: never auto-finalizes (owns one lane).
	a := newIdleTestAgent(t, 1)
	a.state.DelegatedAgent = true
	a.state.Iteration = 100
	if a.autoFinalizeIfPlanComplete() {
		t.Fatal("delegated specialist was auto-finalized")
	}
	// Negative limit disables the stop entirely.
	b := newIdleTestAgent(t, -1)
	for i := 0; i < 50; i++ {
		b.state.Iteration = i + 1
		if b.autoFinalizeIfPlanComplete() {
			t.Fatal("disabled (negative) limit still finalized")
		}
	}
}
