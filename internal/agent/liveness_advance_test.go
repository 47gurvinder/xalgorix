package agent

import (
	"fmt"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// advance-past-stuck recovery: a scan that stalls on one un-completable task
// should skip that task and continue with the rest of its plan instead of
// terminating the whole scan, while staying honest (the skipped task is blocked
// work, not completed coverage) and bounded (a scan blocked on everything still
// stops after MaxStuckAdvances consecutive no-progress advances).

func stuckAgent(t *testing.T, flag bool, maxAdv, pending int) (*Agent, *Plan) {
	t.Helper()
	plan := NewPlan()
	plan.add(&Task{ID: "t-active", Phase: 6, Status: TaskActive})
	for i := 0; i < pending; i++ {
		plan.add(&Task{ID: fmt.Sprintf("p%d", i), Phase: 8, Status: TaskPending})
	}
	state := NewScanState()
	state.Plan = plan
	a := &Agent{state: state, scanBudget: newScanBudget(), cfg: &config.Config{AdvancePastStuckTasks: flag, MaxStuckAdvances: maxAdv}}
	return a, plan
}

func TestAdvancePastStuckTaskMarksBlockedAndContinues(t *testing.T) {
	a, plan := stuckAgent(t, true, 3, 2)
	if !a.advancePastStuckTask() {
		t.Fatal("should advance when unfinished tasks remain")
	}
	at := plan.Get("t-active")
	if at.Status != TaskSkipped || at.Disposition != DispositionBlockedNoProgress {
		t.Fatalf("stuck task should be skipped/blocked_no_progress, got status=%s disp=%s", at.Status, at.Disposition)
	}
	// Honest completion: a blocked_ disposition is blocked work, never silently
	// folded into "completed".
	if !scanHasBlockedWork(a.state, "") {
		t.Fatal("blocked_no_progress must register as blocked work for completion honesty")
	}
	// The pending tasks are still there to work.
	if p := plan.Get("p0"); p == nil || p.Status != TaskPending {
		t.Fatal("remaining pending tasks must be preserved")
	}
}

func TestAdvancePastStuckTaskNoRemainingWork(t *testing.T) {
	// Only the active (stuck) task plus completed ones: nothing to move on to.
	plan := NewPlan()
	plan.add(&Task{ID: "t-active", Status: TaskActive})
	plan.add(&Task{ID: "t-done", Status: TaskCompleted})
	state := NewScanState()
	state.Plan = plan
	a := &Agent{state: state, scanBudget: newScanBudget(), cfg: &config.Config{AdvancePastStuckTasks: true, MaxStuckAdvances: 3}}
	if a.advancePastStuckTask() {
		t.Fatal("must not advance when no unfinished tasks remain to move on to")
	}
}

func TestSemanticLivenessFlagOffStopsAtLimit(t *testing.T) {
	a, _ := stuckAgent(t, false, 3, 5)
	a.state.ProgressIdleIterations = semanticNonProgressLimit - 1
	res := a.semanticLivenessCheck()
	if res.StopReason != "stuck_loop_limit" {
		t.Fatalf("with the flag off the scan must stop at the idle limit, got %+v", res)
	}
}

func TestSemanticLivenessAdvancesThenStopsWhenBlockedEverywhere(t *testing.T) {
	const maxAdv = 2
	a, plan := stuckAgent(t, true, maxAdv, 5)
	advances, stops := 0, 0
	for i := 0; i < maxAdv+2; i++ {
		a.state.ProgressIdleIterations = semanticNonProgressLimit // force the stall
		res := a.semanticLivenessCheck()
		if res.StopReason != "" {
			stops++
			break
		}
		advances++
		// Simulate the agent picking up another task but still making no progress.
		for _, tk := range plan.Tasks {
			if tk.Status == TaskPending {
				tk.Status = TaskActive
				break
			}
		}
	}
	if advances != maxAdv || stops != 1 {
		t.Fatalf("expected %d advances then a stop (blocked everywhere), got advances=%d stops=%d", maxAdv, advances, stops)
	}
}

func TestSemanticLivenessTimeBasedAdvanceOnSlowScan(t *testing.T) {
	// A SLOW scan: the 160-iteration counter is nowhere near its limit, but most
	// of the wall-clock idle budget is spent. Only the time-based trigger can
	// rescue it before the idle watchdog would kill it.
	a, _ := stuckAgent(t, true, 3, 5)
	a.cfg.MaxNonProgressSec = 3600
	a.state.ProgressIdleIterations = 10                         // far below semanticNonProgressLimit (160)
	a.scanBudget.progressAt = time.Now().Add(-59 * time.Minute) // ~1 min left of a 60-min budget
	res := a.semanticLivenessCheck()
	if res.StopReason != "" {
		t.Fatalf("slow stuck scan must advance via the time-based trigger, not stop: %+v", res)
	}
	if a.state.StuckAdvancesSinceProgress != 1 {
		t.Fatalf("expected one time-based advance recorded, got %d", a.state.StuckAdvancesSinceProgress)
	}
	// Flag OFF: the same slow stall must fall through (no advance; watchdog governs).
	b, _ := stuckAgent(t, false, 3, 5)
	b.cfg.MaxNonProgressSec = 3600
	b.state.ProgressIdleIterations = 10
	b.scanBudget.progressAt = time.Now().Add(-59 * time.Minute)
	if res := b.semanticLivenessCheck(); res.StopReason != "" || b.state.StuckAdvancesSinceProgress != 0 {
		t.Fatalf("flag off must not advance: stop=%q advances=%d", res.StopReason, b.state.StuckAdvancesSinceProgress)
	}
}

func TestSemanticLivenessRealProgressReplenishesAdvanceBudget(t *testing.T) {
	a, _ := stuckAgent(t, true, 1, 5)
	// First stall → one advance (budget 1 now spent).
	a.state.ProgressIdleIterations = semanticNonProgressLimit
	if res := a.semanticLivenessCheck(); res.StopReason != "" {
		t.Fatalf("first stall should advance, not stop: %+v", res)
	}
	if a.state.StuckAdvancesSinceProgress != 1 {
		t.Fatalf("expected one advance recorded, got %d", a.state.StuckAdvancesSinceProgress)
	}
	// Real progress happens → the budget replenishes.
	a.scanBudget.progress.Add(1)
	a.state.ProgressIdleIterations = 0
	if res := a.semanticLivenessCheck(); res.StopReason != "" {
		t.Fatalf("progress turn must not stop: %+v", res)
	}
	if a.state.StuckAdvancesSinceProgress != 0 {
		t.Fatalf("real progress must reset the advance budget, got %d", a.state.StuckAdvancesSinceProgress)
	}
}
