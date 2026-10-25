package agent

import "testing"

func crClassless(id, title string) *Task {
	return &Task{ID: id, Title: title, Status: TaskPending}
}

func crPending(s *ScanState) int {
	n := 0
	for _, t := range s.Plan.Tasks {
		if t.Status == TaskPending || t.Status == TaskActive {
			n++
		}
	}
	return n
}

// Base state: the measurable work (a class task + recon) is already terminal and
// only class-less exploratory tasks remain pending — the exact shape of a scan
// stuck churning at 100% systematic coverage.
func crState(flag bool) *ScanState {
	s := NewScanState()
	s.ConvergeReconcile = flag
	s.Iteration = 120
	s.MinIterations = 50
	s.Plan = NewPlan()
	s.Plan.Tasks = []*Task{
		{ID: "sqli-x", VulnClass: "sqli", Status: TaskCompleted},
		{ID: "recon", Status: TaskCompleted},
		crClassless("explore-advisory", "Next.js Image Optimizer RCE advisory"),
		crClassless("explore-pii", "Unauthenticated PII exposure on /api/public"),
	}
	return s
}

func TestMeasurableObligationsMet(t *testing.T) {
	s := NewScanState()
	s.Plan = NewPlan()

	s.Plan.Tasks = []*Task{crClassless("explore-1", "poke around")}
	if measurableObligationsMet(s) {
		t.Fatal("a plan with no measurable task must not report obligations met")
	}

	s.Plan.Tasks = []*Task{
		{ID: "sqli-x", VulnClass: "sqli", Status: TaskPending},
		crClassless("explore-1", "poke around"),
	}
	if measurableObligationsMet(s) {
		t.Fatal("a pending classed task must block convergence")
	}

	s.Plan.Tasks = []*Task{
		{ID: "sqli-x", VulnClass: "sqli", Status: TaskCompleted},
		{ID: "recon", Status: TaskCompleted},
		crClassless("explore-1", "poke around"),
	}
	if !measurableObligationsMet(s) {
		t.Fatal("all measurable tasks terminal must report obligations met")
	}
}

func TestConvergeReconcileClosesClasslessTasks(t *testing.T) {
	s := crState(true)
	reconcilePlan(s)
	if got := crPending(s); got != 0 {
		t.Fatalf("expected all class-less tasks reconciled, still pending=%d", got)
	}
	for _, task := range s.Plan.Tasks {
		if task.VulnClass != "" || task.ID == "recon" {
			continue
		}
		if task.Status != TaskSkipped || task.Disposition != DispositionCoverageComplete {
			t.Fatalf("class-less task %q: status=%s disposition=%q, want skipped/%q",
				task.ID, task.Status, task.Disposition, DispositionCoverageComplete)
		}
	}
}

func TestConvergeReconcileInertWhenFlagOff(t *testing.T) {
	s := crState(false)
	reconcilePlan(s)
	if got := crPending(s); got != 2 {
		t.Fatalf("flag off: class-less tasks must stay pending, pending=%d (want 2)", got)
	}
}

func TestConvergeReconcileRespectsMinIterations(t *testing.T) {
	s := crState(true)
	s.Iteration = 10 // below MinIterations (50)
	reconcilePlan(s)
	if got := crPending(s); got != 2 {
		t.Fatalf("below MinIterations: class-less tasks must stay pending, pending=%d (want 2)", got)
	}
}

func TestConvergeReconcileWaitsForMeasurableTasks(t *testing.T) {
	s := crState(true)
	s.Plan.Tasks[0].Status = TaskPending // a classed task still owes coverage
	reconcilePlan(s)
	for _, task := range s.Plan.Tasks {
		if task.ID == "explore-advisory" || task.ID == "explore-pii" {
			if task.Disposition == DispositionCoverageComplete {
				t.Fatalf("class-less task %q reconciled while a measurable task was still pending", task.ID)
			}
		}
	}
}
