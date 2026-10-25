package llm

import (
	"testing"
	"time"
)

func TestKeyRotatorRoundRobin(t *testing.T) {
	r := NewKeyRotator([]string{"a", "b", "c"})
	seen := map[string]int{}
	for range 6 {
		seen[r.Pick()]++
	}
	for _, k := range []string{"a", "b", "c"} {
		if seen[k] != 2 {
			t.Fatalf("expected 2 picks for %q, got %d", k, seen[k])
		}
	}
}

func TestKeyRotatorDedupAndEmpty(t *testing.T) {
	if got := NewKeyRotator(nil); got != nil {
		t.Fatal("nil input must yield nil rotator")
	}
	r := NewKeyRotator([]string{"a", "", "a", "b"})
	if r.Len() != 2 {
		t.Fatalf("expected dedupe to 2 keys, got %d", r.Len())
	}
}

func TestKeyRotatorCooldownSkip(t *testing.T) {
	r := NewKeyRotator([]string{"a", "b"})
	first := r.Pick()
	r.MarkLastRateLimited()
	next := r.Pick()
	if next == first {
		t.Fatalf("expected cooldown to skip %q", first)
	}
	// While `first` cools, every pick must land on the other key.
	for range 3 {
		if got := r.Pick(); got != next {
			t.Fatalf("expected %q while %q cools, got %q", next, first, got)
		}
	}
}

func TestKeyRotatorAllCoolingFallsBack(t *testing.T) {
	r := NewKeyRotator([]string{"a"})
	k := r.Pick()
	r.MarkLastRateLimited()
	if got := r.Pick(); got != k {
		t.Fatalf("single-key pool must still return its key, got %q", got)
	}
}

func TestKeyRotatorAllCoolingPicksPooled(t *testing.T) {
	r := NewKeyRotator([]string{"a", "b"})
	a := r.Pick()
	r.MarkLastRateLimited()
	b := r.Pick()
	r.MarkLastRateLimited()
	// Both cooling: pick must still return one of the pool keys.
	got := r.Pick()
	if got != a && got != b {
		t.Fatalf("expected a pooled key, got %q", got)
	}
}

func TestKeyRotatorQuotaExhaustedLongerCooldown(t *testing.T) {
	r := NewKeyRotator([]string{"a", "b"})
	// A key rejected with quota_exhausted gets a much longer cooldown than a
	// transient rate limit, so the rotator stops thrashing requests back onto a
	// key whose usage window is drained (every keyPoolCooldown) and instead
	// concentrates on keys with available quota.
	q := r.Pick()
	r.MarkLastQuotaExhausted()
	quotaUntil := r.cooldown[q]

	rl := r.Pick()
	r.MarkLastRateLimited()
	rlUntil := r.cooldown[rl]

	if q == rl {
		t.Fatalf("precondition: expected two distinct keys, got %q twice", q)
	}
	if quotaUntil.Sub(rlUntil) < 5*time.Minute {
		t.Fatalf("quota-exhausted cooldown must be far longer than the transient one: quota=%v rate_limit=%v", quotaUntil, rlUntil)
	}
	// The quota-exhausted key has the longest cooldown, so every pick must land
	// on the other (sooner-expiring) key while it cools.
	for range 4 {
		if got := r.Pick(); got == q {
			t.Fatalf("quota-exhausted key %q must stay skipped while cooling", q)
		}
	}
}
