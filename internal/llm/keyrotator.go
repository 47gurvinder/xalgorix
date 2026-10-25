// API-key pool rotation for provider rate limits.
//
// KeyRotator spreads outbound API-key-authenticated requests across a
// pool of operator-configured keys (XALGORIX_API_KEYS plus
// XALGORIX_API_KEY). Picks advance round-robin, so a pool of N keys
// raises the effective provider rate ceiling roughly N times. When a
// request fails with a provider rate limit (429 / usage-window), the
// key it used enters a short cooldown and subsequent picks skip it
// until the cooldown expires, concentrating traffic on the remaining
// keys.
//
// Thread-safe: concurrent chatWithRetry / ChatStream goroutines from
// parallel scans share one rotator per llm.Client.

package llm

import (
	"sync"
	"time"
)

// keyPoolCooldown is how long a rate-limited key is skipped before it
// becomes eligible again. It exceeds chatWithRetry's 30s rate-limit
// backoff so the retry immediately following a 429 lands on a
// different key; the cooled key returns once the provider's window
// has very likely reset.
const keyPoolCooldown = 90 * time.Second

// keyPoolQuotaCooldown is the longer cooldown applied when a key is rejected
// with quota_exhausted (account balance / usage-window exhaustion). That state
// lasts far longer than a transient per-minute rate limit, so the short
// cooldown above would thrash requests straight back onto the dead key every
// 90s. The longer cooldown keeps the key out of rotation and re-probes it only
// occasionally, so it rejoins once the provider's usage window resets.
const keyPoolQuotaCooldown = 15 * time.Minute

// KeyRotator hands out keys from a fixed pool in round-robin order,
// skipping keys that are cooling down after a rate limit.
type KeyRotator struct {
	mu       sync.Mutex
	keys     []string
	idx      int
	cooldown map[string]time.Time
	last     string
	// sticky selects overflow-failover instead of round-robin: keep using one key
	// until it enters cooldown, then fail over to the next and stay there. Set once
	// at construction via SetSticky.
	sticky bool
}

// NewKeyRotator builds a rotator from the given candidate keys. Empty
// entries and duplicates are dropped; order is preserved. Returns nil
// when no usable key remains so callers can leave the feature off.
func NewKeyRotator(keys []string) *KeyRotator {
	deduped := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		if k == "" {
			continue
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		deduped = append(deduped, k)
	}
	if len(deduped) == 0 {
		return nil
	}
	return &KeyRotator{
		keys:     deduped,
		cooldown: make(map[string]time.Time),
	}
}

// Pick returns the next eligible key, advancing round-robin and
// skipping keys still in cooldown. When every key is cooling down it
// returns the key whose cooldown expires soonest instead of failing:
// the caller still needs a key to attempt, and its own bounded
// backoff prevents hammering.
func (r *KeyRotator) Pick() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if r.sticky {
		return r.pickStickyLocked(now)
	}
	return r.pickRoundRobinLocked(now)
}

// pickRoundRobinLocked advances one key per call, skipping cooling keys — both
// keys carry load simultaneously, raising the effective rate ceiling.
func (r *KeyRotator) pickRoundRobinLocked(now time.Time) string {
	for range r.keys {
		k := r.keys[r.idx%len(r.keys)]
		r.idx++
		until, cooling := r.cooldown[k]
		if !cooling || now.After(until) {
			delete(r.cooldown, k)
			r.last = k
			return k
		}
	}
	return r.pickSoonestLocked()
}

// pickStickyLocked keeps returning the current key until it enters cooldown, then
// fails over to the next eligible key and stays there (overflow failover): one key
// at a time, switching only on a rate limit, so an idle key is held in reserve.
func (r *KeyRotator) pickStickyLocked(now time.Time) string {
	for i := 0; i < len(r.keys); i++ {
		j := (r.idx + i) % len(r.keys)
		k := r.keys[j]
		until, cooling := r.cooldown[k]
		if !cooling || now.After(until) {
			delete(r.cooldown, k)
			r.idx = j // stick to this key until it too cools
			r.last = k
			return k
		}
	}
	return r.pickSoonestLocked()
}

// pickSoonestLocked returns the key whose cooldown expires soonest, used when every
// key is cooling: the caller still needs a key to attempt, and its own bounded
// backoff prevents hammering.
func (r *KeyRotator) pickSoonestLocked() string {
	best := ""
	var bestUntil time.Time
	for _, k := range r.keys {
		until := r.cooldown[k]
		if best == "" || until.Before(bestUntil) {
			best, bestUntil = k, until
		}
	}
	r.last = best
	return best
}

// SetSticky switches the rotator between round-robin (false, default) and
// overflow-failover (true). In sticky mode the rotator keeps returning one key
// until that key enters cooldown, then fails over to the next and stays there,
// instead of alternating every request. Intended to be set once at construction.
func (r *KeyRotator) SetSticky(v bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sticky = v
}

// MarkLastRateLimited puts the key most recently returned by Pick into the
// short transient-rate-limit cooldown so subsequent picks concentrate on the
// remaining keys.
func (r *KeyRotator) MarkLastRateLimited() {
	r.markLast(keyPoolCooldown)
}

// MarkLastQuotaExhausted puts the key most recently returned by Pick into the
// longer quota-exhausted cooldown (see keyPoolQuotaCooldown), so the rotator
// stops routing requests to a key whose usage window is drained until it very
// likely resets, instead of thrashing back onto it every 90s.
func (r *KeyRotator) MarkLastQuotaExhausted() {
	r.markLast(keyPoolQuotaCooldown)
}

// markLast cools the key most recently returned by Pick for the given duration.
func (r *KeyRotator) markLast(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last == "" {
		return
	}
	r.cooldown[r.last] = time.Now().Add(d)
}

// Len reports how many distinct keys the pool holds.
func (r *KeyRotator) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.keys)
}

// Contains reports whether key is one of the pooled keys. Used so the client can
// rotate an endpoint that already carries a pooled key (e.g. a provider profile
// that resolved to the first key while XALGORIX_API_KEY is empty), without ever
// touching a credential that is not in the operator's own pool.
func (r *KeyRotator) Contains(key string) bool {
	if r == nil || key == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, k := range r.keys {
		if k == key {
			return true
		}
	}
	return false
}
