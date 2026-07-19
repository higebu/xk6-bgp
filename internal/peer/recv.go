package peer

import (
	"errors"
	"fmt"
	"sync"
	"time"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/higebu/xk6-bgp/internal/timing"
)

// observedSet stores the receiver state. Prefix keys are NLRI.String()
// (canonical for IP unicast and round-trips through MP NLRI for the
// MUP T1ST / T2ST families). For each prefix only the FirstSeen
// timestamp and a "currently withdrawn?" bit are kept — that is all
// WaitForPrefixes needs, and avoiding a per-prefix struct keeps the
// receive hot path off mallocgc when a single UPDATE carries
// thousands of NLRI.
type observedSet struct {
	mu sync.Mutex

	// failedErr is set once when the session dies (NOTIFICATION, hold
	// timer expiry, read error). It releases current and future waiters
	// immediately instead of letting them run out their timeout.
	failedErr error

	firstSeen map[string]timing.Timestamp
	withdrawn map[string]struct{}

	updateSeq    uint64
	advertiseN    uint64
	withdrawN    uint64
	lastUpdateAt timing.Timestamp
	firstUpdate  timing.Timestamp

	waiters []*waiter
}

// waiter is what a single WaitForPrefixes call holds while blocked.
// pending tracks the prefixes that still have to be observed (or
// re-observed if they came back from a withdraw). applyUpdate strikes
// keys off pending directly, so WaitForPrefixes does not have to scan
// the full want list on every wakeup. done is closed once pending
// reaches empty; it is fired at most once.
type waiter struct {
	want      map[string]struct{}
	pending   map[string]struct{}
	onlyAfter time.Time
	first     timing.Timestamp
	last      timing.Timestamp

	done     chan struct{}
	doneOnce sync.Once
}

func (w *waiter) markDone() {
	w.doneOnce.Do(func() { close(w.done) })
}

func newObservedSet() *observedSet {
	return &observedSet{
		firstSeen: make(map[string]timing.Timestamp, 1024),
		withdrawn: make(map[string]struct{}),
	}
}

// applyUpdate records reach/unreach NLRI. With ADD-PATH receive
// negotiated for the family (addPath true) the key is
// PathNLRI.String() — "<prefix>:<path-id>" — so the same prefix under
// different Path Identifiers counts as distinct routes per RFC 7911
// section 3; otherwise it stays the plain NLRI.String().
func (o *observedSet) applyUpdate(_ bgp.Family, addPath bool, ts timing.Timestamp, reach, unreach []bgp.PathNLRI) {
	o.mu.Lock()
	o.updateSeq++
	if o.firstUpdate.Time().IsZero() {
		o.firstUpdate = ts
	}
	o.lastUpdateAt = ts

	for i := range reach {
		key := reach[i].NLRI.String()
		if addPath {
			key = reach[i].String()
		}
		fs, seen := o.firstSeen[key]
		if !seen {
			o.firstSeen[key] = ts
			fs = ts
		}
		delete(o.withdrawn, key)
		o.advertiseN++
		o.notifyReach(key, fs, ts)
	}
	for i := range unreach {
		key := unreach[i].NLRI.String()
		if addPath {
			key = unreach[i].String()
		}
		o.withdrawn[key] = struct{}{}
		o.withdrawN++
		o.notifyWithdraw(key)
	}
	o.mu.Unlock()
}

// notifyReach updates every waiter that is waiting on key. Caller
// holds o.mu.
func (o *observedSet) notifyReach(key string, firstSeen, ts timing.Timestamp) {
	if len(o.waiters) == 0 {
		return
	}
	for _, w := range o.waiters {
		if _, want := w.want[key]; !want {
			continue
		}
		// FirstSeen-sticky cutoff: only an observation whose
		// FirstSeen is at or after onlyAfter counts. A prefix
		// re-advertised after onlyAfter still does not satisfy the
		// waiter if its FirstSeen predates the cutoff.
		if !w.onlyAfter.IsZero() && firstSeen.Time().Before(w.onlyAfter) {
			continue
		}
		if _, pending := w.pending[key]; pending {
			delete(w.pending, key)
			if w.first.Time().IsZero() || firstSeen.Time().Before(w.first.Time()) {
				w.first = firstSeen
			}
		}
		if w.last.Time().IsZero() || ts.Time().After(w.last.Time()) {
			w.last = ts
		}
		if len(w.pending) == 0 {
			w.markDone()
		}
	}
}

// notifyWithdraw re-arms every waiter that cares about key by putting
// it back into pending. Caller holds o.mu.
func (o *observedSet) notifyWithdraw(key string) {
	if len(o.waiters) == 0 {
		return
	}
	for _, w := range o.waiters {
		if _, want := w.want[key]; !want {
			continue
		}
		w.pending[key] = struct{}{}
	}
}

func (o *observedSet) registerWaiter(want []string, onlyAfter timing.Timestamp) *waiter {
	w := &waiter{
		want:      make(map[string]struct{}, len(want)),
		pending:   make(map[string]struct{}, len(want)),
		onlyAfter: onlyAfter.Time(),
		done:      make(chan struct{}),
	}
	o.mu.Lock()
	for _, p := range want {
		w.want[p] = struct{}{}
		fs, observed := o.firstSeen[p]
		_, gone := o.withdrawn[p]
		matched := observed && !gone && (w.onlyAfter.IsZero() || !fs.Time().Before(w.onlyAfter))
		if matched {
			if w.first.Time().IsZero() || fs.Time().Before(w.first.Time()) {
				w.first = fs
			}
			if w.last.Time().IsZero() || o.lastUpdateAt.Time().After(w.last.Time()) {
				w.last = o.lastUpdateAt
			}
			continue
		}
		w.pending[p] = struct{}{}
	}
	if len(w.pending) == 0 || o.failedErr != nil {
		w.markDone()
	} else {
		o.waiters = append(o.waiters, w)
	}
	o.mu.Unlock()
	return w
}

// fail records the session-fatal error and releases every blocked
// waiter. Called from fsm.fail; waiters report their unmatched
// prefixes as missing together with the session error.
func (o *observedSet) fail(err error) {
	o.mu.Lock()
	if o.failedErr == nil {
		o.failedErr = err
	}
	for _, w := range o.waiters {
		w.markDone()
	}
	o.mu.Unlock()
}

// failureCause returns the error recorded by fail, or nil if the
// session has not failed.
func (o *observedSet) failureCause() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.failedErr
}

func (o *observedSet) deregisterWaiter(w *waiter) {
	o.mu.Lock()
	for i, x := range o.waiters {
		if x == w {
			o.waiters = append(o.waiters[:i], o.waiters[i+1:]...)
			break
		}
	}
	o.mu.Unlock()
}

// WaitResult is the value returned by Peer.WaitForPrefixes. FirstSeen
// is the timestamp at which the *first* matched prefix was observed,
// LastSeen the *last*. Missing lists any prefixes that did not arrive
// before the deadline. Together with the advertise-side SentAt this is
// the input to bgp_prefix_received_duration.
type WaitResult struct {
	Matched   int
	Missing   []string
	FirstSeen timing.Timestamp
	LastSeen  timing.Timestamp
}

// WaitForPrefixes blocks until every prefix in want has been observed
// in a non-withdrawn state, or timeout elapses. If onlyAfter is
// non-zero, observations whose FirstSeen predates it (e.g. leftover
// from a previous advertise on the same long-running session) do not
// count.
func (p *Peer) WaitForPrefixes(want []string, timeout time.Duration, onlyAfter timing.Timestamp) (WaitResult, error) {
	if p.fsm == nil {
		return WaitResult{}, ErrSessionNotReady
	}
	if len(want) == 0 {
		return WaitResult{}, errors.New("waitForPrefixes: prefixes must be non-empty")
	}

	o := p.fsm.observed
	w := o.registerWaiter(want, onlyAfter)
	defer o.deregisterWaiter(w)

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-w.done:
	case <-timer.C:
	}

	o.mu.Lock()
	missing := make([]string, 0, len(w.pending))
	for k := range w.pending {
		missing = append(missing, k)
	}
	res := WaitResult{
		Matched:   len(w.want) - len(missing),
		Missing:   missing,
		FirstSeen: w.first,
		LastSeen:  w.last,
	}
	failed := o.failedErr
	o.mu.Unlock()

	if len(missing) > 0 {
		if failed != nil {
			return res, fmt.Errorf("waitForPrefixes: session down (%w), missing %d/%d",
				failed, len(missing), len(want))
		}
		return res, fmt.Errorf("waitForPrefixes: timed out after %s, missing %d/%d",
			timeout, len(missing), len(want))
	}
	return res, nil
}

// Stats is a snapshot of cumulative receive counters. Cheap to call.
type Stats struct {
	Updates        uint64
	AdvertisedNLRI  uint64
	WithdrawnNLRI  uint64
	UniquePrefixes int
	FirstUpdateAt  timing.Timestamp
	LastUpdateAt   timing.Timestamp
}

func (p *Peer) Stats() Stats {
	if p.fsm == nil {
		return Stats{}
	}
	o := p.fsm.observed
	o.mu.Lock()
	defer o.mu.Unlock()
	return Stats{
		Updates:        o.updateSeq,
		AdvertisedNLRI:  o.advertiseN,
		WithdrawnNLRI:  o.withdrawN,
		UniquePrefixes: len(o.firstSeen),
		FirstUpdateAt:  o.firstUpdate,
		LastUpdateAt:   o.lastUpdateAt,
	}
}

// dispatchUpdate is called by readLoop on every UPDATE. MP_REACH and
// MP_UNREACH attributes are recorded under their own AFI/SAFI per RFC
// 4760 (both may legally appear in one UPDATE with different families).
// Legacy (non-MP) NLRI lists belong to the IPv4-unicast family.
func (f *fsm) dispatchUpdate(u *bgp.BGPUpdate, ts timing.Timestamp) {
	for _, a := range u.PathAttributes {
		switch v := a.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			fam := bgp.NewFamily(v.AFI, v.SAFI)
			f.observed.applyUpdate(fam, f.addPathReceive(fam), ts, v.Value, nil)
		case *bgp.PathAttributeMpUnreachNLRI:
			fam := bgp.NewFamily(v.AFI, v.SAFI)
			f.observed.applyUpdate(fam, f.addPathReceive(fam), ts, nil, v.Value)
		}
	}
	if len(u.NLRI) > 0 || len(u.WithdrawnRoutes) > 0 {
		f.observed.applyUpdate(bgp.RF_IPv4_UC, f.addPathReceive(bgp.RF_IPv4_UC), ts, u.NLRI, u.WithdrawnRoutes)
	}
}

// addPathReceive reports whether ADD-PATH receive was negotiated for
// fam, i.e. whether inbound NLRI for fam carry Path Identifiers.
func (f *fsm) addPathReceive(fam bgp.Family) bool {
	return f.addPathNegotiated[fam]&bgp.BGP_ADD_PATH_RECEIVE != 0
}
