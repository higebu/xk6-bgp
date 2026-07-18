// Package coord provides cross-VU synchronization primitives that
// xk6-bgp exposes to k6 scripts. Each k6 VU has its own JS runtime
// and goroutine; they cannot share Go pointers through ordinary JS
// values. The Registry here lives on the xk6 RootModule (created
// once per k6 process), so VUs can look up the same primitive by
// name and coordinate.
package coord

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ErrBarrierTimeout is returned by ArriveTimeout when the rendezvous
// does not complete within the given duration.
var ErrBarrierTimeout = errors.New("barrier: timed out waiting for participants")

// Barrier blocks every caller of Arrive() until Target callers have
// arrived, then releases all of them. Subsequent Arrive() calls
// return immediately (the barrier is single-use). A separate barrier
// instance is needed for a separate rendezvous.
type Barrier struct {
	target  int64
	arrived atomic.Int64
	done    chan struct{}
}

func NewBarrier(target int) (*Barrier, error) {
	if target <= 0 {
		return nil, errors.New("barrier: target must be > 0")
	}
	return &Barrier{
		target: int64(target),
		done:   make(chan struct{}),
	}, nil
}

// Arrive registers this caller and blocks until Target callers have
// arrived. Returns the 1-based index of this caller within the
// rendezvous so callers can detect who "tripped" the barrier (the
// caller whose index equals Target is the one that completed it).
func (b *Barrier) Arrive() int64 {
	n, _ := b.ArriveTimeout(0)
	return n
}

// ArriveTimeout is Arrive with an upper bound on the wait; d <= 0
// waits forever. On timeout the arrival is NOT withdrawn — the caller
// still counts toward Target, so a VU that gives up and aborts does
// not additionally wedge the VUs still waiting.
func (b *Barrier) ArriveTimeout(d time.Duration) (int64, error) {
	n := b.arrived.Add(1)
	if n == b.target {
		close(b.done)
	}
	if d <= 0 {
		<-b.done
		return n, nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-b.done:
		return n, nil
	case <-timer.C:
		return n, ErrBarrierTimeout
	}
}

// Registry stores Barriers by name. Multiple VUs requesting the same
// name + target receive the same Barrier instance, so they all
// rendezvous at the same point.
type Registry struct {
	mu       sync.Mutex
	barriers map[string]*Barrier
}

func NewRegistry() *Registry {
	return &Registry{barriers: map[string]*Barrier{}}
}

// Barrier returns the named Barrier, creating it with the given
// target if it does not exist. If a barrier with the same name
// already exists with a different target the second caller's target
// is ignored — the first creator wins, which is the natural
// expectation when N VUs each call Barrier(name, N).
func (r *Registry) Barrier(name string, target int) (*Barrier, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if b, ok := r.barriers[name]; ok {
		return b, nil
	}
	b, err := NewBarrier(target)
	if err != nil {
		return nil, err
	}
	r.barriers[name] = b
	return b, nil
}
