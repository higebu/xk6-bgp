package bgp

import (
	"fmt"

	"github.com/grafana/sobek"
	"github.com/higebu/xk6-bgp/internal/coord"
)

// Barrier is the JS-facing wrapper around coord.Barrier. Construct
// one with `bgp.barrier(name, count)`; all VUs that call the same
// name with the same count share the underlying rendezvous.
type Barrier struct {
	impl *coord.Barrier
}

// barrier resolves (or creates) a named barrier from the root
// module's registry. It is bound to JS as `bgp.barrier(name, count)`.
func (mi *ModuleInstance) barrier(name string, count int) (*Barrier, error) {
	b, err := mi.root.barriers.Barrier(name, count)
	if err != nil {
		return nil, err
	}
	return &Barrier{impl: b}, nil
}

// Arrive blocks until every other holder of this Barrier has also
// called Arrive(). Returns the 1-based arrival order so callers can
// tell who completed the rendezvous (the caller whose return value
// equals `count` was the last to arrive).
//
// The optional timeout (duration string or seconds number, e.g.
// `arrive('60s')`) bounds the wait and throws when it elapses; a VU
// that never reaches its arrive() — a failed open(), typically — would
// otherwise leave every other VU blocked until the scenario's
// maxDuration. A timed-out arrival still counts toward the barrier's
// target so the remaining VUs are not wedged a second time.
func (b *Barrier) Arrive(timeout sobek.Value) (int64, error) {
	d, err := valueDuration(timeout)
	if err != nil {
		return 0, fmt.Errorf("arrive: timeout: %w", err)
	}
	n, err := b.impl.ArriveTimeout(d)
	if err != nil {
		return n, fmt.Errorf("arrive: %w", err)
	}
	return n, nil
}
