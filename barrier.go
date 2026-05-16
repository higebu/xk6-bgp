package bgp

import "github.com/higebu/xk6-bgp/internal/coord"

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
func (b *Barrier) Arrive() int64 {
	return b.impl.Arrive()
}
