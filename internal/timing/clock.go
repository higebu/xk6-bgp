// Package timing centralizes timestamp acquisition. Every wire event
// takes its timestamp through Now() so wall and monotonic readings stay
// paired. Convergence is reported in microseconds, so accessors expose
// µs directly.
package timing

import "time"

type Timestamp struct {
	t time.Time
}

func Now() Timestamp { return Timestamp{t: time.Now()} }

func (ts Timestamp) Time() time.Time { return ts.t }

func (ts Timestamp) WallNs() int64 { return ts.t.UnixNano() }

// MonoNs returns nanoseconds since monoEpoch. The absolute value is
// process-local; only diffs between MonoNs readings are meaningful.
func (ts Timestamp) MonoNs() int64 {
	return ts.t.Sub(monoEpoch).Nanoseconds()
}

func (ts Timestamp) Sub(other Timestamp) time.Duration {
	return ts.t.Sub(other.t)
}

func (ts Timestamp) SubMicros(other Timestamp) int64 {
	return ts.t.Sub(other.t).Microseconds()
}

// FromMonoNs reconstructs a Timestamp from a previously emitted MonoNs
// reading. The reconstructed value has the same Time().Sub semantics
// as the original within this process; wall-clock readings reflect the
// re-derived time.Time, which is fine for ordering checks but not for
// emitting back as WallNs.
func FromMonoNs(monoNs int64) Timestamp {
	return Timestamp{t: monoEpoch.Add(time.Duration(monoNs))}
}

var monoEpoch = time.Now()
