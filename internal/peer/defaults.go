// Package peer implements xk6-bgp's BGP session: one TCP/179 connection
// driven by a hand-rolled FSM. gobgp's pkg/packet/bgp does wire-level
// encode/decode; no RIB, policy, or best-path is kept here on purpose.
package peer

import "time"

// RFC 4271 section 10 recommended defaults.
const (
	DefaultHoldTime    = 180 * time.Second
	DefaultOpenTimeout = 30 * time.Second
)

type SessionTimers struct {
	HoldTime    time.Duration
	OpenTimeout time.Duration
}

func (s *SessionTimers) ApplyDefaults() {
	if s.HoldTime == 0 {
		s.HoldTime = DefaultHoldTime
	}
	if s.OpenTimeout == 0 {
		s.OpenTimeout = DefaultOpenTimeout
	}
}
