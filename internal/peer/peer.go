package peer

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/higebu/xk6-bgp/internal/packet"
)

type Config struct {
	LocalAS  uint32
	PeerAS   uint32 // 0 = accept any
	RouterID netip.Addr
	Target   string

	// LocalAddress, when valid, is bound on the TCP socket before
	// connecting. Lets a single host drive many BGP sessions from
	// distinct source IPs (loopback aliases) so each session looks
	// like a separate peer to the DUT.
	LocalAddress netip.Addr

	Families []bgp.Family

	Timers SessionTimers
	Caps   packet.CapsConfig

	Tags map[string]string
}

// Validate runs the cheap field-level checks. It does not mutate the
// receiver — defaults are applied separately by ApplyDefaults so callers
// can re-Validate after editing without surprise.
func (c *Config) Validate() error {
	if c.LocalAS == 0 {
		return errors.New("localAS must be > 0")
	}
	if c.Target == "" {
		return errors.New("target is required (host:port)")
	}
	if !c.RouterID.IsValid() || !c.RouterID.Is4() {
		return errors.New("routerId must be an IPv4 address")
	}
	if len(c.Families) == 0 {
		return errors.New("at least one address family is required")
	}
	// RFC 4271 section 4.2: HoldTime is a 2-octet seconds field and
	// MUST be 0 or at least 3. 0 here means "unset" (ApplyDefaults
	// fills it in), so only the explicit values are checked; without
	// this the uint16 conversion in BuildOpen would silently wrap.
	if hs := c.Timers.HoldTime / time.Second; hs != 0 && (hs < 3 || hs > 65535) {
		return fmt.Errorf("holdtime must be 0 or between 3s and 65535s, got %s", c.Timers.HoldTime)
	}
	for i, f := range c.Families {
		if f == 0 {
			return fmt.Errorf("families[%d] is invalid", i)
		}
	}
	return nil
}

// ApplyDefaults fills in unset timers and carries LocalAS / Families
// into the capability set so the FSM does not need to know about
// fallback values.
func (c *Config) ApplyDefaults() {
	c.Timers.ApplyDefaults()
	c.Caps.Families = c.Families
	if c.Caps.FourOctetAS == 0 {
		c.Caps.FourOctetAS = c.LocalAS
	}
}

type Peer struct {
	cfg Config
	fsm *fsm
}

// New validates cfg, applies defaults, and returns a Peer ready for Open.
func New(cfg Config) (*Peer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.ApplyDefaults()
	return &Peer{cfg: cfg}, nil
}

func (p *Peer) Open(ctx context.Context) error {
	if p.fsm != nil {
		return errors.New("xk6-bgp: Peer is single-use; construct a new bgp.Peer to reconnect")
	}
	p.fsm = newFSM(p.cfg)
	return p.fsm.Open(ctx)
}

func (p *Peer) Close() error {
	if p.fsm == nil {
		return nil
	}
	return p.fsm.Close()
}

func (p *Peer) State() State {
	if p.fsm == nil {
		return StateIdle
	}
	return p.fsm.State()
}

// sessionNotReadyErr wraps ErrSessionNotReady with the async cause
// (NOTIFICATION, hold timer expiry, read error) recorded by the FSM's
// last fail, if any, so Advertise/Withdraw callers learn why the
// session went down without a separate peer.state poll.
func (p *Peer) sessionNotReadyErr() error {
	if p.fsm == nil {
		return ErrSessionNotReady
	}
	if cause := p.fsm.failureCause(); cause != nil {
		return fmt.Errorf("%w: %w", ErrSessionNotReady, cause)
	}
	return ErrSessionNotReady
}

// SessionUpDuration returns the µs between OpenSent and Established, or
// 0 if the session never reached Established.
func (p *Peer) SessionUpDuration() int64 {
	if p.fsm == nil {
		return 0
	}
	est := p.fsm.EstablishedAt()
	if est.Time().IsZero() {
		return 0
	}
	return est.SubMicros(p.fsm.OpenSentAt())
}

// Families returns the configured families in original order. The JS
// facade uses this to validate per-advertise family strings against the
// negotiated set without re-parsing.
func (p *Peer) Families() []bgp.Family { return p.cfg.Families }
