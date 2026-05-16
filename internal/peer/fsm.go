package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/higebu/xk6-bgp/internal/packet"
	"github.com/higebu/xk6-bgp/internal/timing"
)

// State is the BGP FSM state. xk6-bgp always initiates the TCP
// connection, so RFC 4271's Connect/Idle distinction collapses to Idle.
type State int32

const (
	StateIdle State = iota
	StateActive
	StateOpenSent
	StateOpenConfirm
	StateEstablished
)

func (s State) String() string {
	switch s {
	case StateIdle:
		return "Idle"
	case StateActive:
		return "Active"
	case StateOpenSent:
		return "OpenSent"
	case StateOpenConfirm:
		return "OpenConfirm"
	case StateEstablished:
		return "Established"
	default:
		return fmt.Sprintf("State(%d)", int32(s))
	}
}

var (
	ErrOpenTimeout     = errors.New("xk6-bgp: open timed out before Established")
	ErrPeerRejected    = errors.New("xk6-bgp: peer sent NOTIFICATION")
	ErrUnexpectedMsg   = errors.New("xk6-bgp: unexpected BGP message for current state")
	ErrSessionNotReady = errors.New("xk6-bgp: peer is not in Established state")
)

type fsm struct {
	cfg Config

	state atomic.Int32

	conn    net.Conn
	writeMu sync.Mutex

	// Session parameters set inside acceptPeerOpen and read by readLoop /
	// keepaliveLoop after Established. The dial goroutine writes them
	// before either loop is started, so they are race-free without a
	// lock; introducing concurrent writers would require revisiting.
	negotiatedHold             time.Duration
	keepaliveTick              time.Duration
	peerAS                     uint32
	peerCaps                   []bgp.ParameterCapabilityInterface
	extendedMessagesNegotiated bool

	loopCtx    context.Context
	loopCancel context.CancelFunc
	loopWg     sync.WaitGroup

	openSentAt    timing.Timestamp
	establishedAt timing.Timestamp

	establishedCh chan struct{}
	doneCh        chan error

	observed *observedSet
}

func newFSM(cfg Config) *fsm {
	f := &fsm{
		cfg:           cfg,
		establishedCh: make(chan struct{}),
		doneCh:        make(chan error, 1),
		observed:      newObservedSet(),
	}
	f.state.Store(int32(StateIdle))
	return f
}

func (f *fsm) State() State { return State(f.state.Load()) }

func (f *fsm) setState(s State) { f.state.Store(int32(s)) }

// Open dials, completes the OPEN/KEEPALIVE handshake, and starts the
// read + keepalive loops. Blocks until Established, timeout, or error.
func (f *fsm) Open(parent context.Context) error {
	if !f.state.CompareAndSwap(int32(StateIdle), int32(StateActive)) {
		return fmt.Errorf("xk6-bgp: Open called in state %s", f.State())
	}

	dialer := net.Dialer{Timeout: f.cfg.Timers.OpenTimeout}
	if f.cfg.LocalAddress.IsValid() {
		dialer.LocalAddr = &net.TCPAddr{IP: f.cfg.LocalAddress.AsSlice()}
	}
	conn, err := dialer.DialContext(parent, "tcp", f.cfg.Target)
	if err != nil {
		f.setState(StateIdle)
		return fmt.Errorf("xk6-bgp: dial %s: %w", f.cfg.Target, err)
	}
	f.conn = conn

	openMsg, err := BuildOpen(f.cfg.LocalAS, f.cfg.Timers.HoldTime, f.cfg.RouterID, f.cfg.Caps)
	if err != nil {
		_ = conn.Close()
		f.setState(StateIdle)
		return err
	}
	openBytes, err := openMsg.Serialize()
	if err != nil {
		_ = conn.Close()
		f.setState(StateIdle)
		return fmt.Errorf("xk6-bgp: serialize OPEN: %w", err)
	}

	f.openSentAt = timing.Now()
	if _, err := conn.Write(openBytes); err != nil {
		_ = conn.Close()
		f.setState(StateIdle)
		return fmt.Errorf("xk6-bgp: send OPEN: %w", err)
	}
	f.setState(StateOpenSent)

	// Context cancellation after OPEN was sent but before the peer
	// replies must unblock the handshake. Closing the conn from a
	// watcher goroutine is the only portable way to unblock the
	// in-flight ReadMessage.
	hsCtx, hsCancel := context.WithCancel(parent)
	hsDone := make(chan struct{})
	go func() {
		select {
		case <-hsCtx.Done():
			if parent.Err() != nil {
				_ = conn.Close()
			}
		case <-hsDone:
		}
	}()

	deadline := f.openSentAt.Time().Add(f.cfg.Timers.OpenTimeout)
	err = f.handshake(parent, deadline)
	close(hsDone)
	hsCancel()
	if err != nil {
		_ = conn.Close()
		f.setState(StateIdle)
		return err
	}

	_ = conn.SetReadDeadline(time.Time{}) // readLoop re-arms per HoldTime

	f.loopCtx, f.loopCancel = context.WithCancel(parent)
	f.loopWg.Add(2)
	go f.readLoop()
	go f.keepaliveLoop()

	return nil
}

func (f *fsm) handshake(parent context.Context, deadline time.Time) error {
	gotPeerOpen := false
	gotPeerKA := false

	for {
		_ = f.conn.SetReadDeadline(deadline)
		_, msg, err := ReadMessage(f.conn)
		if err != nil {
			return fmt.Errorf("xk6-bgp: handshake read: %w", err)
		}
		if parent.Err() != nil {
			return parent.Err()
		}

		switch m := msg.Body.(type) {
		case *bgp.BGPOpen:
			if gotPeerOpen {
				return fmt.Errorf("%w: duplicate OPEN", ErrUnexpectedMsg)
			}
			if err := f.acceptPeerOpen(m); err != nil {
				_ = f.sendNotification(bgp.BGP_ERROR_OPEN_MESSAGE_ERROR, bgp.BGP_ERROR_SUB_UNACCEPTABLE_HOLD_TIME, nil)
				return err
			}
			if err := f.writeMessage(BuildKeepalive()); err != nil {
				return fmt.Errorf("xk6-bgp: send first KEEPALIVE: %w", err)
			}
			gotPeerOpen = true
			f.setState(StateOpenConfirm)

		case *bgp.BGPKeepAlive:
			if !gotPeerOpen {
				return fmt.Errorf("%w: KEEPALIVE before OPEN", ErrUnexpectedMsg)
			}
			gotPeerKA = true

		case *bgp.BGPNotification:
			return fmt.Errorf("%w: code=%d sub=%d", ErrPeerRejected, m.ErrorCode, m.ErrorSubcode)

		default:
			return fmt.Errorf("%w: type=%d during handshake", ErrUnexpectedMsg, msg.Header.Type)
		}

		if gotPeerOpen && gotPeerKA {
			f.establishedAt = timing.Now()
			f.setState(StateEstablished)
			close(f.establishedCh)
			return nil
		}

		if time.Now().After(deadline) {
			return ErrOpenTimeout
		}
	}
}

func (f *fsm) acceptPeerOpen(m *bgp.BGPOpen) error {
	if m.HoldTime != 0 && m.HoldTime < 3 {
		return fmt.Errorf("xk6-bgp: peer advertised invalid HoldTime %ds", m.HoldTime)
	}

	// RFC 4271 section 4.2: HoldTime is min(local, peer); 0 disables keepalive.
	local := uint16(f.cfg.Timers.HoldTime / time.Second) // #nosec G115 -- HoldTime is a 2-octet field per RFC 4271 section 4.2
	negotiated := min(local, m.HoldTime)
	f.negotiatedHold = time.Duration(negotiated) * time.Second
	if negotiated == 0 {
		f.keepaliveTick = 0
	} else {
		// RFC 4271 section 10: keepalive_time = HoldTime / 3.
		f.keepaliveTick = max(f.negotiatedHold/3, time.Second)
	}

	f.peerAS = uint32(m.MyAS)
	for _, p := range m.OptParams {
		ocp, ok := p.(*bgp.OptionParameterCapability)
		if !ok {
			continue
		}
		for _, c := range ocp.Capability {
			if four, ok := c.(*bgp.CapFourOctetASNumber); ok {
				f.peerAS = four.CapValue // RFC 6793: overrides 2-octet MyAS
			}
			// RFC 8654 section 3: Extended Messages applies only when both sides
			// advertised capability code 6.
			if c.Code() == packet.BGPCapExtendedMessage && f.cfg.Caps.ExtendedMessage {
				f.extendedMessagesNegotiated = true
			}
			f.peerCaps = append(f.peerCaps, c)
		}
	}

	if f.cfg.PeerAS != 0 && f.peerAS != f.cfg.PeerAS {
		return fmt.Errorf("xk6-bgp: peer AS mismatch: config=%d wire=%d", f.cfg.PeerAS, f.peerAS)
	}
	return nil
}

// writeMessage serializes msg and writes it under writeMu so concurrent
// VUs and the keepalive goroutine never interleave bytes on the packet.
func (f *fsm) writeMessage(msg *bgp.BGPMessage) error {
	buf, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("BGP serialize: %w", err)
	}
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	_, err = f.conn.Write(buf)
	return err
}

func (f *fsm) sendNotification(code, subcode uint8, data []byte) error {
	return f.writeMessage(BuildNotification(code, subcode, data))
}

func (f *fsm) keepaliveLoop() {
	defer f.loopWg.Done()
	if f.keepaliveTick <= 0 { // HoldTime 0 → no periodic keepalives
		<-f.loopCtx.Done()
		return
	}
	ticker := time.NewTicker(f.keepaliveTick)
	defer ticker.Stop()
	for {
		select {
		case <-f.loopCtx.Done():
			return
		case <-ticker.C:
			if err := f.writeMessage(BuildKeepalive()); err != nil {
				f.fail(fmt.Errorf("xk6-bgp: send KEEPALIVE: %w", err))
				return
			}
		}
	}
}

func (f *fsm) readLoop() {
	defer f.loopWg.Done()
	for {
		if f.loopCtx.Err() != nil {
			return
		}

		if f.negotiatedHold > 0 {
			_ = f.conn.SetReadDeadline(time.Now().Add(f.negotiatedHold))
		}
		maxLen := bgp.BGP_MAX_MESSAGE_LENGTH
		if f.extendedMessagesNegotiated {
			maxLen = packet.BGPExtendedMaxMessageLength
		}
		_, msg, err := ReadMessageMax(f.conn, maxLen)
		if err != nil {
			if f.loopCtx.Err() != nil {
				return
			}
			f.fail(fmt.Errorf("xk6-bgp: read: %w", err))
			return
		}
		ts := timing.Now()

		switch m := msg.Body.(type) {
		case *bgp.BGPUpdate:
			f.dispatchUpdate(m, ts)
		case *bgp.BGPKeepAlive:
		case *bgp.BGPNotification:
			f.fail(fmt.Errorf("%w: code=%d sub=%d", ErrPeerRejected, m.ErrorCode, m.ErrorSubcode))
			return
		}
	}
}

// Close cleanly tears the session down. Sends Cease NOTIFICATION if we
// reached Established, then closes the conn and joins the loops.
func (f *fsm) Close() error {
	prev := State(f.state.Load())
	if prev == StateIdle {
		return nil
	}
	if !f.state.CompareAndSwap(int32(prev), int32(StateIdle)) {
		return nil
	}

	if f.conn != nil && prev == StateEstablished {
		_ = f.sendNotification(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, nil)
	}
	if f.loopCancel != nil {
		f.loopCancel()
	}
	if f.conn != nil {
		_ = f.conn.Close()
	}
	f.loopWg.Wait()
	select {
	case f.doneCh <- nil:
	default:
	}
	return nil
}

func (f *fsm) fail(err error) {
	if f.loopCancel != nil {
		f.loopCancel()
	}
	if f.conn != nil {
		_ = f.conn.Close()
	}
	f.state.Store(int32(StateIdle))
	select {
	case f.doneCh <- err:
	default:
	}
}

func (f *fsm) EstablishedAt() timing.Timestamp { return f.establishedAt }
func (f *fsm) OpenSentAt() timing.Timestamp    { return f.openSentAt }
