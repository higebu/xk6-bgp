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

// notificationWriteTimeout bounds the best-effort NOTIFICATION write on
// teardown paths. Without it a peer that stopped reading would leave
// Close (or the hold-timer failure path) blocked in conn.Write behind
// writeMu indefinitely.
const notificationWriteTimeout = 2 * time.Second

// openRejectError carries the RFC 4271 section 6.2 subcode to put in
// the OPEN Message Error NOTIFICATION when the peer's OPEN is
// unacceptable.
type openRejectError struct {
	subcode uint8
	reason  string
}

func (e *openRejectError) Error() string { return e.reason }

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
	fourOctetASNegotiated      bool
	// routeRefreshNegotiated is set when the peer advertised the RFC
	// 2918 Route Refresh capability (code 2). RFC 2918 section 4 allows
	// sending a ROUTE-REFRESH only to a peer that advertised it.
	routeRefreshNegotiated bool
	// enhancedRefreshNegotiated is set when both sides advertised the
	// RFC 7313 Enhanced Route Refresh capability (code 70); only then
	// are inbound BoRR/EoRR demarcations recognized (RFC 7313 section 4).
	enhancedRefreshNegotiated bool
	// addPathNegotiated is the effective per-family RFC 7911 mode:
	// send is set when we advertised send and the peer advertised
	// receive, receive when we advertised receive and the peer
	// advertised send. nil when ADD-PATH is not in play.
	addPathNegotiated map[bgp.Family]bgp.BGPAddPathMode
	// msgOpts carries the negotiation outcome (ADD-PATH modes, 2-octet
	// AS_PATH decoding) into every gobgp Serialize/Parse call. Built
	// once in acceptPeerOpen; nil on the default 4-octet-AS,
	// no-ADD-PATH session so the hot path stays allocation-free.
	msgOpts []*bgp.MarshallingOption

	loopCtx    context.Context
	loopCancel context.CancelFunc
	loopWg     sync.WaitGroup

	openSentAt    timing.Timestamp
	establishedAt timing.Timestamp

	observed *observedSet
}

func newFSM(cfg Config) *fsm {
	f := &fsm{
		cfg:      cfg,
		observed: newObservedSet(),
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
				subcode := uint8(0) // 0 = unspecific per RFC 4271 section 6
				var oe *openRejectError
				if errors.As(err, &oe) {
					subcode = oe.subcode
				}
				_ = f.sendNotification(bgp.BGP_ERROR_OPEN_MESSAGE_ERROR, subcode, nil)
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
			return nil
		}

		if time.Now().After(deadline) {
			return ErrOpenTimeout
		}
	}
}

func (f *fsm) acceptPeerOpen(m *bgp.BGPOpen) error {
	if m.HoldTime != 0 && m.HoldTime < 3 {
		return &openRejectError{
			subcode: bgp.BGP_ERROR_SUB_UNACCEPTABLE_HOLD_TIME,
			reason:  fmt.Sprintf("xk6-bgp: peer advertised invalid HoldTime %ds", m.HoldTime),
		}
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
	var peerAddPath map[bgp.Family]bgp.BGPAddPathMode
	for _, p := range m.OptParams {
		ocp, ok := p.(*bgp.OptionParameterCapability)
		if !ok {
			continue
		}
		for _, c := range ocp.Capability {
			if four, ok := c.(*bgp.CapFourOctetASNumber); ok {
				f.peerAS = four.CapValue // RFC 6793: overrides 2-octet MyAS
				f.fourOctetASNegotiated = true
			}
			// RFC 8654 section 3: Extended Messages applies only when both sides
			// advertised capability code 6.
			if c.Code() == packet.BGPCapExtendedMessage && f.cfg.Caps.ExtendedMessage {
				f.extendedMessagesNegotiated = true
			}
			if c.Code() == bgp.BGP_CAP_ROUTE_REFRESH {
				f.routeRefreshNegotiated = true
			}
			if c.Code() == bgp.BGP_CAP_ENHANCED_ROUTE_REFRESH && f.cfg.Caps.EnhancedRefresh {
				f.enhancedRefreshNegotiated = true
			}
			if ap, ok := c.(*bgp.CapAddPath); ok {
				if peerAddPath == nil {
					peerAddPath = make(map[bgp.Family]bgp.BGPAddPathMode, len(ap.Tuples))
				}
				for _, t := range ap.Tuples {
					peerAddPath[t.Family] |= t.Mode
				}
			}
			f.peerCaps = append(f.peerCaps, c)
		}
	}

	// RFC 7911 section 5: each direction is enabled independently —
	// we may send additional paths for a family only if we advertised
	// send and the peer advertised receive, and vice versa.
	for fam, local := range f.cfg.Caps.AddPath {
		peerMode := peerAddPath[fam]
		var mode bgp.BGPAddPathMode
		if local&bgp.BGP_ADD_PATH_SEND != 0 && peerMode&bgp.BGP_ADD_PATH_RECEIVE != 0 {
			mode |= bgp.BGP_ADD_PATH_SEND
		}
		if local&bgp.BGP_ADD_PATH_RECEIVE != 0 && peerMode&bgp.BGP_ADD_PATH_SEND != 0 {
			mode |= bgp.BGP_ADD_PATH_RECEIVE
		}
		if mode != 0 {
			if f.addPathNegotiated == nil {
				f.addPathNegotiated = make(map[bgp.Family]bgp.BGPAddPathMode, len(f.cfg.Caps.AddPath))
			}
			f.addPathNegotiated[fam] = mode
		}
	}
	if f.addPathNegotiated != nil || !f.fourOctetASNegotiated {
		f.msgOpts = []*bgp.MarshallingOption{{
			AddPath:    f.addPathNegotiated,
			Use2ByteAS: !f.fourOctetASNegotiated,
		}}
	}

	if f.cfg.PeerAS != 0 && f.peerAS != f.cfg.PeerAS {
		return &openRejectError{
			subcode: bgp.BGP_ERROR_SUB_BAD_PEER_AS,
			reason:  fmt.Sprintf("xk6-bgp: peer AS mismatch: config=%d wire=%d", f.cfg.PeerAS, f.peerAS),
		}
	}
	return nil
}

// writeMessage serializes msg and writes it under writeMu so concurrent
// VUs and the keepalive goroutine never interleave bytes on the packet.
func (f *fsm) writeMessage(msg *bgp.BGPMessage) error {
	buf, err := msg.Serialize(f.msgOpts...)
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
		_, msg, ts, err := ReadMessageMax(f.conn, maxLen, f.msgOpts...)
		if err != nil {
			if f.loopCtx.Err() != nil {
				return
			}
			// RFC 4271 section 6.5: hold timer expiry must be announced
			// with a NOTIFICATION (code 4) before dropping the session.
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() && f.negotiatedHold > 0 {
				_ = f.conn.SetWriteDeadline(time.Now().Add(notificationWriteTimeout))
				_ = f.sendNotification(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil)
				f.fail(fmt.Errorf("xk6-bgp: hold timer expired: %w", err))
				return
			}
			f.fail(fmt.Errorf("xk6-bgp: read: %w", err))
			return
		}

		switch m := msg.Body.(type) {
		case *bgp.BGPUpdate:
			f.dispatchUpdate(m, ts)
		case *bgp.BGPRouteRefresh:
			f.dispatchRouteRefresh(m, ts)
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

	if f.conn != nil {
		// Unblock a writer stuck in conn.Write while holding writeMu
		// (its Write returns a timeout error) and bound the Cease write
		// below, so Close cannot hang on a peer that stopped reading.
		_ = f.conn.SetWriteDeadline(time.Now().Add(notificationWriteTimeout))
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
	// Wake blocked WaitForPrefixes callers immediately — no further
	// UPDATEs can arrive, so letting them run out their timeout would
	// just stall the VU.
	f.observed.fail(err)
}

func (f *fsm) EstablishedAt() timing.Timestamp { return f.establishedAt }
func (f *fsm) OpenSentAt() timing.Timestamp    { return f.openSentAt }

// failureCause returns the async session-fatal error recorded by the
// most recent fail() call (NOTIFICATION, hold timer expiry, read
// error), or nil if the session has not failed. Lets Advertise/Withdraw
// report why a session dropped between calls without the caller having
// to separately poll peer.state.
func (f *fsm) failureCause() error { return f.observed.failureCause() }
