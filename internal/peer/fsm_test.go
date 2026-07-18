package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/higebu/xk6-bgp/internal/packet"
)

// fakePeerOpts controls what the local-loopback mock peer does after
// accepting a TCP connection.
type fakePeerOpts struct {
	myAS           uint16
	holdTime       uint16
	routerID       netip.Addr
	skipOpen       bool
	openAfterError bool
	openErrCode    uint8
	openErrSubcode uint8
	sendKAFirst    bool // send KA before OPEN (invalid order)
}

func defaultFakePeerOpts() fakePeerOpts {
	return fakePeerOpts{
		myAS:     65000,
		holdTime: 180,
		routerID: netip.MustParseAddr("10.0.0.2"),
	}
}

// startFakePeer accepts one connection and plays the peer side per opts.
// It returns the listener (so the test can close it on cleanup) and an
// error channel that publishes the eventual outcome.
func startFakePeer(t *testing.T, opts fakePeerOpts) (*net.TCPListener, <-chan error) {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)
		conn, err := l.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		errCh <- runFakePeer(conn, opts)
	}()
	return l, errCh
}

func runFakePeer(conn net.Conn, opts fakePeerOpts) error {
	if opts.sendKAFirst {
		// Push a KEEPALIVE before any OPEN — peer FSM should error.
		buf, _ := BuildKeepalive().Serialize()
		if _, err := conn.Write(buf); err != nil {
			return fmt.Errorf("write KA: %w", err)
		}
		// Read whatever the peer sends (probably OPEN then close).
		// Best-effort drain.
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		_, _, _ = ReadMessage(conn)
		return nil
	}

	if !opts.skipOpen {
		// Wait for the FSM's OPEN.
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, msg, err := ReadMessage(conn)
		if err != nil {
			return fmt.Errorf("read OPEN: %w", err)
		}
		if _, ok := msg.Body.(*bgp.BGPOpen); !ok {
			return fmt.Errorf("expected OPEN, got %T", msg.Body)
		}
	}

	if opts.openAfterError {
		n := BuildNotification(opts.openErrCode, opts.openErrSubcode, nil)
		buf, _ := n.Serialize()
		_, err := conn.Write(buf)
		return err
	}

	// Send our OPEN + KEEPALIVE.
	open, err := BuildOpen(uint32(opts.myAS), time.Duration(opts.holdTime)*time.Second, opts.routerID, packet.CapsConfig{
		Families:    []bgp.Family{bgp.RF_IPv4_UC},
		FourOctetAS: uint32(opts.myAS),
	})
	if err != nil {
		return err
	}
	obuf, _ := open.Serialize()
	if _, err := conn.Write(obuf); err != nil {
		return err
	}
	kbuf, _ := BuildKeepalive().Serialize()
	if _, err := conn.Write(kbuf); err != nil {
		return err
	}

	// Read the peer's KEEPALIVE response and stop.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := ReadMessage(conn)
	if err != nil {
		return fmt.Errorf("read KA from peer: %w", err)
	}
	if _, ok := msg.Body.(*bgp.BGPKeepAlive); !ok {
		return fmt.Errorf("expected KA, got %T", msg.Body)
	}
	// Hold the connection open briefly so the Peer's readLoop can settle.
	time.Sleep(50 * time.Millisecond)
	return nil
}

func newTestPeer(t *testing.T, target string) *Peer {
	t.Helper()
	p, err := New(Config{
		LocalAS:  65001,
		PeerAS:   65000,
		RouterID: netip.MustParseAddr("10.0.0.1"),
		Target:   target,
		Families: []bgp.Family{bgp.RF_IPv4_UC},
		Timers: SessionTimers{
			Keepalive:   30 * time.Second,
			HoldTime:    90 * time.Second,
			OpenTimeout: 2 * time.Second,
		},
		Caps: packet.CapsConfig{
			FourOctetAS: 65001,
		},
	})
	if err != nil {
		t.Fatalf("peer.New: %v", err)
	}
	return p
}

func TestFSM_HappyPath(t *testing.T) {
	l, peerErr := startFakePeer(t, defaultFakePeerOpts())
	defer l.Close()

	p := newTestPeer(t, l.Addr().String())
	defer p.Close()

	if err := p.Open(context.Background()); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if p.State() != StateEstablished {
		t.Fatalf("state = %s, want Established", p.State())
	}
	if p.SessionUpDuration() <= 0 {
		t.Fatalf("SessionUpDuration() = %d, expected > 0", p.SessionUpDuration())
	}

	// Wait for fake peer to finish its work.
	select {
	case err := <-peerErr:
		if err != nil {
			t.Logf("fake peer ended with: %v (acceptable)", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fake peer did not finish")
	}
}

func TestFSM_PeerRejectsWithNotification(t *testing.T) {
	l, _ := startFakePeer(t, fakePeerOpts{
		myAS:           65000,
		holdTime:       180,
		routerID:       netip.MustParseAddr("10.0.0.2"),
		openAfterError: true,
		openErrCode:    bgp.BGP_ERROR_OPEN_MESSAGE_ERROR,
		openErrSubcode: bgp.BGP_ERROR_SUB_BAD_PEER_AS,
	})
	defer l.Close()

	p := newTestPeer(t, l.Addr().String())
	defer p.Close()

	err := p.Open(context.Background())
	if !errors.Is(err, ErrPeerRejected) {
		t.Fatalf("expected ErrPeerRejected, got %v", err)
	}
	if p.State() != StateIdle {
		t.Fatalf("state = %s, want Idle after rejection", p.State())
	}
}

func TestFSM_InvalidSequence_KeepAliveBeforeOpen(t *testing.T) {
	l, _ := startFakePeer(t, fakePeerOpts{
		myAS:        65000,
		routerID:    netip.MustParseAddr("10.0.0.2"),
		sendKAFirst: true,
	})
	defer l.Close()

	p := newTestPeer(t, l.Addr().String())
	defer p.Close()

	err := p.Open(context.Background())
	if !errors.Is(err, ErrUnexpectedMsg) {
		t.Fatalf("expected ErrUnexpectedMsg, got %v", err)
	}
	if p.State() != StateIdle {
		t.Fatalf("state = %s, want Idle after invalid sequence", p.State())
	}
}

func TestFSM_OpenTimeoutNoData(t *testing.T) {
	// Listener that accepts but never replies.
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		// Hold the connection open silently.
		time.Sleep(2 * time.Second)
		_ = conn.Close()
	}()

	p, err := New(Config{
		LocalAS:  65001,
		PeerAS:   65000,
		RouterID: netip.MustParseAddr("10.0.0.1"),
		Target:   l.Addr().String(),
		Families: []bgp.Family{bgp.RF_IPv4_UC},
		Timers:   SessionTimers{OpenTimeout: 300 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("peer.New: %v", err)
	}
	err = p.Open(context.Background())
	if err == nil {
		t.Fatal("expected error on OpenTimeout")
	}
	if p.State() != StateIdle {
		t.Fatalf("state = %s, want Idle", p.State())
	}
}

func TestFSM_AdvertiseEmptyRoutesRejected(t *testing.T) {
	l, peerErr := startFakePeer(t, defaultFakePeerOpts())
	defer l.Close()

	p := newTestPeer(t, l.Addr().String())
	defer p.Close()

	if err := p.Open(context.Background()); err != nil {
		t.Fatalf("Open: %v", err)
	}

	if _, err := p.Advertise(AdvertiseRequest{Family: bgp.RF_IPv4_UC}); err == nil {
		t.Fatal("expected error on empty routes")
	}

	<-peerErr
}

// TestFSM_PeerDisconnectAfterEstablished covers the disconnect path
// from issue 25: once the DUT FINs/RSTs the TCP connection, the
// readLoop must drive the FSM back to Idle and subsequent Advertise
// calls must surface ErrSessionNotReady rather than block.
func TestFSM_PeerDisconnectAfterEstablished(t *testing.T) {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		// Honor the handshake then close immediately so the local FSM
		// transitions to Established and then observes a peer-initiated
		// teardown.
		opts := defaultFakePeerOpts()
		_ = runFakePeer(conn, opts)
		_ = conn.Close()
	}()

	p := newTestPeer(t, l.Addr().String())
	defer p.Close()

	if err := p.Open(context.Background()); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if p.State() != StateEstablished {
		t.Fatalf("state = %s, want Established before peer FIN", p.State())
	}

	// Spin until the readLoop has observed the close. 200 ms is generous
	// for a localhost FIN; the loop polls every 5 ms.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) && p.State() != StateIdle {
		time.Sleep(5 * time.Millisecond)
	}
	if p.State() != StateIdle {
		t.Fatalf("state = %s, want Idle after peer FIN", p.State())
	}

	_, err = p.Advertise(AdvertiseRequest{
		Family: bgp.RF_IPv4_UC,
		Attrs: packet.PathAttrs{
			NextHop: netip.MustParseAddr("10.0.0.1"),
			LocalAS: 65001,
		},
		Routes: []packet.Route{packet.MustIPRoute(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.100.0.0/24"))},
	})
	if !errors.Is(err, ErrSessionNotReady) {
		t.Fatalf("Advertise after peer FIN returned %v, want ErrSessionNotReady", err)
	}
}

// TestFSM_OpenContextCanceled covers issue 25's "context cancellation
// during Open()" gap: a context that fires while the dial / handshake
// is in flight must short-circuit Open with the context error rather
// than wait for OpenTimeout.
func TestFSM_OpenContextCanceled(t *testing.T) {
	// Listener that accepts but never replies — Open will block in the
	// handshake read loop until the context fires.
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		time.Sleep(time.Second)
		_ = conn.Close()
	}()

	p, err := New(Config{
		LocalAS:  65001,
		PeerAS:   65000,
		RouterID: netip.MustParseAddr("10.0.0.1"),
		Target:   l.Addr().String(),
		Families: []bgp.Family{bgp.RF_IPv4_UC},
		Timers:   SessionTimers{OpenTimeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatalf("peer.New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = p.Open(ctx)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error when context is canceled mid-Open")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Open took %s after ctx cancel, expected to return promptly", elapsed)
	}
	if p.State() != StateIdle {
		t.Fatalf("state = %s, want Idle after canceled Open", p.State())
	}
}

func TestFSM_AdvertiseBeforeEstablishedRejected(t *testing.T) {
	p, err := New(Config{
		LocalAS:  65001,
		RouterID: netip.MustParseAddr("10.0.0.1"),
		Target:   "127.0.0.1:1",
		Families: []bgp.Family{bgp.RF_IPv4_UC},
	})
	if err != nil {
		t.Fatalf("peer.New: %v", err)
	}
	_, err = p.Advertise(AdvertiseRequest{
		Family: bgp.RF_IPv4_UC,
		Attrs: packet.PathAttrs{
			NextHop: netip.MustParseAddr("10.0.0.1"),
			LocalAS: 65001,
		},
		Routes: []packet.Route{packet.MustIPRoute(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.100.0.0/24"))},
	})
	if !errors.Is(err, ErrSessionNotReady) {
		t.Fatalf("expected ErrSessionNotReady, got %v", err)
	}
}

// TestFSM_BadPeerASNotificationSubcode verifies the OPEN rejection for
// an AS mismatch carries subcode 2 (Bad Peer AS) per RFC 4271 section
// 6.2, not a generic or unrelated subcode.
func TestFSM_BadPeerASNotificationSubcode(t *testing.T) {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	notifCh := make(chan *bgp.BGPNotification, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, _, err := ReadMessage(conn); err != nil { // FSM's OPEN
			return
		}
		// Advertise AS 65999 while the test Peer expects 65000.
		open, err := BuildOpen(65999, 180*time.Second, netip.MustParseAddr("10.0.0.2"), packet.CapsConfig{
			Families:    []bgp.Family{bgp.RF_IPv4_UC},
			FourOctetAS: 65999,
		})
		if err != nil {
			return
		}
		obuf, _ := open.Serialize()
		if _, err := conn.Write(obuf); err != nil {
			return
		}
		kbuf, _ := BuildKeepalive().Serialize()
		if _, err := conn.Write(kbuf); err != nil {
			return
		}
		for {
			_, msg, err := ReadMessage(conn)
			if err != nil {
				return
			}
			if n, ok := msg.Body.(*bgp.BGPNotification); ok {
				notifCh <- n
				return
			}
		}
	}()

	p := newTestPeer(t, l.Addr().String())
	if err := p.Open(context.Background()); err == nil {
		t.Fatal("expected AS-mismatch error from Open")
	}
	select {
	case n := <-notifCh:
		if n.ErrorCode != bgp.BGP_ERROR_OPEN_MESSAGE_ERROR || n.ErrorSubcode != bgp.BGP_ERROR_SUB_BAD_PEER_AS {
			t.Fatalf("NOTIFICATION code=%d sub=%d, want code=%d sub=%d",
				n.ErrorCode, n.ErrorSubcode, bgp.BGP_ERROR_OPEN_MESSAGE_ERROR, bgp.BGP_ERROR_SUB_BAD_PEER_AS)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer never received a NOTIFICATION")
	}
}
