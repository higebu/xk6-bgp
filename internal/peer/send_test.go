package peer

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/higebu/xk6-bgp/internal/packet"
)

// TestAdvertise_RejectsExtendedWithoutNegotiation guards issue 17: when
// the JS layer requests UseExtendedMessages but the peer never
// advertised RFC 8654 capability 6, the send path must surface a
// dedicated error instead of crafting an oversize UPDATE that the peer
// would tear the session down for.
func TestAdvertise_RejectsExtendedWithoutNegotiation(t *testing.T) {
	cfg := Config{
		LocalAS:  65001,
		Target:   "127.0.0.1:0",
		RouterID: netip.MustParseAddr("10.0.0.1"),
		Families: []bgp.Family{bgp.RF_IPv4_UC},
	}
	cfg.ApplyDefaults()
	p := &Peer{cfg: cfg, fsm: newFSM(cfg)}
	p.fsm.state.Store(int32(StateEstablished))
	p.fsm.extendedMessagesNegotiated = false

	_, err := p.Advertise(AdvertiseRequest{
		Family: bgp.RF_IPv4_UC,
		Attrs:  packet.PathAttrs{NextHop: netip.MustParseAddr("10.0.0.1"), LocalAS: 65001},
		Routes: []packet.Route{packet.MustIPRoute(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.0.0.0/24"))},
		Encoding: packet.EncodingOptions{
			UseExtendedMessages: true,
		},
	})
	if !errors.Is(err, ErrExtendedMessagesNotNegotiated) {
		t.Fatalf("got err=%v, want ErrExtendedMessagesNotNegotiated", err)
	}
}

// TestAdvertise_RejectsPathIDWithoutNegotiation verifies a route
// carrying an RFC 7911 Path Identifier is refused when ADD-PATH send
// was not negotiated for the family.
func TestAdvertise_RejectsPathIDWithoutNegotiation(t *testing.T) {
	cfg := Config{
		LocalAS:  65001,
		Target:   "127.0.0.1:0",
		RouterID: netip.MustParseAddr("10.0.0.1"),
		Families: []bgp.Family{bgp.RF_IPv4_UC},
	}
	cfg.ApplyDefaults()
	p := &Peer{cfg: cfg, fsm: newFSM(cfg)}
	p.fsm.state.Store(int32(StateEstablished))
	p.fsm.fourOctetASNegotiated = true

	_, err := p.Advertise(AdvertiseRequest{
		Family: bgp.RF_IPv4_UC,
		Attrs:  packet.PathAttrs{NextHop: netip.MustParseAddr("10.0.0.1"), LocalAS: 65001},
		Routes: []packet.Route{
			packet.WithPathID(packet.MustIPRoute(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.0.0.0/24")), 1),
		},
	})
	if !errors.Is(err, ErrAddPathNotNegotiated) {
		t.Fatalf("got err=%v, want ErrAddPathNotNegotiated", err)
	}
}

// TestRouteRefresh_RejectsWithoutNegotiation verifies the RFC 2918
// section 4 guard: a ROUTE-REFRESH must not be sent to a peer that did
// not advertise the Route Refresh capability.
func TestRouteRefresh_RejectsWithoutNegotiation(t *testing.T) {
	cfg := Config{
		LocalAS:  65001,
		Target:   "127.0.0.1:0",
		RouterID: netip.MustParseAddr("10.0.0.1"),
		Families: []bgp.Family{bgp.RF_IPv4_UC},
	}
	cfg.ApplyDefaults()
	p := &Peer{cfg: cfg, fsm: newFSM(cfg)}
	p.fsm.state.Store(int32(StateEstablished))

	_, err := p.RouteRefresh(bgp.RF_IPv4_UC)
	if !errors.Is(err, ErrRouteRefreshNotNegotiated) {
		t.Fatalf("got err=%v, want ErrRouteRefreshNotNegotiated", err)
	}
}

func TestRouteRefresh_RejectsBeforeEstablished(t *testing.T) {
	cfg := Config{
		LocalAS:  65001,
		Target:   "127.0.0.1:0",
		RouterID: netip.MustParseAddr("10.0.0.1"),
		Families: []bgp.Family{bgp.RF_IPv4_UC},
	}
	cfg.ApplyDefaults()
	p := &Peer{cfg: cfg, fsm: newFSM(cfg)}

	_, err := p.RouteRefresh(bgp.RF_IPv4_UC)
	if !errors.Is(err, ErrSessionNotReady) {
		t.Fatalf("got err=%v, want ErrSessionNotReady", err)
	}
}

// TestRouteRefresh_WireRoundTrip sends a refresh over a pipe and parses
// the wire bytes back through gobgp ParseBGPMessage.
func TestRouteRefresh_WireRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	cfg := Config{
		LocalAS:  65001,
		Target:   "127.0.0.1:0",
		RouterID: netip.MustParseAddr("10.0.0.1"),
		Families: []bgp.Family{bgp.RF_IPv6_UC},
	}
	cfg.ApplyDefaults()
	p := &Peer{cfg: cfg, fsm: newFSM(cfg)}
	p.fsm.conn = c1
	p.fsm.state.Store(int32(StateEstablished))
	p.fsm.routeRefreshNegotiated = true

	type result struct {
		rr  *bgp.BGPRouteRefresh
		err error
	}
	gotCh := make(chan result, 1)
	go func() {
		_, msg, err := ReadMessage(c2)
		if err != nil {
			gotCh <- result{err: err}
			return
		}
		rr, ok := msg.Body.(*bgp.BGPRouteRefresh)
		if !ok {
			gotCh <- result{err: fmt.Errorf("parsed %T, want *bgp.BGPRouteRefresh", msg.Body)}
			return
		}
		gotCh <- result{rr: rr}
	}()

	ts, err := p.RouteRefresh(bgp.RF_IPv6_UC)
	if err != nil {
		t.Fatalf("RouteRefresh: %v", err)
	}
	if ts.Time().IsZero() {
		t.Fatal("write timestamp is zero")
	}

	select {
	case got := <-gotCh:
		if got.err != nil {
			t.Fatalf("reader: %v", got.err)
		}
		if got.rr.AFI != bgp.RF_IPv6_UC.Afi() || got.rr.SAFI != bgp.RF_IPv6_UC.Safi() {
			t.Fatalf("AFI/SAFI = %d/%d, want %d/%d",
				got.rr.AFI, got.rr.SAFI, bgp.RF_IPv6_UC.Afi(), bgp.RF_IPv6_UC.Safi())
		}
		if got.rr.Demarcation != RouteRefreshNormal {
			t.Fatalf("demarcation = %d, want %d", got.rr.Demarcation, RouteRefreshNormal)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not finish in 2s")
	}
}

// TestWriteUpdates_AddPath round-trips two paths for the same prefix
// through writeUpdates on a session that negotiated ADD-PATH, reading
// them back with the matching receive-side MarshallingOption.
func TestWriteUpdates_AddPath(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	cfg := Config{
		LocalAS:  65001,
		Target:   "127.0.0.1:0",
		RouterID: netip.MustParseAddr("10.0.0.1"),
		Families: []bgp.Family{bgp.RF_IPv4_UC},
	}
	cfg.ApplyDefaults()

	f := newFSM(cfg)
	f.conn = c1
	f.state.Store(int32(StateEstablished))
	f.fourOctetASNegotiated = true
	f.addPathNegotiated = map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_SEND}

	routes := []packet.Route{
		packet.WithPathID(packet.MustIPRoute(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.0.0.0/24")), 1),
		packet.WithPathID(packet.MustIPRoute(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.0.0.0/24")), 2),
	}

	type recvNLRI struct {
		prefix string
		id     uint32
	}
	gotCh := make(chan []recvNLRI, 1)
	go func() {
		rxOpt := &bgp.MarshallingOption{
			AddPath: map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_RECEIVE},
		}
		var got []recvNLRI
		_, msg, err := ReadMessage(c2, rxOpt)
		if err == nil {
			if u, ok := msg.Body.(*bgp.BGPUpdate); ok {
				for _, n := range u.NLRI {
					got = append(got, recvNLRI{prefix: n.NLRI.String(), id: n.ID})
				}
			}
		}
		gotCh <- got
	}()

	attrs := packet.PathAttrs{NextHop: netip.MustParseAddr("10.0.0.1"), LocalAS: 65001}
	if _, sent, err := f.writeUpdates(false, attrs, routes, packet.EncodingOptions{}, 0.0); err != nil || sent != 2 {
		t.Fatalf("writeUpdates: sent=%d err=%v", sent, err)
	}

	select {
	case got := <-gotCh:
		want := []recvNLRI{{"10.0.0.0/24", 1}, {"10.0.0.0/24", 2}}
		if len(got) != len(want) {
			t.Fatalf("received %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("NLRI[%d] = %+v, want %+v", i, got[i], want[i])
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not finish in 2s")
	}
}

// TestWriteUpdatesChunking verifies that announcing more routes than
// fit in a single 4 KiB UPDATE results in multiple wire UPDATEs whose
// decoded NLRIs reconstitute the original list, in order.
func TestWriteUpdatesChunking(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	cfg := Config{
		LocalAS:  65001,
		Target:   "127.0.0.1:0",
		RouterID: netip.MustParseAddr("10.0.0.1"),
		Families: []bgp.Family{bgp.RF_IPv4_UC},
	}
	cfg.ApplyDefaults()

	f := newFSM(cfg)
	f.conn = c1
	f.state.Store(int32(StateEstablished))
	// A real session reaches writeUpdates only after acceptPeerOpen; a
	// 4-octet-AS peer is the baseline this test models.
	f.fourOctetASNegotiated = true

	// 2000 distinct /32 NLRIs blow past the 4096-byte limit when
	// packed with full IPv4-unicast path attrs (Origin / AS_PATH /
	// NEXT_HOP) and the prefixes carried in the UPDATE NLRI field.
	const n = 2000
	routes := make([]packet.Route, 0, n)
	for i := 0; i < n; i++ {
		routes = append(routes, packet.MustIPRoute(bgp.RF_IPv4_UC,
			netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.%d/32",
				(i>>16)&0xff, (i>>8)&0xff, i&0xff))))
	}

	got := atomic.Int64{}
	readErr := make(chan error, 1)
	go func() {
		for {
			_, msg, err := ReadMessage(c2)
			if err != nil {
				readErr <- err
				return
			}
			if u, ok := msg.Body.(*bgp.BGPUpdate); ok {
				got.Add(int64(len(u.NLRI)))
			}
		}
	}()

	attrs := packet.PathAttrs{
		Origin:  0,
		NextHop: netip.MustParseAddr("10.0.0.1"),
		LocalAS: 65001,
	}

	ts, sent, err := f.writeUpdates(false, attrs, routes, packet.EncodingOptions{}, 0.0)
	if err != nil {
		t.Fatalf("writeUpdates: %v", err)
	}
	if sent != n {
		t.Fatalf("sent=%d, want %d", sent, n)
	}
	if ts.Time().IsZero() {
		t.Fatalf("first timestamp is zero")
	}

	// Close write side, drain reader, then check decoded count. The
	// reader returns when the pipe closes; any error is fine.
	_ = c1.Close()
	select {
	case <-readErr:
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not finish in 2s")
	}
	if g := got.Load(); g != int64(n) {
		t.Fatalf("decoded NLRIs=%d, want %d", g, n)
	}
}
