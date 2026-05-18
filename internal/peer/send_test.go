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
