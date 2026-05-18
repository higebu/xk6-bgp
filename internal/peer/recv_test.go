package peer

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/higebu/xk6-bgp/internal/timing"
	"github.com/higebu/xk6-bgp/internal/packet"
)

func mustPathNLRIs(t *testing.T, prefixes ...string) []bgp.PathNLRI {
	t.Helper()
	out := make([]bgp.PathNLRI, 0, len(prefixes))
	for _, p := range prefixes {
		pref, err := netip.ParsePrefix(p)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", p, err)
		}
		nlri, err := bgp.NewIPAddrPrefix(pref)
		if err != nil {
			t.Fatalf("NewIPAddrPrefix: %v", err)
		}
		out = append(out, bgp.PathNLRI{NLRI: nlri})
	}
	return out
}

func TestObservedSetAdvertiseWithdraw(t *testing.T) {
	o := newObservedSet()
	t0 := timing.Now()

	o.applyUpdate(bgp.RF_IPv4_UC, t0, mustPathNLRIs(t, "10.0.0.0/24", "10.0.1.0/24"), nil)

	if _, seen := o.firstSeen["10.0.0.0/24"]; !seen {
		t.Fatalf("10.0.0.0/24 not advertised")
	}
	if _, gone := o.withdrawn["10.0.0.0/24"]; gone {
		t.Fatalf("10.0.0.0/24 should not be withdrawn after advertise")
	}
	if o.advertiseN != 2 || o.withdrawN != 0 {
		t.Fatalf("counters: advertise=%d withdraw=%d", o.advertiseN, o.withdrawN)
	}

	t1 := timing.Now()
	o.applyUpdate(bgp.RF_IPv4_UC, t1, nil, mustPathNLRIs(t, "10.0.0.0/24"))
	if _, gone := o.withdrawn["10.0.0.0/24"]; !gone {
		t.Fatalf("10.0.0.0/24 should be withdrawn")
	}
	if o.advertiseN != 2 || o.withdrawN != 1 {
		t.Fatalf("after withdraw counters: advertise=%d withdraw=%d", o.advertiseN, o.withdrawN)
	}
}

func TestFSMDispatchExtractsMPNLRI(t *testing.T) {
	cfg := Config{
		LocalAS:  65001,
		Target:   "127.0.0.1:0",
		RouterID: netip.MustParseAddr("10.0.0.1"),
		Families: []bgp.Family{bgp.RF_IPv4_UC},
	}
	cfg.ApplyDefaults()
	f := newFSM(cfg)

	msg, err := packet.BuildUpdateMessage(
		false,
		packet.PathAttrs{
			Origin:  0,
			NextHop: netip.MustParseAddr("192.0.2.1"),
			LocalAS: 65001,
		},
		[]packet.Route{
			packet.MustIPRoute(bgp.RF_IPv4_UC, netip.MustParsePrefix("203.0.113.0/24")),
			packet.MustIPRoute(bgp.RF_IPv4_UC, netip.MustParsePrefix("198.51.100.0/24")),
		},
		packet.EncodingOptions{},
	)
	if err != nil {
		t.Fatalf("BuildUpdateMessage: %v", err)
	}

	bytes, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	parsed, err := bgp.ParseBGPMessage(bytes)
	if err != nil {
		t.Fatalf("ParseBGPMessage: %v", err)
	}
	body, ok := parsed.Body.(*bgp.BGPUpdate)
	if !ok {
		t.Fatalf("expected BGPUpdate, got %T", parsed.Body)
	}

	ts := timing.Now()
	f.dispatchUpdate(body, ts)

	for _, want := range []string{"203.0.113.0/24", "198.51.100.0/24"} {
		if _, seen := f.observed.firstSeen[want]; !seen {
			t.Fatalf("%s not observed", want)
		}
		if _, gone := f.observed.withdrawn[want]; gone {
			t.Fatalf("%s should not be withdrawn", want)
		}
	}
}

func TestFSMDispatchExtractsIPv6MPNLRI(t *testing.T) {
	cfg := Config{
		LocalAS:  65001,
		Target:   "127.0.0.1:0",
		RouterID: netip.MustParseAddr("10.0.0.1"),
		Families: []bgp.Family{bgp.RF_IPv6_UC},
	}
	cfg.ApplyDefaults()
	f := newFSM(cfg)

	msg, err := packet.BuildUpdateMessage(
		false,
		packet.PathAttrs{
			Origin:  0,
			NextHop: netip.MustParseAddr("2001:db8::1"),
			LocalAS: 65001,
		},
		[]packet.Route{
			packet.MustIPRoute(bgp.RF_IPv6_UC, netip.MustParsePrefix("2001:db8:a::/48")),
			packet.MustIPRoute(bgp.RF_IPv6_UC, netip.MustParsePrefix("2001:db8:b::/48")),
		},
		packet.EncodingOptions{},
	)
	if err != nil {
		t.Fatalf("BuildUpdateMessage: %v", err)
	}
	bytes, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	parsed, err := bgp.ParseBGPMessage(bytes)
	if err != nil {
		t.Fatalf("ParseBGPMessage: %v", err)
	}
	body := parsed.Body.(*bgp.BGPUpdate)

	f.dispatchUpdate(body, timing.Now())

	for _, want := range []string{"2001:db8:a::/48", "2001:db8:b::/48"} {
		if _, seen := f.observed.firstSeen[want]; !seen {
			t.Fatalf("%s not observed", want)
		}
		if _, gone := f.observed.withdrawn[want]; gone {
			t.Fatalf("%s should not be withdrawn", want)
		}
	}
}

func TestWaitForPrefixes_Synchronous(t *testing.T) {
	o := newObservedSet()
	cfg := Config{LocalAS: 65001, Target: "127.0.0.1:0", RouterID: netip.MustParseAddr("10.0.0.1"), Families: []bgp.Family{bgp.RF_IPv4_UC}}
	cfg.ApplyDefaults()
	p := &Peer{cfg: cfg, fsm: &fsm{observed: o}}
	p.fsm.state.Store(int32(StateEstablished))

	wantPrefixes := []string{"10.10.0.0/24", "10.10.1.0/24", "10.10.2.0/24"}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond)
		o.applyUpdate(bgp.RF_IPv4_UC, timing.Now(), mustPathNLRIs(t, wantPrefixes...), nil)
	}()

	res, err := p.WaitForPrefixes(wantPrefixes, 2*time.Second, timing.Timestamp{})
	if err != nil {
		t.Fatalf("WaitForPrefixes: %v", err)
	}
	if res.Matched != 3 {
		t.Fatalf("Matched=%d, want 3", res.Matched)
	}
	if res.FirstSeen.Time().IsZero() || res.LastSeen.Time().IsZero() {
		t.Fatalf("zero timestamps: %+v", res)
	}
	wg.Wait()
}

func TestWaitForPrefixes_Timeout(t *testing.T) {
	o := newObservedSet()
	cfg := Config{LocalAS: 65001, Target: "127.0.0.1:0", RouterID: netip.MustParseAddr("10.0.0.1"), Families: []bgp.Family{bgp.RF_IPv4_UC}}
	cfg.ApplyDefaults()
	p := &Peer{cfg: cfg, fsm: &fsm{observed: o}}
	p.fsm.state.Store(int32(StateEstablished))

	o.applyUpdate(bgp.RF_IPv4_UC, timing.Now(), mustPathNLRIs(t, "10.10.0.0/24"), nil)
	res, err := p.WaitForPrefixes([]string{"10.10.0.0/24", "10.10.99.0/24"}, 50*time.Millisecond, timing.Timestamp{})
	if err == nil {
		t.Fatalf("expected timeout, got nil err, res=%+v", res)
	}
	if len(res.Missing) != 1 || res.Missing[0] != "10.10.99.0/24" {
		t.Fatalf("Missing=%v, want [10.10.99.0/24]", res.Missing)
	}
}

func TestWaitForPrefixes_OnlyAfter(t *testing.T) {
	o := newObservedSet()
	cfg := Config{LocalAS: 65001, Target: "127.0.0.1:0", RouterID: netip.MustParseAddr("10.0.0.1"), Families: []bgp.Family{bgp.RF_IPv4_UC}}
	cfg.ApplyDefaults()
	p := &Peer{cfg: cfg, fsm: &fsm{observed: o}}
	p.fsm.state.Store(int32(StateEstablished))

	// Old observation that should be ignored.
	o.applyUpdate(bgp.RF_IPv4_UC, timing.Now(), mustPathNLRIs(t, "10.10.0.0/24"), nil)

	time.Sleep(5 * time.Millisecond)
	cutoff := timing.Now()

	// Same prefix re-observed *after* cutoff in a goroutine.
	go func() {
		time.Sleep(10 * time.Millisecond)
		o.applyUpdate(bgp.RF_IPv4_UC, timing.Now(), mustPathNLRIs(t, "10.10.0.0/24"), nil)
	}()

	// FirstSeen is sticky, so onlyAfter must NOT pass with old timestamp.
	// We expect timeout because FirstSeen is before the cutoff even after re-advertise.
	res, err := p.WaitForPrefixes([]string{"10.10.0.0/24"}, 100*time.Millisecond, cutoff)
	if err == nil {
		t.Fatalf("expected timeout, got nil err, res=%+v", res)
	}
}
