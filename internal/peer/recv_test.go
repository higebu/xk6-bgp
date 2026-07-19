package peer

import (
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/higebu/xk6-bgp/internal/packet"
	"github.com/higebu/xk6-bgp/internal/timing"
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

	o.applyUpdate(bgp.RF_IPv4_UC, false, t0, mustPathNLRIs(t, "10.0.0.0/24", "10.0.1.0/24"), nil)

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
	o.applyUpdate(bgp.RF_IPv4_UC, false, t1, nil, mustPathNLRIs(t, "10.0.0.0/24"))
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
		o.applyUpdate(bgp.RF_IPv4_UC, false, timing.Now(), mustPathNLRIs(t, wantPrefixes...), nil)
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

	o.applyUpdate(bgp.RF_IPv4_UC, false, timing.Now(), mustPathNLRIs(t, "10.10.0.0/24"), nil)
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
	o.applyUpdate(bgp.RF_IPv4_UC, false, timing.Now(), mustPathNLRIs(t, "10.10.0.0/24"), nil)

	time.Sleep(5 * time.Millisecond)
	cutoff := timing.Now()

	// Same prefix re-observed *after* cutoff in a goroutine.
	go func() {
		time.Sleep(10 * time.Millisecond)
		o.applyUpdate(bgp.RF_IPv4_UC, false, timing.Now(), mustPathNLRIs(t, "10.10.0.0/24"), nil)
	}()

	// FirstSeen is sticky, so onlyAfter must NOT pass with old timestamp.
	// We expect timeout because FirstSeen is before the cutoff even after re-advertise.
	res, err := p.WaitForPrefixes([]string{"10.10.0.0/24"}, 100*time.Millisecond, cutoff)
	if err == nil {
		t.Fatalf("expected timeout, got nil err, res=%+v", res)
	}
}

// TestWaitForPrefixes_LastSeenNotSkewedByUnrelatedUpdate verifies that
// LastSeen for a prefix already observed at registration time reflects
// that prefix's own FirstSeen, not a later UPDATE for an unrelated
// prefix that happened to bump the observedSet's lastUpdateAt.
func TestWaitForPrefixes_LastSeenNotSkewedByUnrelatedUpdate(t *testing.T) {
	o := newObservedSet()
	cfg := Config{LocalAS: 65001, Target: "127.0.0.1:0", RouterID: netip.MustParseAddr("10.0.0.1"), Families: []bgp.Family{bgp.RF_IPv4_UC}}
	cfg.ApplyDefaults()
	p := &Peer{cfg: cfg, fsm: &fsm{observed: o}}
	p.fsm.state.Store(int32(StateEstablished))

	tA := timing.Now()
	o.applyUpdate(bgp.RF_IPv4_UC, false, tA, mustPathNLRIs(t, "10.20.0.0/24"), nil)

	time.Sleep(5 * time.Millisecond)
	// An unrelated prefix observed later bumps o.lastUpdateAt well past tA.
	o.applyUpdate(bgp.RF_IPv4_UC, false, timing.Now(), mustPathNLRIs(t, "10.20.99.0/24"), nil)

	res, err := p.WaitForPrefixes([]string{"10.20.0.0/24"}, time.Second, timing.Timestamp{})
	if err != nil {
		t.Fatalf("WaitForPrefixes: %v", err)
	}
	if !res.LastSeen.Time().Equal(tA.Time()) {
		t.Fatalf("LastSeen = %v, want %v (the prefix's own observation, not skewed by the later unrelated UPDATE)",
			res.LastSeen.Time(), tA.Time())
	}
}

// TestWaitForPrefixes_SessionFailureWakesWaiter verifies a session-
// fatal error releases a blocked waiter immediately instead of letting
// it run out the full timeout.
func TestWaitForPrefixes_SessionFailureWakesWaiter(t *testing.T) {
	o := newObservedSet()
	cfg := Config{LocalAS: 65001, Target: "127.0.0.1:0", RouterID: netip.MustParseAddr("10.0.0.1"), Families: []bgp.Family{bgp.RF_IPv4_UC}}
	cfg.ApplyDefaults()
	p := &Peer{cfg: cfg, fsm: &fsm{observed: o}}
	p.fsm.state.Store(int32(StateEstablished))

	go func() {
		time.Sleep(10 * time.Millisecond)
		o.fail(errors.New("peer sent NOTIFICATION"))
	}()

	start := time.Now()
	_, err := p.WaitForPrefixes([]string{"10.10.0.0/24"}, 5*time.Second, timing.Timestamp{})
	if err == nil {
		t.Fatal("expected session-down error")
	}
	if !strings.Contains(err.Error(), "session down") {
		t.Fatalf("err=%v, want session-down error", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("waiter released after %s, want immediate wake", elapsed)
	}
}

// dispatchRaw feeds a hand-crafted wire-format UPDATE through the same
// parse + dispatch path readLoop uses and returns the observed set.
func dispatchRaw(t *testing.T, raw []byte) *observedSet {
	t.Helper()
	msg, err := bgp.ParseBGPMessage(raw)
	if err != nil {
		t.Fatalf("ParseBGPMessage: %v", err)
	}
	upd, ok := msg.Body.(*bgp.BGPUpdate)
	if !ok {
		t.Fatalf("parsed %T, want *bgp.BGPUpdate", msg.Body)
	}
	f := &fsm{observed: newObservedSet()}
	f.dispatchUpdate(upd, timing.Now())
	return f.observed
}

func marker() []byte {
	m := make([]byte, 16)
	for i := range m {
		m[i] = 0xff
	}
	return m
}

// TestDispatch_KnownBytes_IPv4Unicast decodes a byte-literal RFC 4271
// UPDATE (ORIGIN IGP, AS_PATH SEQ{65001}, NEXT_HOP 10.0.0.1, NLRI
// 10.1.0.0/24 + 10.2.0.0/16) so a symmetric encode/decode bug in our
// own builder cannot mask a receive-path regression.
func TestDispatch_KnownBytes_IPv4Unicast(t *testing.T) {
	raw := append(marker(),
		0x00, 0x32, // length 50
		0x02,       // type UPDATE
		0x00, 0x00, // withdrawn routes length 0
		0x00, 0x14, // total path attribute length 20
		0x40, 0x01, 0x01, 0x00, // ORIGIN IGP
		0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9, // AS_PATH SEQ{65001}, 4-octet AS
		0x40, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x01, // NEXT_HOP 10.0.0.1
		0x18, 0x0a, 0x01, 0x00, // 10.1.0.0/24
		0x10, 0x0a, 0x02, // 10.2.0.0/16
	)
	o := dispatchRaw(t, raw)
	for _, want := range []string{"10.1.0.0/24", "10.2.0.0/16"} {
		if _, ok := o.firstSeen[want]; !ok {
			t.Errorf("prefix %s not observed; got %v", want, mapKeys(o.firstSeen))
		}
	}
	if len(o.firstSeen) != 2 {
		t.Errorf("observed %d prefixes, want 2: %v", len(o.firstSeen), mapKeys(o.firstSeen))
	}
}

// TestDispatch_KnownBytes_IPv4Withdraw decodes a byte-literal UPDATE
// whose only content is the Withdrawn Routes field.
func TestDispatch_KnownBytes_IPv4Withdraw(t *testing.T) {
	raw := append(marker(),
		0x00, 0x1b, // length 27
		0x02,       // type UPDATE
		0x00, 0x04, // withdrawn routes length 4
		0x18, 0x0a, 0x01, 0x00, // withdraw 10.1.0.0/24
		0x00, 0x00, // total path attribute length 0
	)
	o := dispatchRaw(t, raw)
	if _, ok := o.withdrawn["10.1.0.0/24"]; !ok {
		t.Fatalf("10.1.0.0/24 not marked withdrawn")
	}
}

// TestDispatch_KnownBytes_IPv6MPReach decodes a byte-literal RFC 4760
// UPDATE carrying 2001:db8:1::/64 in MP_REACH_NLRI.
func TestDispatch_KnownBytes_IPv6MPReach(t *testing.T) {
	raw := append(marker(),
		0x00, 0x45, // length 69
		0x02,       // type UPDATE
		0x00, 0x00, // withdrawn routes length 0
		0x00, 0x2e, // total path attribute length 46
		0x40, 0x01, 0x01, 0x00, // ORIGIN IGP
		0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9, // AS_PATH SEQ{65001}, 4-octet AS
		0x80, 0x0e, 0x1e, // MP_REACH_NLRI, length 30
		0x00, 0x02, 0x01, // AFI 2 (IPv6) / SAFI 1 (unicast)
		0x10, // next-hop length 16
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 2001:db8::1
		0x00,                                                 // reserved
		0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, // 2001:db8:1::/64
	)
	o := dispatchRaw(t, raw)
	if _, ok := o.firstSeen["2001:db8:1::/64"]; !ok {
		t.Fatalf("2001:db8:1::/64 not observed; got %v", mapKeys(o.firstSeen))
	}
}

// TestDispatch_KnownBytes_VPNv4MPReach decodes a byte-literal RFC 4364
// / RFC 8277 UPDATE carrying RD 65000:1, label 0 (RFC 9252 section 4
// no-transposition form), prefix 10.1.0.0/24 in MP_REACH_NLRI.
func TestDispatch_KnownBytes_VPNv4MPReach(t *testing.T) {
	raw := append(marker(),
		0x00, 0x47, // length 71
		0x02,       // type UPDATE
		0x00, 0x00, // withdrawn routes length 0
		0x00, 0x30, // total path attribute length 48
		0x40, 0x01, 0x01, 0x00, // ORIGIN IGP
		0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9, // AS_PATH SEQ{65001}, 4-octet AS
		0x80, 0x0e, 0x20, // MP_REACH_NLRI, length 32
		0x00, 0x01, 0x80, // AFI 1 (IPv4) / SAFI 128 (MPLS-labeled VPN)
		0x0c, // next-hop length 12 (zeroed RD + IPv4 per RFC 4364 section 4.3.2)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x01, // next-hop 10.0.0.1
		0x00,             // reserved
		0x70,             // NLRI length 112 bits: label(24) + RD(64) + prefix(24)
		0x00, 0x00, 0x01, // label 0, bottom-of-stack
		0x00, 0x00, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x01, // RD type 0, 65000:1
		0x0a, 0x01, 0x00, // 10.1.0.0/24
	)
	o := dispatchRaw(t, raw)
	if len(o.firstSeen) != 1 {
		t.Fatalf("observed %d prefixes, want 1: %v", len(o.firstSeen), mapKeys(o.firstSeen))
	}
	if _, ok := o.firstSeen["65000:1:10.1.0.0/24"]; !ok {
		t.Fatalf("VPNv4 NLRI not observed under expected key; got %v", mapKeys(o.firstSeen))
	}
}

// dispatchRawAddPath is dispatchRaw for a session that negotiated
// ADD-PATH receive for the given families: the parse gets the matching
// MarshallingOption and the fsm carries the negotiated modes.
func dispatchRawAddPath(t *testing.T, raw []byte, fams ...bgp.Family) *observedSet {
	t.Helper()
	modes := make(map[bgp.Family]bgp.BGPAddPathMode, len(fams))
	for _, fam := range fams {
		modes[fam] = bgp.BGP_ADD_PATH_RECEIVE
	}
	msg, err := bgp.ParseBGPMessage(raw, &bgp.MarshallingOption{AddPath: modes})
	if err != nil {
		t.Fatalf("ParseBGPMessage: %v", err)
	}
	upd, ok := msg.Body.(*bgp.BGPUpdate)
	if !ok {
		t.Fatalf("parsed %T, want *bgp.BGPUpdate", msg.Body)
	}
	f := &fsm{observed: newObservedSet(), addPathNegotiated: modes}
	f.dispatchUpdate(upd, timing.Now())
	return f.observed
}

// TestDispatch_KnownBytes_IPv4UnicastAddPath decodes a byte-literal
// RFC 7911 UPDATE carrying the same prefix twice under Path
// Identifiers 1 and 2. Both must be recorded as distinct routes under
// "<prefix>:<path-id>" keys.
func TestDispatch_KnownBytes_IPv4UnicastAddPath(t *testing.T) {
	raw := append(marker(),
		0x00, 0x3b, // length 59
		0x02,       // type UPDATE
		0x00, 0x00, // withdrawn routes length 0
		0x00, 0x14, // total path attribute length 20
		0x40, 0x01, 0x01, 0x00, // ORIGIN IGP
		0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9, // AS_PATH SEQ{65001}, 4-octet AS
		0x40, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x01, // NEXT_HOP 10.0.0.1
		0x00, 0x00, 0x00, 0x01, 0x18, 0x0a, 0x01, 0x00, // path-id 1, 10.1.0.0/24
		0x00, 0x00, 0x00, 0x02, 0x18, 0x0a, 0x01, 0x00, // path-id 2, 10.1.0.0/24
	)
	o := dispatchRawAddPath(t, raw, bgp.RF_IPv4_UC)
	for _, want := range []string{"10.1.0.0/24:1", "10.1.0.0/24:2"} {
		if _, ok := o.firstSeen[want]; !ok {
			t.Errorf("path %s not observed; got %v", want, mapKeys(o.firstSeen))
		}
	}
	if len(o.firstSeen) != 2 {
		t.Errorf("observed %d routes, want 2: %v", len(o.firstSeen), mapKeys(o.firstSeen))
	}
}

// TestDispatch_KnownBytes_IPv4WithdrawAddPath decodes a byte-literal
// UPDATE withdrawing one specific path of a prefix.
func TestDispatch_KnownBytes_IPv4WithdrawAddPath(t *testing.T) {
	raw := append(marker(),
		0x00, 0x1f, // length 31
		0x02,       // type UPDATE
		0x00, 0x08, // withdrawn routes length 8
		0x00, 0x00, 0x00, 0x01, 0x18, 0x0a, 0x01, 0x00, // path-id 1, withdraw 10.1.0.0/24
		0x00, 0x00, // total path attribute length 0
	)
	o := dispatchRawAddPath(t, raw, bgp.RF_IPv4_UC)
	if _, ok := o.withdrawn["10.1.0.0/24:1"]; !ok {
		t.Fatalf("10.1.0.0/24:1 not marked withdrawn")
	}
}

// TestDispatch_KnownBytes_IPv6MPReachAddPath decodes a byte-literal
// RFC 4760 + RFC 7911 UPDATE carrying 2001:db8:1::/64 under Path
// Identifier 5 in MP_REACH_NLRI.
func TestDispatch_KnownBytes_IPv6MPReachAddPath(t *testing.T) {
	raw := append(marker(),
		0x00, 0x49, // length 73
		0x02,       // type UPDATE
		0x00, 0x00, // withdrawn routes length 0
		0x00, 0x32, // total path attribute length 50
		0x40, 0x01, 0x01, 0x00, // ORIGIN IGP
		0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9, // AS_PATH SEQ{65001}, 4-octet AS
		0x80, 0x0e, 0x22, // MP_REACH_NLRI, length 34
		0x00, 0x02, 0x01, // AFI 2 (IPv6) / SAFI 1 (unicast)
		0x10, // next-hop length 16
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 2001:db8::1
		0x00,                   // reserved
		0x00, 0x00, 0x00, 0x05, // path-id 5
		0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, // 2001:db8:1::/64
	)
	o := dispatchRawAddPath(t, raw, bgp.RF_IPv6_UC)
	if _, ok := o.firstSeen["2001:db8:1::/64:5"]; !ok {
		t.Fatalf("2001:db8:1::/64:5 not observed; got %v", mapKeys(o.firstSeen))
	}
}

// TestDispatch_KnownBytes_TwoByteASPath decodes a byte-literal UPDATE
// from a peer that never negotiated the RFC 6793 4-octet AS capability
// — the AS_PATH carries 2-octet AS numbers, which gobgp's default
// 4-octet parse must reject and the Use2ByteAS option must accept.
func TestDispatch_KnownBytes_TwoByteASPath(t *testing.T) {
	raw := append(marker(),
		0x00, 0x2d, // length 45
		0x02,       // type UPDATE
		0x00, 0x00, // withdrawn routes length 0
		0x00, 0x12, // total path attribute length 18
		0x40, 0x01, 0x01, 0x00, // ORIGIN IGP
		0x40, 0x02, 0x04, 0x02, 0x01, 0xfd, 0xe9, // AS_PATH SEQ{65001}, 2-octet AS
		0x40, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x01, // NEXT_HOP 10.0.0.1
		0x18, 0x0a, 0x01, 0x00, // 10.1.0.0/24
	)
	if _, err := bgp.ParseBGPMessage(raw); err == nil {
		t.Fatal("expected the default 4-octet AS parse to reject a 2-octet AS_PATH")
	}
	msg, err := bgp.ParseBGPMessage(raw, &bgp.MarshallingOption{Use2ByteAS: true})
	if err != nil {
		t.Fatalf("ParseBGPMessage with Use2ByteAS: %v", err)
	}
	upd, ok := msg.Body.(*bgp.BGPUpdate)
	if !ok {
		t.Fatalf("parsed %T, want *bgp.BGPUpdate", msg.Body)
	}
	f := &fsm{observed: newObservedSet()}
	f.dispatchUpdate(upd, timing.Now())
	if _, ok := f.observed.firstSeen["10.1.0.0/24"]; !ok {
		t.Fatalf("10.1.0.0/24 not observed; got %v", mapKeys(f.observed.firstSeen))
	}
}

func mapKeys(m map[string]timing.Timestamp) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
