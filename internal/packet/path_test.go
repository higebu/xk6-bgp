package packet

import (
	"net/netip"
	"testing"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func parseAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

func ipRoutes(family bgp.Family, prefixes ...string) []Route {
	out := make([]Route, len(prefixes))
	for i, p := range prefixes {
		out[i] = MustIPRoute(family, mustPrefix(p))
	}
	return out
}

func TestBuildUpdateMessage_AdvertiseRoundTrip(t *testing.T) {
	msg, err := BuildUpdateMessage(false,
		PathAttrs{NextHop: parseAddr("10.0.0.1"), LocalAS: 65001},
		ipRoutes(bgp.RF_IPv4_UC, "10.100.0.0/24", "10.100.1.0/24"),
		EncodingOptions{})
	if err != nil {
		t.Fatalf("BuildUpdateMessage: %v", err)
	}
	buf, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	parsed, err := bgp.ParseBGPMessage(buf)
	if err != nil {
		t.Fatalf("ParseBGPMessage: %v", err)
	}
	upd, ok := parsed.Body.(*bgp.BGPUpdate)
	if !ok {
		t.Fatalf("body is %T not BGPUpdate", parsed.Body)
	}

	for _, a := range upd.PathAttributes {
		if _, ok := a.(*bgp.PathAttributeMpReachNLRI); ok {
			t.Fatalf("IPv4 unicast must not use MP_REACH_NLRI")
		}
	}
	var nh *bgp.PathAttributeNextHop
	for _, a := range upd.PathAttributes {
		if v, ok := a.(*bgp.PathAttributeNextHop); ok {
			nh = v
			break
		}
	}
	if nh == nil {
		t.Fatal("NEXT_HOP attribute not found")
	}
	if nh.Value.String() != "10.0.0.1" {
		t.Fatalf("nexthop mismatch: %s", nh.Value)
	}
	if got := len(upd.NLRI); got != 2 {
		t.Fatalf("expected 2 NLRIs, got %d", got)
	}
	gotPrefixes := map[string]bool{}
	for _, pn := range upd.NLRI {
		gotPrefixes[pn.NLRI.String()] = true
	}
	for _, want := range []string{"10.100.0.0/24", "10.100.1.0/24"} {
		if !gotPrefixes[want] {
			t.Errorf("missing prefix %s in parsed UPDATE", want)
		}
	}
}

func TestBuildUpdateMessage_WithdrawRoundTrip(t *testing.T) {
	msg, err := BuildUpdateMessage(true, PathAttrs{},
		ipRoutes(bgp.RF_IPv4_UC, "10.100.0.0/24"), EncodingOptions{})
	if err != nil {
		t.Fatalf("BuildUpdateMessage: %v", err)
	}
	buf, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	parsed, err := bgp.ParseBGPMessage(buf)
	if err != nil {
		t.Fatalf("ParseBGPMessage: %v", err)
	}
	upd, ok := parsed.Body.(*bgp.BGPUpdate)
	if !ok {
		t.Fatalf("body is %T not BGPUpdate", parsed.Body)
	}
	for _, a := range upd.PathAttributes {
		if _, ok := a.(*bgp.PathAttributeMpUnreachNLRI); ok {
			t.Fatalf("IPv4 unicast must not use MP_UNREACH_NLRI")
		}
	}
	if len(upd.WithdrawnRoutes) != 1 || upd.WithdrawnRoutes[0].NLRI.String() != "10.100.0.0/24" {
		t.Fatalf("unexpected withdrawn NLRIs: %+v", upd.WithdrawnRoutes)
	}
}

func TestBuildUpdateMessage_IPv6AdvertiseRoundTrip(t *testing.T) {
	msg, err := BuildUpdateMessage(false,
		PathAttrs{NextHop: parseAddr("2001:db8::1"), LocalAS: 65001},
		ipRoutes(bgp.RF_IPv6_UC,
			"2001:db8:1::/48",
			"2001:db8:2::/48",
			"2001:0db8:3::/48", // non-canonical input
		), EncodingOptions{})
	if err != nil {
		t.Fatalf("BuildUpdateMessage: %v", err)
	}
	buf, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	parsed, err := bgp.ParseBGPMessage(buf)
	if err != nil {
		t.Fatalf("ParseBGPMessage: %v", err)
	}
	upd, ok := parsed.Body.(*bgp.BGPUpdate)
	if !ok {
		t.Fatalf("body is %T not BGPUpdate", parsed.Body)
	}

	var mpr *bgp.PathAttributeMpReachNLRI
	for _, a := range upd.PathAttributes {
		if v, ok := a.(*bgp.PathAttributeMpReachNLRI); ok {
			mpr = v
			break
		}
	}
	if mpr == nil {
		t.Fatal("MP_REACH_NLRI not found")
	}
	if mpr.AFI != bgp.AFI_IP6 || mpr.SAFI != bgp.SAFI_UNICAST {
		t.Fatalf("unexpected AFI/SAFI: %d/%d", mpr.AFI, mpr.SAFI)
	}
	if mpr.Nexthop.String() != "2001:db8::1" {
		t.Fatalf("nexthop mismatch: %s", mpr.Nexthop)
	}
	if got := len(mpr.Value); got != 3 {
		t.Fatalf("expected 3 NLRIs, got %d", got)
	}
	gotPrefixes := map[string]bool{}
	for _, pn := range mpr.Value {
		gotPrefixes[pn.NLRI.String()] = true
	}
	for _, want := range []string{"2001:db8:1::/48", "2001:db8:2::/48", "2001:db8:3::/48"} {
		if !gotPrefixes[want] {
			t.Errorf("missing prefix %s in parsed UPDATE", want)
		}
	}
}

func TestBuildUpdateMessage_IPv6WithdrawRoundTrip(t *testing.T) {
	msg, err := BuildUpdateMessage(true, PathAttrs{},
		ipRoutes(bgp.RF_IPv6_UC, "2001:db8:1::/48"), EncodingOptions{})
	if err != nil {
		t.Fatalf("BuildUpdateMessage: %v", err)
	}
	buf, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	parsed, err := bgp.ParseBGPMessage(buf)
	if err != nil {
		t.Fatalf("ParseBGPMessage: %v", err)
	}
	upd := parsed.Body.(*bgp.BGPUpdate)
	var mpu *bgp.PathAttributeMpUnreachNLRI
	for _, a := range upd.PathAttributes {
		if v, ok := a.(*bgp.PathAttributeMpUnreachNLRI); ok {
			mpu = v
			break
		}
	}
	if mpu == nil {
		t.Fatal("MP_UNREACH_NLRI not found")
	}
	if mpu.AFI != bgp.AFI_IP6 || mpu.SAFI != bgp.SAFI_UNICAST {
		t.Fatalf("unexpected AFI/SAFI: %d/%d", mpu.AFI, mpu.SAFI)
	}
	if len(mpu.Value) != 1 || mpu.Value[0].NLRI.String() != "2001:db8:1::/48" {
		t.Fatalf("unexpected withdrawn NLRIs: %+v", mpu.Value)
	}
}

func TestChunkRoutes_IPv6(t *testing.T) {
	// 2000 distinct IPv6 /128 NLRIs blow past the 4096-byte limit when
	// packed with full IPv6-unicast path attrs (Origin / AS_PATH /
	// MP_REACH_NLRI / next-hop).
	const n = 2000
	routes := make([]Route, 0, n)
	for i := range n {
		hi := uint16(i >> 16)
		lo := uint16(i & 0xffff)
		routes = append(routes, MustIPRoute(bgp.RF_IPv6_UC,
			netip.PrefixFrom(
				netip.AddrFrom16([16]byte{
					0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0,
					0, 0, 0, 0, byte(hi >> 8), byte(hi), byte(lo >> 8), byte(lo),
				}), 128)))
	}
	attrs := PathAttrs{NextHop: parseAddr("2001:db8::1"), LocalAS: 65001}
	chunks, err := ChunkRoutes(false, attrs, routes, EncodingOptions{})
	if err != nil {
		t.Fatalf("ChunkRoutes: %v", err)
	}
	if len(chunks) < 2 {
		t.Fatalf("expected >=2 chunks for %d /128 routes, got %d", n, len(chunks))
	}
	total := 0
	for _, c := range chunks {
		msg, err := BuildUpdateMessage(false, attrs, c, EncodingOptions{})
		if err != nil {
			t.Fatalf("BuildUpdateMessage: %v", err)
		}
		buf, err := msg.Serialize()
		if err != nil {
			t.Fatalf("Serialize: %v", err)
		}
		if len(buf) > bgp.BGP_MAX_MESSAGE_LENGTH {
			t.Fatalf("chunk serialized to %dB > %dB", len(buf), bgp.BGP_MAX_MESSAGE_LENGTH)
		}
		total += len(c)
	}
	if total != n {
		t.Fatalf("chunked %d routes, want %d", total, n)
	}
}

func TestChunkRoutes_ExtendedMessages(t *testing.T) {
	// 5000 IPv4 /32 routes pack into ~7 chunks at the 4096-byte limit,
	// but a single chunk under the 65535-byte Extended Messages limit.
	const n = 5000
	routes := make([]Route, 0, n)
	for i := range n {
		routes = append(routes, MustIPRoute(bgp.RF_IPv4_UC,
			netip.PrefixFrom(
				netip.AddrFrom4([4]byte{10, byte((i >> 16) & 0xff), byte((i >> 8) & 0xff), byte(i & 0xff)}), 32)))
	}
	attrs := PathAttrs{NextHop: parseAddr("10.0.0.1"), LocalAS: 65001}

	chunks, err := ChunkRoutes(false, attrs, routes, EncodingOptions{})
	if err != nil {
		t.Fatalf("ChunkRoutes (default): %v", err)
	}
	if len(chunks) < 5 {
		t.Fatalf("expected >=5 chunks at 4096B for %d /32 routes, got %d", n, len(chunks))
	}

	chunksExt, err := ChunkRoutes(false, attrs, routes, EncodingOptions{UseExtendedMessages: true})
	if err != nil {
		t.Fatalf("ChunkRoutes (extended): %v", err)
	}
	if len(chunksExt) != 1 {
		t.Fatalf("expected single chunk under 65535B for %d /32 routes, got %d", n, len(chunksExt))
	}

	msg, err := BuildUpdateMessage(false, attrs, chunksExt[0], EncodingOptions{UseExtendedMessages: true})
	if err != nil {
		t.Fatalf("BuildUpdateMessage: %v", err)
	}
	buf, err := SerializeMessage(msg, EncodingOptions{UseExtendedMessages: true})
	if err != nil {
		t.Fatalf("SerializeMessage: %v", err)
	}
	if len(buf) <= bgp.BGP_MAX_MESSAGE_LENGTH {
		t.Fatalf("extended-messages chunk serialized to %dB, expected > %dB", len(buf), bgp.BGP_MAX_MESSAGE_LENGTH)
	}
	if len(buf) > BGPExtendedMaxMessageLength {
		t.Fatalf("extended-messages chunk serialized to %dB > %dB", len(buf), BGPExtendedMaxMessageLength)
	}
}

func TestBuildUpdateMessage_FamilyMismatch(t *testing.T) {
	// IPRoute's constructor rejects a v6 prefix under the IPv4 family,
	// so the mismatch is caught at NewIPRoute rather than inside
	// BuildUpdateMessage. The intent of this test is preserved: a route
	// whose address family does not match the requested family must
	// not produce a valid UPDATE.
	_, err := NewIPRoute(bgp.RF_IPv4_UC, mustPrefix("2001:db8::/64"))
	if err == nil {
		t.Fatal("expected family-mismatch error from NewIPRoute")
	}
}

func TestBuildUpdateMessage_MixedFamilyRejected(t *testing.T) {
	mixed := []Route{
		MustIPRoute(bgp.RF_IPv4_UC, mustPrefix("10.0.0.0/24")),
		MustIPRoute(bgp.RF_IPv6_UC, mustPrefix("2001:db8::/64")),
	}
	_, err := BuildUpdateMessage(false,
		PathAttrs{NextHop: parseAddr("10.0.0.1"), LocalAS: 65001},
		mixed, EncodingOptions{})
	if err == nil {
		t.Fatal("expected error when routes carry mixed families")
	}
}

func TestBuildUpdateMessage_EmptyRoutes(t *testing.T) {
	_, err := BuildUpdateMessage(false,
		PathAttrs{NextHop: parseAddr("10.0.0.1"), LocalAS: 65001}, nil, EncodingOptions{})
	if err == nil {
		t.Fatal("expected error for empty routes")
	}
}

// TestBuildUpdateMessage_IPv4UnicastForceMpReach verifies that the
// UseMpReachForIPv4Unicast escape hatch puts IPv4 unicast into
// MP_REACH_NLRI even though the default is the traditional NLRI field.
func TestBuildUpdateMessage_IPv4UnicastForceMpReach(t *testing.T) {
	msg, err := BuildUpdateMessage(false,
		PathAttrs{NextHop: parseAddr("10.0.0.1"), LocalAS: 65001},
		ipRoutes(bgp.RF_IPv4_UC, "10.100.0.0/24"),
		EncodingOptions{UseMpReachForIPv4Unicast: true})
	if err != nil {
		t.Fatalf("BuildUpdateMessage: %v", err)
	}
	buf, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	parsed, err := bgp.ParseBGPMessage(buf)
	if err != nil {
		t.Fatalf("ParseBGPMessage: %v", err)
	}
	upd := parsed.Body.(*bgp.BGPUpdate)
	if len(upd.NLRI) != 0 {
		t.Fatalf("expected empty traditional NLRI under forced MP_REACH, got %d", len(upd.NLRI))
	}
	var mpr *bgp.PathAttributeMpReachNLRI
	for _, a := range upd.PathAttributes {
		if v, ok := a.(*bgp.PathAttributeMpReachNLRI); ok {
			mpr = v
			break
		}
	}
	if mpr == nil {
		t.Fatal("MP_REACH_NLRI not found under UseMpReachForIPv4Unicast")
	}
	if mpr.AFI != bgp.AFI_IP || mpr.SAFI != bgp.SAFI_UNICAST {
		t.Fatalf("unexpected AFI/SAFI: %d/%d", mpr.AFI, mpr.SAFI)
	}
	var nh *bgp.PathAttributeNextHop
	for _, a := range upd.PathAttributes {
		if v, ok := a.(*bgp.PathAttributeNextHop); ok {
			nh = v
			break
		}
	}
	if nh == nil {
		t.Fatal("NEXT_HOP attribute not found under UseMpReachForIPv4Unicast " +
			"(RFC 4271 section 5 well-known mandatory; FRR rejects re-encoded UPDATE without it)")
	}
	if nh.Value.String() != "10.0.0.1" {
		t.Fatalf("NEXT_HOP value: got %s want 10.0.0.1", nh.Value)
	}
}

// TestBuildUpdateMessage_IPv6AdvertiseNoIPv4NextHop verifies that an
// IPv6-unicast UPDATE (which is always MP_REACH) does NOT carry the
// IPv4-only NEXT_HOP attribute — that attribute is invalid for an
// IPv6 next-hop and would be rejected.
func TestBuildUpdateMessage_IPv6AdvertiseNoIPv4NextHop(t *testing.T) {
	msg, err := BuildUpdateMessage(false,
		PathAttrs{NextHop: parseAddr("2001:db8::1"), LocalAS: 65001},
		ipRoutes(bgp.RF_IPv6_UC, "2001:db8:1::/64"),
		EncodingOptions{})
	if err != nil {
		t.Fatalf("BuildUpdateMessage: %v", err)
	}
	buf, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	parsed, err := bgp.ParseBGPMessage(buf)
	if err != nil {
		t.Fatalf("ParseBGPMessage: %v", err)
	}
	upd := parsed.Body.(*bgp.BGPUpdate)
	for _, a := range upd.PathAttributes {
		if _, ok := a.(*bgp.PathAttributeNextHop); ok {
			t.Fatal("unexpected IPv4 NEXT_HOP attribute in IPv6-unicast UPDATE")
		}
	}
}

// TestBuildUpdateMessage_MPFamilyNoNextHopAttr verifies that MP
// families other than IPv4 unicast (here VPNv4 with an IPv4 next-hop)
// carry the next-hop only inside MP_REACH_NLRI per RFC 4760 section 3
// and never a top-level NEXT_HOP attribute — that workaround is
// reserved for MP_REACH-encoded IPv4 unicast.
func TestBuildUpdateMessage_MPFamilyNoNextHopAttr(t *testing.T) {
	rd := mustRD(t, "65000:1")
	r, err := NewVPNIPRoute(bgp.RF_IPv4_VPN, rd, netip.MustParsePrefix("10.1.0.0/24"))
	if err != nil {
		t.Fatalf("NewVPNIPRoute: %v", err)
	}
	msg, err := BuildUpdateMessage(false,
		PathAttrs{NextHop: parseAddr("10.0.0.1"), LocalAS: 65001},
		[]Route{r}, EncodingOptions{})
	if err != nil {
		t.Fatalf("BuildUpdateMessage: %v", err)
	}
	buf, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	parsed, err := bgp.ParseBGPMessage(buf)
	if err != nil {
		t.Fatalf("ParseBGPMessage: %v", err)
	}
	upd := parsed.Body.(*bgp.BGPUpdate)
	for _, a := range upd.PathAttributes {
		if _, ok := a.(*bgp.PathAttributeNextHop); ok {
			t.Fatal("unexpected NEXT_HOP attribute in VPNv4 UPDATE")
		}
	}
}

// TestBuildUpdateMessage_AddPathIPv4RoundTrip serializes two paths for
// the same IPv4 prefix with ADD-PATH send enabled and re-parses them
// with the receive-side option, checking the Path Identifiers survive
// the traditional NLRI field.
func TestBuildUpdateMessage_AddPathIPv4RoundTrip(t *testing.T) {
	txOpts := EncodingOptions{
		AddPath: map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_SEND},
	}
	routes := []Route{
		WithPathID(MustIPRoute(bgp.RF_IPv4_UC, mustPrefix("10.100.0.0/24")), 1),
		WithPathID(MustIPRoute(bgp.RF_IPv4_UC, mustPrefix("10.100.0.0/24")), 2),
	}
	msg, err := BuildUpdateMessage(false,
		PathAttrs{NextHop: parseAddr("10.0.0.1"), LocalAS: 65001}, routes, txOpts)
	if err != nil {
		t.Fatalf("BuildUpdateMessage: %v", err)
	}
	buf, err := SerializeMessage(msg, txOpts)
	if err != nil {
		t.Fatalf("SerializeMessage: %v", err)
	}
	parsed, err := bgp.ParseBGPMessage(buf, &bgp.MarshallingOption{
		AddPath: map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_RECEIVE},
	})
	if err != nil {
		t.Fatalf("ParseBGPMessage: %v", err)
	}
	upd := parsed.Body.(*bgp.BGPUpdate)
	if len(upd.NLRI) != 2 {
		t.Fatalf("NLRI count = %d, want 2", len(upd.NLRI))
	}
	for i, wantID := range []uint32{1, 2} {
		if upd.NLRI[i].ID != wantID || upd.NLRI[i].NLRI.String() != "10.100.0.0/24" {
			t.Errorf("NLRI[%d] = %s id=%d, want 10.100.0.0/24 id=%d",
				i, upd.NLRI[i].NLRI, upd.NLRI[i].ID, wantID)
		}
	}
}

// TestBuildUpdateMessage_AddPathIPv6MPReachRoundTrip does the same for
// an MP_REACH_NLRI family.
func TestBuildUpdateMessage_AddPathIPv6MPReachRoundTrip(t *testing.T) {
	txOpts := EncodingOptions{
		AddPath: map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv6_UC: bgp.BGP_ADD_PATH_SEND},
	}
	routes := []Route{
		WithPathID(MustIPRoute(bgp.RF_IPv6_UC, mustPrefix("2001:db8:a::/48")), 7),
		WithPathID(MustIPRoute(bgp.RF_IPv6_UC, mustPrefix("2001:db8:a::/48")), 8),
	}
	msg, err := BuildUpdateMessage(false,
		PathAttrs{NextHop: parseAddr("2001:db8::1"), LocalAS: 65001}, routes, txOpts)
	if err != nil {
		t.Fatalf("BuildUpdateMessage: %v", err)
	}
	buf, err := SerializeMessage(msg, txOpts)
	if err != nil {
		t.Fatalf("SerializeMessage: %v", err)
	}
	parsed, err := bgp.ParseBGPMessage(buf, &bgp.MarshallingOption{
		AddPath: map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv6_UC: bgp.BGP_ADD_PATH_RECEIVE},
	})
	if err != nil {
		t.Fatalf("ParseBGPMessage: %v", err)
	}
	upd := parsed.Body.(*bgp.BGPUpdate)
	var mpr *bgp.PathAttributeMpReachNLRI
	for _, a := range upd.PathAttributes {
		if v, ok := a.(*bgp.PathAttributeMpReachNLRI); ok {
			mpr = v
		}
	}
	if mpr == nil {
		t.Fatal("MP_REACH_NLRI attribute missing")
	}
	if len(mpr.Value) != 2 {
		t.Fatalf("MP_REACH NLRI count = %d, want 2", len(mpr.Value))
	}
	for i, wantID := range []uint32{7, 8} {
		if mpr.Value[i].ID != wantID || mpr.Value[i].NLRI.String() != "2001:db8:a::/48" {
			t.Errorf("Value[%d] = %s id=%d, want 2001:db8:a::/48 id=%d",
				i, mpr.Value[i].NLRI, mpr.Value[i].ID, wantID)
		}
	}
}

// TestBuildUpdateMessage_Use2ByteAS checks RFC 6793 section 4.2.2
// encoding toward an OLD (2-octet AS) peer: mappable local AS numbers
// go into a 2-octet AS_PATH with no AS4_PATH; a non-mappable one
// becomes AS_TRANS in AS_PATH with the real value in AS4_PATH.
func TestBuildUpdateMessage_Use2ByteAS(t *testing.T) {
	cases := []struct {
		name       string
		localAS    uint32
		wantASPath uint32
		wantAs4    bool
	}{
		{"mappable", 65001, 65001, false},
		{"non-mappable", 4200000000, bgp.AS_TRANS, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := EncodingOptions{Use2ByteAS: true}
			msg, err := BuildUpdateMessage(false,
				PathAttrs{NextHop: parseAddr("10.0.0.1"), LocalAS: tc.localAS},
				ipRoutes(bgp.RF_IPv4_UC, "10.100.0.0/24"), opts)
			if err != nil {
				t.Fatalf("BuildUpdateMessage: %v", err)
			}
			buf, err := SerializeMessage(msg, opts)
			if err != nil {
				t.Fatalf("SerializeMessage: %v", err)
			}
			parsed, err := bgp.ParseBGPMessage(buf, &bgp.MarshallingOption{Use2ByteAS: true})
			if err != nil {
				t.Fatalf("ParseBGPMessage: %v", err)
			}
			upd := parsed.Body.(*bgp.BGPUpdate)

			var asPath *bgp.PathAttributeAsPath
			var as4Path *bgp.PathAttributeAs4Path
			for _, a := range upd.PathAttributes {
				switch v := a.(type) {
				case *bgp.PathAttributeAsPath:
					asPath = v
				case *bgp.PathAttributeAs4Path:
					as4Path = v
				}
			}
			if asPath == nil || len(asPath.Value) != 1 {
				t.Fatalf("AS_PATH missing or malformed: %v", asPath)
			}
			if _, ok := asPath.Value[0].(*bgp.AsPathParam); !ok {
				t.Fatalf("AS_PATH param is %T, want 2-octet *bgp.AsPathParam", asPath.Value[0])
			}
			if got := asPath.Value[0].GetAS(); len(got) != 1 || got[0] != tc.wantASPath {
				t.Fatalf("AS_PATH = %v, want [%d]", got, tc.wantASPath)
			}
			if tc.wantAs4 {
				if as4Path == nil || len(as4Path.Value) != 1 {
					t.Fatalf("AS4_PATH missing for non-mappable AS")
				}
				if got := as4Path.Value[0].GetAS(); len(got) != 1 || got[0] != tc.localAS {
					t.Fatalf("AS4_PATH = %v, want [%d]", got, tc.localAS)
				}
			} else if as4Path != nil {
				t.Fatal("AS4_PATH present for a mappable AS (RFC 6793 section 4.2.2 forbids it)")
			}
		})
	}
}

// TestChunkRoutes_AddPath verifies the 4-octet Path Identifier is
// budgeted per NLRI: every chunk must still serialize within
// BGP_MAX_MESSAGE_LENGTH with ADD-PATH send enabled.
func TestChunkRoutes_AddPath(t *testing.T) {
	const n = 2000
	opts := EncodingOptions{
		AddPath: map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_SEND},
	}
	routes := make([]Route, 0, n)
	for i := range n {
		routes = append(routes, WithPathID(MustIPRoute(bgp.RF_IPv4_UC,
			netip.PrefixFrom(
				netip.AddrFrom4([4]byte{10, byte((i >> 16) & 0xff), byte((i >> 8) & 0xff), byte(i & 0xff)}), 32)),
			uint32(i+1)))
	}
	attrs := PathAttrs{NextHop: parseAddr("10.0.0.1"), LocalAS: 65001}

	plain, err := ChunkRoutes(false, attrs, routes, EncodingOptions{})
	if err != nil {
		t.Fatalf("ChunkRoutes (plain): %v", err)
	}
	chunks, err := ChunkRoutes(false, attrs, routes, opts)
	if err != nil {
		t.Fatalf("ChunkRoutes (add-path): %v", err)
	}
	if len(chunks) <= len(plain) {
		t.Fatalf("add-path chunks = %d, want more than the %d plain chunks (4B/NLRI overhead)",
			len(chunks), len(plain))
	}
	total := 0
	for _, c := range chunks {
		msg, err := BuildUpdateMessage(false, attrs, c, opts)
		if err != nil {
			t.Fatalf("BuildUpdateMessage: %v", err)
		}
		buf, err := SerializeMessage(msg, opts)
		if err != nil {
			t.Fatalf("SerializeMessage: %v", err)
		}
		if len(buf) > bgp.BGP_MAX_MESSAGE_LENGTH {
			t.Fatalf("chunk serialized to %dB > %dB", len(buf), bgp.BGP_MAX_MESSAGE_LENGTH)
		}
		total += len(c)
	}
	if total != n {
		t.Fatalf("chunked %d routes, want %d", total, n)
	}
}
