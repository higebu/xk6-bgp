package packet

import (
	"net/netip"
	"testing"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func mustRD(t *testing.T, s string) bgp.RouteDistinguisherInterface {
	t.Helper()
	rd, err := bgp.ParseRouteDistinguisher(s)
	if err != nil {
		t.Fatalf("ParseRouteDistinguisher(%q): %v", s, err)
	}
	return rd
}

// roundTripMUPUpdate builds an UPDATE for a single MUP route, serializes
// it, parses it back, and returns the recovered MP_REACH NLRI. Every MUP
// test below funnels through this so the wire-level expectations stay in
// one place.
func roundTripMUPUpdate(t *testing.T, route Route, nextHop netip.Addr) bgp.NLRI {
	t.Helper()
	attrs := PathAttrs{NextHop: nextHop, LocalAS: 65001}
	msg, err := BuildUpdateMessage(false, attrs, []Route{route}, EncodingOptions{})
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
	if mpr.SAFI != bgp.SAFI_MUP {
		t.Fatalf("expected SAFI_MUP, got %d", mpr.SAFI)
	}
	if len(mpr.Value) != 1 {
		t.Fatalf("expected 1 NLRI, got %d", len(mpr.Value))
	}
	return mpr.Value[0].NLRI
}

func TestMUPRoute_ISDRoundTrip(t *testing.T) {
	rd := mustRD(t, "65000:1")
	cases := []struct {
		name   string
		family bgp.Family
		prefix string
		nh     string
	}{
		{"ipv4", bgp.RF_MUP_IPv4, "10.10.10.0/24", "10.0.0.1"},
		{"ipv6", bgp.RF_MUP_IPv6, "2001:db8:1::/48", "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewMUPInterworkSegmentDiscoveryRoute(tc.family, rd, mustPrefix(tc.prefix))
			if err != nil {
				t.Fatalf("NewMUPInterworkSegmentDiscoveryRoute: %v", err)
			}
			got := roundTripMUPUpdate(t, r, parseAddr(tc.nh))
			n, ok := got.(*bgp.MUPNLRI)
			if !ok {
				t.Fatalf("recovered NLRI is %T", got)
			}
			if n.RouteType != bgp.MUP_ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY {
				t.Fatalf("route type = %d, want ISD", n.RouteType)
			}
			isd := n.RouteTypeData.(*bgp.MUPInterworkSegmentDiscoveryRoute)
			if isd.Prefix.String() != mustPrefix(tc.prefix).String() {
				t.Fatalf("prefix=%s, want %s", isd.Prefix, tc.prefix)
			}
			if isd.RD.String() != "65000:1" {
				t.Fatalf("rd=%s, want 65000:1", isd.RD)
			}
		})
	}
}

func TestMUPRoute_DSDRoundTrip(t *testing.T) {
	rd := mustRD(t, "65000:1")
	cases := []struct {
		name    string
		family  bgp.Family
		address string
		nh      string
	}{
		{"ipv4", bgp.RF_MUP_IPv4, "10.10.10.1", "10.0.0.1"},
		{"ipv6", bgp.RF_MUP_IPv6, "2001:db8::1", "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewMUPDirectSegmentDiscoveryRoute(tc.family, rd, parseAddr(tc.address))
			if err != nil {
				t.Fatalf("NewMUPDirectSegmentDiscoveryRoute: %v", err)
			}
			got := roundTripMUPUpdate(t, r, parseAddr(tc.nh))
			n, ok := got.(*bgp.MUPNLRI)
			if !ok {
				t.Fatalf("recovered NLRI is %T", got)
			}
			if n.RouteType != bgp.MUP_ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY {
				t.Fatalf("route type = %d, want DSD", n.RouteType)
			}
			dsd := n.RouteTypeData.(*bgp.MUPDirectSegmentDiscoveryRoute)
			if dsd.Address.String() != parseAddr(tc.address).String() {
				t.Fatalf("address=%s, want %s", dsd.Address, tc.address)
			}
		})
	}
}

func TestMUPRoute_T1STRoundTrip(t *testing.T) {
	rd := mustRD(t, "65000:1")
	v4Src := parseAddr("10.10.10.2")
	v6Src := parseAddr("2001:db8::2")
	cases := []struct {
		name     string
		family   bgp.Family
		prefix   string
		teid     string
		qfi      uint8
		endpoint string
		source   *netip.Addr
		nh       string
	}{
		{"ipv4_no_source", bgp.RF_MUP_IPv4, "192.0.2.0/24", "0.0.0.100", 9, "10.10.10.1", nil, "10.0.0.1"},
		{"ipv4_with_source", bgp.RF_MUP_IPv4, "192.0.2.0/24", "0.0.0.100", 9, "10.10.10.1", &v4Src, "10.0.0.1"},
		{"ipv6_no_source", bgp.RF_MUP_IPv6, "2001:db8:1::/48", "0.0.0.100", 9, "2001:db8::1", nil, "2001:db8::1"},
		{"ipv6_with_source", bgp.RF_MUP_IPv6, "2001:db8:1::/48", "0.0.0.100", 9, "2001:db8::1", &v6Src, "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewMUPType1SessionTransformedRoute(tc.family, rd,
				mustPrefix(tc.prefix), parseAddr(tc.teid), tc.qfi, parseAddr(tc.endpoint), tc.source)
			if err != nil {
				t.Fatalf("NewMUPType1SessionTransformedRoute: %v", err)
			}
			got := roundTripMUPUpdate(t, r, parseAddr(tc.nh))
			n, ok := got.(*bgp.MUPNLRI)
			if !ok {
				t.Fatalf("recovered NLRI is %T", got)
			}
			if n.RouteType != bgp.MUP_ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED {
				t.Fatalf("route type = %d, want T1ST", n.RouteType)
			}
			t1 := n.RouteTypeData.(*bgp.MUPType1SessionTransformedRoute)
			if t1.Prefix.String() != mustPrefix(tc.prefix).String() {
				t.Fatalf("prefix=%s, want %s", t1.Prefix, tc.prefix)
			}
			if t1.TEID.String() != parseAddr(tc.teid).String() {
				t.Fatalf("teid=%s, want %s", t1.TEID, tc.teid)
			}
			if t1.QFI != tc.qfi {
				t.Fatalf("qfi=%d, want %d", t1.QFI, tc.qfi)
			}
			if t1.EndpointAddress.String() != parseAddr(tc.endpoint).String() {
				t.Fatalf("endpoint=%s, want %s", t1.EndpointAddress, tc.endpoint)
			}
			if tc.source == nil {
				if t1.SourceAddressLength != 0 {
					t.Fatalf("expected SourceAddressLength=0, got %d", t1.SourceAddressLength)
				}
			} else {
				if t1.SourceAddress == nil || t1.SourceAddress.String() != tc.source.String() {
					t.Fatalf("source=%v, want %s", t1.SourceAddress, tc.source)
				}
			}
		})
	}
}

func TestMUPRoute_T2STRoundTrip(t *testing.T) {
	rd := mustRD(t, "65000:1")
	cases := []struct {
		name     string
		family   bgp.Family
		endpoint string
		eaLen    uint8
		teid     string
		nh       string
	}{
		{"ipv4_teid32", bgp.RF_MUP_IPv4, "10.10.10.1", 64, "0.0.0.100", "10.0.0.1"},
		{"ipv4_teid10", bgp.RF_MUP_IPv4, "10.10.10.1", 42, "100.64.0.0", "10.0.0.1"},
		{"ipv6_teid32", bgp.RF_MUP_IPv6, "2001:db8::1", 160, "0.0.0.100", "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewMUPType2SessionTransformedRoute(tc.family, rd, parseAddr(tc.endpoint), tc.eaLen, parseAddr(tc.teid))
			if err != nil {
				t.Fatalf("NewMUPType2SessionTransformedRoute: %v", err)
			}
			got := roundTripMUPUpdate(t, r, parseAddr(tc.nh))
			n, ok := got.(*bgp.MUPNLRI)
			if !ok {
				t.Fatalf("recovered NLRI is %T", got)
			}
			if n.RouteType != bgp.MUP_ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED {
				t.Fatalf("route type = %d, want T2ST", n.RouteType)
			}
			t2 := n.RouteTypeData.(*bgp.MUPType2SessionTransformedRoute)
			if t2.EndpointAddress.String() != parseAddr(tc.endpoint).String() {
				t.Fatalf("endpoint=%s, want %s", t2.EndpointAddress, tc.endpoint)
			}
			if t2.EndpointAddressLength != tc.eaLen {
				t.Fatalf("eaLen=%d, want %d", t2.EndpointAddressLength, tc.eaLen)
			}
		})
	}
}

func TestMUPRoute_WithdrawRoundTrip(t *testing.T) {
	rd := mustRD(t, "65000:1")
	r, err := NewMUPInterworkSegmentDiscoveryRoute(bgp.RF_MUP_IPv4, rd, mustPrefix("10.10.10.0/24"))
	if err != nil {
		t.Fatalf("NewMUPInterworkSegmentDiscoveryRoute: %v", err)
	}
	msg, err := BuildUpdateMessage(true, PathAttrs{}, []Route{r}, EncodingOptions{})
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
	if mpu.AFI != bgp.AFI_IP || mpu.SAFI != bgp.SAFI_MUP {
		t.Fatalf("AFI/SAFI=%d/%d, want %d/%d", mpu.AFI, mpu.SAFI, bgp.AFI_IP, bgp.SAFI_MUP)
	}
	if len(mpu.Value) != 1 {
		t.Fatalf("expected 1 NLRI, got %d", len(mpu.Value))
	}
}

func TestMUPRoute_ConstructorErrors(t *testing.T) {
	rd := mustRD(t, "65000:1")
	if _, err := NewMUPInterworkSegmentDiscoveryRoute(bgp.RF_IPv4_UC, rd, mustPrefix("10.0.0.0/24")); err == nil {
		t.Fatal("expected error for non-MUP family")
	}
	if _, err := NewMUPInterworkSegmentDiscoveryRoute(bgp.RF_MUP_IPv4, nil, mustPrefix("10.0.0.0/24")); err == nil {
		t.Fatal("expected error for nil RD")
	}
	if _, err := NewMUPInterworkSegmentDiscoveryRoute(bgp.RF_MUP_IPv4, rd, mustPrefix("2001:db8::/64")); err == nil {
		t.Fatal("expected error for AFI mismatch")
	}
	if _, err := NewMUPType1SessionTransformedRoute(bgp.RF_MUP_IPv4, rd,
		mustPrefix("10.0.0.0/24"), parseAddr("::1"), 9, parseAddr("10.0.0.1"), nil); err == nil {
		t.Fatal("expected error for IPv6 TEID")
	}
	if _, err := NewMUPType2SessionTransformedRoute(bgp.RF_MUP_IPv4, rd, parseAddr("10.0.0.1"), 31, parseAddr("0.0.0.1")); err == nil {
		t.Fatal("expected error for endpointAddressLength<32 on ipv4-mup")
	}
}
