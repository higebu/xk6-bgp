package packet

import (
	"net"
	"net/netip"
	"testing"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// roundTripEVPNUpdate builds an UPDATE with one EVPN route plus the
// supplied path attrs, serializes it, parses it back, and returns the
// recovered NLRI alongside the ext-comm and PMSI-Tunnel attrs (each
// may be nil depending on the input).
func roundTripEVPNUpdate(t *testing.T, route Route, attrs PathAttrs) (bgp.NLRI, *bgp.PathAttributeExtendedCommunities, *bgp.PathAttributePmsiTunnel) {
	t.Helper()
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
	upd := parsed.Body.(*bgp.BGPUpdate)
	var mpr *bgp.PathAttributeMpReachNLRI
	var extc *bgp.PathAttributeExtendedCommunities
	var pmsi *bgp.PathAttributePmsiTunnel
	for _, a := range upd.PathAttributes {
		switch v := a.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			mpr = v
		case *bgp.PathAttributeExtendedCommunities:
			extc = v
		case *bgp.PathAttributePmsiTunnel:
			pmsi = v
		}
	}
	if mpr == nil {
		t.Fatal("MP_REACH_NLRI not found")
	}
	if mpr.AFI != bgp.AFI_L2VPN || mpr.SAFI != bgp.SAFI_EVPN {
		t.Fatalf("AFI/SAFI=%d/%d, want %d/%d", mpr.AFI, mpr.SAFI, bgp.AFI_L2VPN, bgp.SAFI_EVPN)
	}
	if len(mpr.Value) != 1 {
		t.Fatalf("expected 1 NLRI, got %d", len(mpr.Value))
	}
	return mpr.Value[0].NLRI, extc, pmsi
}

func TestEVPNMacIPRoute_RoundTrip(t *testing.T) {
	rd := mustRD(t, "65000:1")
	mac, err := net.ParseMAC("aa:bb:cc:dd:ee:01")
	if err != nil {
		t.Fatalf("ParseMAC: %v", err)
	}
	esi, err := ParseESI("single-homed")
	if err != nil {
		t.Fatalf("ParseESI: %v", err)
	}
	r, err := NewEVPNMacIPRoute(rd, esi, 100, mac, netip.MustParseAddr("10.1.1.1"), []uint32{10100})
	if err != nil {
		t.Fatalf("NewEVPNMacIPRoute: %v", err)
	}
	attrs := PathAttrs{NextHop: parseAddr("10.0.0.1"), LocalAS: 65001}
	got, _, _ := roundTripEVPNUpdate(t, r, attrs)
	n, ok := got.(*bgp.EVPNNLRI)
	if !ok {
		t.Fatalf("recovered NLRI is %T", got)
	}
	if n.RouteType != bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT {
		t.Fatalf("route type=%d, want %d", n.RouteType, bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT)
	}
	route := n.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
	if route.RD.String() != "65000:1" {
		t.Fatalf("rd=%s, want 65000:1", route.RD)
	}
	if route.ETag != 100 {
		t.Fatalf("etag=%d, want 100", route.ETag)
	}
	if route.MacAddress.String() != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("mac=%s", route.MacAddress)
	}
	if route.IPAddress.String() != "10.1.1.1" {
		t.Fatalf("ip=%s, want 10.1.1.1", route.IPAddress)
	}
	if len(route.Labels) != 1 || route.Labels[0] != 10100 {
		t.Fatalf("labels=%v, want [10100]", route.Labels)
	}
}

func TestEVPNMacIPRoute_MacOnly(t *testing.T) {
	rd := mustRD(t, "65000:1")
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	esi, _ := ParseESI("")
	r, err := NewEVPNMacIPRoute(rd, esi, 0, mac, netip.Addr{}, []uint32{10100})
	if err != nil {
		t.Fatalf("NewEVPNMacIPRoute: %v", err)
	}
	attrs := PathAttrs{NextHop: parseAddr("10.0.0.1"), LocalAS: 65001}
	got, _, _ := roundTripEVPNUpdate(t, r, attrs)
	route := got.(*bgp.EVPNNLRI).RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
	if route.IPAddressLength != 0 {
		t.Fatalf("ipAddressLength=%d, want 0 (mac-only)", route.IPAddressLength)
	}
}

func TestEVPNMacIPRoute_TwoLabels(t *testing.T) {
	rd := mustRD(t, "65000:1")
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:03")
	esi, _ := ParseESI("")
	r, err := NewEVPNMacIPRoute(rd, esi, 0, mac, netip.MustParseAddr("2001:db8::1"), []uint32{10100, 20200})
	if err != nil {
		t.Fatalf("NewEVPNMacIPRoute: %v", err)
	}
	attrs := PathAttrs{NextHop: parseAddr("2001:db8::ff"), LocalAS: 65001}
	got, _, _ := roundTripEVPNUpdate(t, r, attrs)
	route := got.(*bgp.EVPNNLRI).RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
	if route.IPAddressLength != 128 {
		t.Fatalf("ipAddressLength=%d, want 128", route.IPAddressLength)
	}
	if len(route.Labels) != 2 || route.Labels[0] != 10100 || route.Labels[1] != 20200 {
		t.Fatalf("labels=%v, want [10100 20200]", route.Labels)
	}
}

func TestEVPNIMETRoute_RoundTripWithPMSI(t *testing.T) {
	rd := mustRD(t, "65000:1")
	r, err := NewEVPNIMETRoute(rd, 200, netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatalf("NewEVPNIMETRoute: %v", err)
	}
	attrs := PathAttrs{
		NextHop: parseAddr("10.0.0.1"),
		LocalAS: 65001,
		PMSITunnel: &PMSITunnelConfig{
			Tunnel:   uint8(bgp.PMSI_TUNNEL_TYPE_INGRESS_REPL),
			Label:    10100,
			Endpoint: netip.MustParseAddr("10.0.0.1"),
		},
	}
	got, _, pmsi := roundTripEVPNUpdate(t, r, attrs)
	n := got.(*bgp.EVPNNLRI)
	if n.RouteType != bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG {
		t.Fatalf("route type=%d, want IMET (%d)", n.RouteType, bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG)
	}
	route := n.RouteTypeData.(*bgp.EVPNMulticastEthernetTagRoute)
	if route.ETag != 200 {
		t.Fatalf("etag=%d, want 200", route.ETag)
	}
	if route.IPAddress.String() != "10.0.0.1" {
		t.Fatalf("originIp=%s, want 10.0.0.1", route.IPAddress)
	}
	if pmsi == nil {
		t.Fatal("PMSI Tunnel attr not found")
	}
	if pmsi.TunnelType != bgp.PMSI_TUNNEL_TYPE_INGRESS_REPL {
		t.Fatalf("PMSI tunnel type=%d, want INGRESS_REPL (%d)", pmsi.TunnelType, bgp.PMSI_TUNNEL_TYPE_INGRESS_REPL)
	}
	if pmsi.Label != 10100 {
		t.Fatalf("PMSI label=%d, want 10100", pmsi.Label)
	}
	ir, ok := pmsi.TunnelID.(*bgp.IngressReplTunnelID)
	if !ok {
		t.Fatalf("PMSI tunnel ID type=%T", pmsi.TunnelID)
	}
	if ir.Value.String() != "10.0.0.1" {
		t.Fatalf("PMSI endpoint=%s, want 10.0.0.1", ir.Value)
	}
}

func TestEVPNIPPrefixRoute_RoundTrip(t *testing.T) {
	rd := mustRD(t, "65000:1")
	esi, _ := ParseESI("")
	r, err := NewEVPNIPPrefixRoute(rd, esi, 300, mustPrefix("10.1.0.0/24"), netip.Addr{}, 50100)
	if err != nil {
		t.Fatalf("NewEVPNIPPrefixRoute: %v", err)
	}
	rmac, err := net.ParseMAC("aa:bb:cc:dd:ee:99")
	if err != nil {
		t.Fatalf("ParseMAC: %v", err)
	}
	attrs := PathAttrs{
		NextHop:        parseAddr("10.0.0.1"),
		LocalAS:        65001,
		ExtCommunities: []bgp.ExtendedCommunityInterface{bgp.NewRoutersMacExtended(rmac.String())},
	}
	got, extc, _ := roundTripEVPNUpdate(t, r, attrs)
	n := got.(*bgp.EVPNNLRI)
	if n.RouteType != bgp.EVPN_IP_PREFIX {
		t.Fatalf("route type=%d, want IP_PREFIX (%d)", n.RouteType, bgp.EVPN_IP_PREFIX)
	}
	route := n.RouteTypeData.(*bgp.EVPNIPPrefixRoute)
	if route.IPPrefix.String() != "10.1.0.0" || route.IPPrefixLength != 24 {
		t.Fatalf("prefix=%s/%d, want 10.1.0.0/24", route.IPPrefix, route.IPPrefixLength)
	}
	if route.GWIPAddress.String() != "0.0.0.0" {
		t.Fatalf("gw=%s, want 0.0.0.0 (default)", route.GWIPAddress)
	}
	if route.Label != 50100 {
		t.Fatalf("label=%d, want 50100", route.Label)
	}
	if extc == nil || len(extc.Value) != 1 {
		t.Fatalf("ext-comm missing or wrong shape: %+v", extc)
	}
	rm, ok := extc.Value[0].(*bgp.RouterMacExtended)
	if !ok {
		t.Fatalf("ext-comm[0] is %T", extc.Value[0])
	}
	if rm.Mac.String() != "aa:bb:cc:dd:ee:99" {
		t.Fatalf("router-mac=%s, want aa:bb:cc:dd:ee:99", rm.Mac)
	}
}

func TestEVPNRoute_ConstructorErrors(t *testing.T) {
	rd := mustRD(t, "65000:1")
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	esi, _ := ParseESI("")
	if _, err := NewEVPNMacIPRoute(nil, esi, 0, mac, netip.MustParseAddr("10.0.0.1"), []uint32{10}); err == nil {
		t.Fatal("expected error for nil RD")
	}
	if _, err := NewEVPNMacIPRoute(rd, esi, 0, net.HardwareAddr{0xaa}, netip.MustParseAddr("10.0.0.1"), []uint32{10}); err == nil {
		t.Fatal("expected error for short mac")
	}
	if _, err := NewEVPNMacIPRoute(rd, esi, 0, mac, netip.MustParseAddr("10.0.0.1"), nil); err == nil {
		t.Fatal("expected error for empty labels")
	}
	if _, err := NewEVPNMacIPRoute(rd, esi, 0, mac, netip.MustParseAddr("10.0.0.1"), []uint32{1, 2, 3}); err == nil {
		t.Fatal("expected error for >2 labels")
	}
	if _, err := NewEVPNIPPrefixRoute(rd, esi, 0, mustPrefix("10.0.0.0/24"), netip.MustParseAddr("2001:db8::1"), 0); err == nil {
		t.Fatal("expected error for mismatched gateway family")
	}
}

func TestParseESI(t *testing.T) {
	tests := []struct {
		in   string
		typ  bgp.ESIType
		want []byte
	}{
		{"", bgp.ESI_ARBITRARY, make([]byte, 9)},
		{"single-homed", bgp.ESI_ARBITRARY, make([]byte, 9)},
	}
	for _, tc := range tests {
		esi, err := ParseESI(tc.in)
		if err != nil {
			t.Fatalf("ParseESI(%q): %v", tc.in, err)
		}
		if esi.Type != tc.typ {
			t.Fatalf("ParseESI(%q) type=%d, want %d", tc.in, esi.Type, tc.typ)
		}
		buf, err := esi.Serialize()
		if err != nil {
			t.Fatalf("Serialize: %v", err)
		}
		for i := 1; i < 10; i++ {
			if buf[i] != 0 {
				t.Fatalf("ParseESI(%q) wire byte[%d]=%x, want 0", tc.in, i, buf[i])
			}
		}
	}
}
