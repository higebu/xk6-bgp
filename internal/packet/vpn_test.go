package packet

import (
	"net/netip"
	"testing"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// roundTripSRv6VPNUpdate builds an UPDATE with one VPNIPRoute plus an
// SRv6 L3 Service Prefix-SID attribute, serializes it, parses it back,
// and returns the recovered NLRI, ext-comm, and Prefix-SID attributes.
func roundTripSRv6VPNUpdate(t *testing.T, route Route, attrs PathAttrs) (bgp.NLRI, *bgp.PathAttributeExtendedCommunities, *bgp.PathAttributePrefixSID) {
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
	upd, ok := parsed.Body.(*bgp.BGPUpdate)
	if !ok {
		t.Fatalf("body is %T not BGPUpdate", parsed.Body)
	}
	var mpr *bgp.PathAttributeMpReachNLRI
	var extc *bgp.PathAttributeExtendedCommunities
	var psid *bgp.PathAttributePrefixSID
	for _, a := range upd.PathAttributes {
		switch v := a.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			mpr = v
		case *bgp.PathAttributeExtendedCommunities:
			extc = v
		case *bgp.PathAttributePrefixSID:
			psid = v
		}
	}
	if mpr == nil {
		t.Fatal("MP_REACH_NLRI not found")
	}
	if mpr.SAFI != bgp.SAFI_MPLS_VPN {
		t.Fatalf("expected SAFI_MPLS_VPN, got %d", mpr.SAFI)
	}
	if len(mpr.Value) != 1 {
		t.Fatalf("expected 1 NLRI, got %d", len(mpr.Value))
	}
	return mpr.Value[0].NLRI, extc, psid
}

func TestVPNIPRoute_SRv6IPv4AdvertiseRoundTrip(t *testing.T) {
	rd := mustRD(t, "65000:1")
	rt, err := bgp.ParseRouteTarget("65000:100")
	if err != nil {
		t.Fatalf("ParseRouteTarget: %v", err)
	}
	r, err := NewVPNIPRoute(bgp.RF_IPv4_VPN, rd, mustPrefix("10.10.10.0/24"))
	if err != nil {
		t.Fatalf("NewVPNIPRoute: %v", err)
	}
	attrs := PathAttrs{
		NextHop:        parseAddr("10.0.0.1"),
		LocalAS:        65001,
		ExtCommunities: []bgp.ExtendedCommunityInterface{rt},
		SRv6L3Service: &SRv6L3ServiceConfig{
			SID:                netip.MustParseAddr("fc00:0:1::"),
			EndpointBehavior:   bgp.END_DT4,
			LocatorBlockLength: 40, LocatorNodeLength: 24, FunctionLength: 16,
		},
	}
	got, extc, psid := roundTripSRv6VPNUpdate(t, r, attrs)
	n, ok := got.(*bgp.LabeledVPNIPAddrPrefix)
	if !ok {
		t.Fatalf("recovered NLRI is %T", got)
	}
	if n.RD.String() != "65000:1" {
		t.Fatalf("rd=%s, want 65000:1", n.RD)
	}
	if n.Prefix.String() != "10.10.10.0/24" {
		t.Fatalf("prefix=%s, want 10.10.10.0/24", n.Prefix)
	}
	if len(n.Labels.Labels) != 1 || n.Labels.Labels[0] != 0 {
		t.Fatalf("labels=%v, want [0] (placeholder per RFC 9252 §4)", n.Labels.Labels)
	}
	if extc == nil || len(extc.Value) != 1 || extc.Value[0].String() != "65000:100" {
		t.Fatalf("ext-comm mismatch: %+v", extc)
	}
	if psid == nil {
		t.Fatal("Prefix-SID attribute not found")
	}
	if len(psid.TLVs) != 1 {
		t.Fatalf("expected 1 TLV, got %d", len(psid.TLVs))
	}
	stlv, ok := psid.TLVs[0].(*bgp.SRv6ServiceTLV)
	if !ok {
		t.Fatalf("TLV[0] is %T", psid.TLVs[0])
	}
	if stlv.Type != bgp.TLVTypeSRv6L3Service {
		t.Fatalf("TLV type=%d, want SRv6L3Service (%d)", stlv.Type, bgp.TLVTypeSRv6L3Service)
	}
	if len(stlv.SubTLVs) != 1 {
		t.Fatalf("expected 1 sub-TLV, got %d", len(stlv.SubTLVs))
	}
	info := stlv.SubTLVs[0].(*bgp.SRv6InformationSubTLV)
	if info.EndpointBehavior != uint16(bgp.END_DT4) {
		t.Fatalf("behavior=%d, want END_DT4 (%d)", info.EndpointBehavior, bgp.END_DT4)
	}
	gotSID, _ := netip.AddrFromSlice(info.SID)
	if gotSID.String() != "fc00:0:1::" {
		t.Fatalf("sid=%s, want fc00:0:1::", gotSID)
	}
	if r.Key() != "65000:1:10.10.10.0/24" {
		t.Fatalf("Key=%s, want 65000:1:10.10.10.0/24", r.Key())
	}
}

func TestVPNIPRoute_SRv6IPv6AdvertiseRoundTrip(t *testing.T) {
	rd := mustRD(t, "65000:1")
	r, err := NewVPNIPRoute(bgp.RF_IPv6_VPN, rd, mustPrefix("2001:db8:1::/48"))
	if err != nil {
		t.Fatalf("NewVPNIPRoute: %v", err)
	}
	attrs := PathAttrs{
		NextHop: parseAddr("2001:db8::1"),
		LocalAS: 65001,
		SRv6L3Service: &SRv6L3ServiceConfig{
			SID:                netip.MustParseAddr("fc00:0:1::"),
			EndpointBehavior:   bgp.END_DT6,
			LocatorBlockLength: 40, LocatorNodeLength: 24, FunctionLength: 16,
		},
	}
	got, _, psid := roundTripSRv6VPNUpdate(t, r, attrs)
	n, ok := got.(*bgp.LabeledVPNIPAddrPrefix)
	if !ok {
		t.Fatalf("recovered NLRI is %T", got)
	}
	if n.Prefix.String() != "2001:db8:1::/48" {
		t.Fatalf("prefix=%s, want 2001:db8:1::/48", n.Prefix)
	}
	if psid == nil {
		t.Fatal("Prefix-SID attribute not found")
	}
	info := psid.TLVs[0].(*bgp.SRv6ServiceTLV).SubTLVs[0].(*bgp.SRv6InformationSubTLV)
	if info.EndpointBehavior != uint16(bgp.END_DT6) {
		t.Fatalf("behavior=%d, want END_DT6 (%d)", info.EndpointBehavior, bgp.END_DT6)
	}
	if r.Key() != "65000:1:2001:db8:1::/48" {
		t.Fatalf("Key=%s, want 65000:1:2001:db8:1::/48", r.Key())
	}
}

func TestVPNIPRoute_WithdrawRoundTrip(t *testing.T) {
	rd := mustRD(t, "65000:1")
	r, err := NewVPNIPRoute(bgp.RF_IPv4_VPN, rd, mustPrefix("10.10.10.0/24"))
	if err != nil {
		t.Fatalf("NewVPNIPRoute: %v", err)
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
	if mpu.AFI != bgp.AFI_IP || mpu.SAFI != bgp.SAFI_MPLS_VPN {
		t.Fatalf("AFI/SAFI=%d/%d, want %d/%d", mpu.AFI, mpu.SAFI, bgp.AFI_IP, bgp.SAFI_MPLS_VPN)
	}
	if len(mpu.Value) != 1 {
		t.Fatalf("expected 1 NLRI, got %d", len(mpu.Value))
	}
}

func TestVPNIPRoute_ConstructorErrors(t *testing.T) {
	rd := mustRD(t, "65000:1")
	if _, err := NewVPNIPRoute(bgp.RF_IPv4_UC, rd, mustPrefix("10.0.0.0/24")); err == nil {
		t.Fatal("expected error for non-VPN family")
	}
	if _, err := NewVPNIPRoute(bgp.RF_IPv4_VPN, nil, mustPrefix("10.0.0.0/24")); err == nil {
		t.Fatal("expected error for nil RD")
	}
	if _, err := NewVPNIPRoute(bgp.RF_IPv4_VPN, rd, mustPrefix("2001:db8::/64")); err == nil {
		t.Fatal("expected error for IPv4-VPN with IPv6 prefix")
	}
	if _, err := NewVPNIPRoute(bgp.RF_IPv6_VPN, rd, mustPrefix("10.0.0.0/24")); err == nil {
		t.Fatal("expected error for IPv6-VPN with IPv4 prefix")
	}
}

func TestSRv6L3ServiceConfig_RejectsIPv4SID(t *testing.T) {
	cfg := &SRv6L3ServiceConfig{
		SID:              netip.MustParseAddr("10.0.0.1"),
		EndpointBehavior: bgp.END_DT4,
	}
	if _, err := cfg.buildAttr(); err == nil {
		t.Fatal("expected error for IPv4 SID")
	}
}
