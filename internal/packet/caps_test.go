package packet

import (
	"testing"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func TestBuildCapabilities_RoundTrip(t *testing.T) {
	caps, err := BuildCapabilities(CapsConfig{
		Families:        []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_MUP_IPv4},
		FourOctetAS:     65001,
		RouteRefresh:    true,
		ExtendedMessage: true,
		GracefulRestart: &GRConfig{RestartTime: 120, Notification: true},
	})
	if err != nil {
		t.Fatalf("BuildCapabilities: %v", err)
	}
	if len(caps) == 0 {
		t.Fatal("expected at least one capability")
	}

	// Wrap into an OPEN message and round-trip through gobgp's parser.
	open, err := bgp.NewBGPOpenMessage(65001, 180, parseAddr("10.0.0.1"), []bgp.OptionParameterInterface{
		bgp.NewOptionParameterCapability(caps),
	})
	if err != nil {
		t.Fatalf("NewBGPOpenMessage: %v", err)
	}
	buf, err := open.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	parsed, err := bgp.ParseBGPMessage(buf)
	if err != nil {
		t.Fatalf("ParseBGPMessage: %v", err)
	}
	po, ok := parsed.Body.(*bgp.BGPOpen)
	if !ok {
		t.Fatalf("parsed body is not BGPOpen, got %T", parsed.Body)
	}
	if po.MyAS != 65001 {
		t.Fatalf("MyAS mismatch: %d", po.MyAS)
	}

	// Walk capabilities, ensure the expected codes are present.
	want := map[bgp.BGPCapabilityCode]bool{
		bgp.BGP_CAP_MULTIPROTOCOL:        false,
		bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER: false,
		bgp.BGP_CAP_ROUTE_REFRESH:        false,
		bgp.BGP_CAP_GRACEFUL_RESTART:     false,
		BGPCapExtendedMessage:            false,
	}
	mpFamilies := map[bgp.Family]bool{}

	for _, op := range po.OptParams {
		ocp, ok := op.(*bgp.OptionParameterCapability)
		if !ok {
			continue
		}
		for _, c := range ocp.Capability {
			if _, ok := want[c.Code()]; ok {
				want[c.Code()] = true
			}
			if mp, ok := c.(*bgp.CapMultiProtocol); ok {
				mpFamilies[mp.CapValue] = true
			}
		}
	}
	for code, seen := range want {
		if !seen {
			t.Errorf("expected capability code %d, not found in re-parsed OPEN", code)
		}
	}
	for _, f := range []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_MUP_IPv4} {
		if !mpFamilies[f] {
			t.Errorf("expected MP capability for family %s, not found", f)
		}
	}
}

// TestBuildCapabilities_AddPathRoundTrip round-trips an OPEN carrying
// the RFC 7911 ADD-PATH capability and checks the per-family tuples
// survive gobgp's parser.
func TestBuildCapabilities_AddPathRoundTrip(t *testing.T) {
	caps, err := BuildCapabilities(CapsConfig{
		Families:    []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC},
		FourOctetAS: 65001,
		AddPath: map[bgp.Family]bgp.BGPAddPathMode{
			bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_BOTH,
			bgp.RF_IPv6_UC: bgp.BGP_ADD_PATH_SEND,
		},
	})
	if err != nil {
		t.Fatalf("BuildCapabilities: %v", err)
	}

	open, err := bgp.NewBGPOpenMessage(65001, 180, parseAddr("10.0.0.1"), []bgp.OptionParameterInterface{
		bgp.NewOptionParameterCapability(caps),
	})
	if err != nil {
		t.Fatalf("NewBGPOpenMessage: %v", err)
	}
	buf, err := open.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	parsed, err := bgp.ParseBGPMessage(buf)
	if err != nil {
		t.Fatalf("ParseBGPMessage: %v", err)
	}
	po := parsed.Body.(*bgp.BGPOpen)

	got := map[bgp.Family]bgp.BGPAddPathMode{}
	for _, op := range po.OptParams {
		ocp, ok := op.(*bgp.OptionParameterCapability)
		if !ok {
			continue
		}
		for _, c := range ocp.Capability {
			if ap, ok := c.(*bgp.CapAddPath); ok {
				for _, tp := range ap.Tuples {
					got[tp.Family] |= tp.Mode
				}
			}
		}
	}
	if got[bgp.RF_IPv4_UC] != bgp.BGP_ADD_PATH_BOTH {
		t.Errorf("ipv4-unicast mode = %v, want both", got[bgp.RF_IPv4_UC])
	}
	if got[bgp.RF_IPv6_UC] != bgp.BGP_ADD_PATH_SEND {
		t.Errorf("ipv6-unicast mode = %v, want send", got[bgp.RF_IPv6_UC])
	}
	if len(got) != 2 {
		t.Errorf("ADD-PATH tuples for %d families, want 2", len(got))
	}
}

func TestBuildCapabilities_AddPathErrors(t *testing.T) {
	if _, err := BuildCapabilities(CapsConfig{
		Families:    []bgp.Family{bgp.RF_IPv4_UC},
		FourOctetAS: 65001,
		AddPath:     map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv6_UC: bgp.BGP_ADD_PATH_BOTH},
	}); err == nil {
		t.Error("expected error for ADD-PATH family missing from Families")
	}
	if _, err := BuildCapabilities(CapsConfig{
		Families:    []bgp.Family{bgp.RF_IPv4_UC},
		FourOctetAS: 65001,
		AddPath:     map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: 4},
	}); err == nil {
		t.Error("expected error for Send/Receive value outside 1-3")
	}
}

func TestResolveAddPathMode(t *testing.T) {
	for name, want := range map[string]bgp.BGPAddPathMode{
		"receive": bgp.BGP_ADD_PATH_RECEIVE,
		"send":    bgp.BGP_ADD_PATH_SEND,
		"both":    bgp.BGP_ADD_PATH_BOTH,
		"Both":    bgp.BGP_ADD_PATH_BOTH,
	} {
		if got, err := ResolveAddPathMode(name); err != nil || got != want {
			t.Errorf("%q: got %v %v, want %v", name, got, err, want)
		}
	}
	if _, err := ResolveAddPathMode("nope"); err == nil {
		t.Error("expected error for unknown mode")
	}
}

func TestResolveFamily(t *testing.T) {
	if f, err := ResolveFamily("ipv4-unicast"); err != nil || f != bgp.RF_IPv4_UC {
		t.Errorf("ipv4-unicast: got %v %v", f, err)
	}
	if f, err := ResolveFamily("ipv4-mup"); err != nil || f != bgp.RF_MUP_IPv4 {
		t.Errorf("ipv4-mup: got %v %v", f, err)
	}
	if _, err := ResolveFamily("nope"); err == nil {
		t.Error("expected error for unknown family")
	}
}
