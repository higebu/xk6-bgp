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
