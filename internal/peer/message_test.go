package peer

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/higebu/xk6-bgp/internal/packet"
)

func TestBuildOpen_RoundTrip(t *testing.T) {
	open, err := BuildOpen(65001, 180*time.Second, netip.MustParseAddr("10.0.0.1"), packet.CapsConfig{
		Families:        []bgp.Family{bgp.RF_IPv4_UC},
		FourOctetAS:     65001,
		RouteRefresh:    true,
		ExtendedMessage: true,
		GracefulRestart: &packet.GRConfig{RestartTime: 120, Notification: true},
	})
	if err != nil {
		t.Fatalf("BuildOpen: %v", err)
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
		t.Fatalf("body type %T not BGPOpen", parsed.Body)
	}
	if po.MyAS != 65001 || po.HoldTime != 180 {
		t.Fatalf("OPEN field mismatch: AS=%d hold=%d", po.MyAS, po.HoldTime)
	}
	if got := po.ID.String(); got != "10.0.0.1" {
		t.Fatalf("router id mismatch: %s", got)
	}
}

func TestBuildOpen_4OctetAS(t *testing.T) {
	open, err := BuildOpen(1234567, 180*time.Second, netip.MustParseAddr("10.0.0.1"), packet.CapsConfig{
		Families:    []bgp.Family{bgp.RF_IPv4_UC},
		FourOctetAS: 1234567,
	})
	if err != nil {
		t.Fatalf("BuildOpen: %v", err)
	}
	po := open.Body.(*bgp.BGPOpen)
	if po.MyAS != bgp.AS_TRANS {
		t.Fatalf("expected AS_TRANS marker, got %d", po.MyAS)
	}

	// Walk capabilities to confirm 4-octet-AS carries the real ASN.
	gotAS := uint32(0)
	for _, p := range po.OptParams {
		ocp, ok := p.(*bgp.OptionParameterCapability)
		if !ok {
			continue
		}
		for _, c := range ocp.Capability {
			if four, ok := c.(*bgp.CapFourOctetASNumber); ok {
				gotAS = four.CapValue
			}
		}
	}
	if gotAS != 1234567 {
		t.Fatalf("4-octet-AS capability missing or wrong: %d", gotAS)
	}
}

func TestBuildOpen_RejectsIPv6RouterID(t *testing.T) {
	_, err := BuildOpen(65001, 180*time.Second, netip.MustParseAddr("2001:db8::1"), packet.CapsConfig{
		Families:    []bgp.Family{bgp.RF_IPv4_UC},
		FourOctetAS: 65001,
	})
	if err == nil {
		t.Fatal("expected error for IPv6 router-id")
	}
}

func TestBuildKeepaliveSerializes(t *testing.T) {
	buf, err := BuildKeepalive().Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if len(buf) != bgp.BGP_HEADER_LENGTH {
		t.Fatalf("KEEPALIVE wrong length: %d", len(buf))
	}
	parsed, err := bgp.ParseBGPMessage(buf)
	if err != nil {
		t.Fatalf("ParseBGPMessage: %v", err)
	}
	if _, ok := parsed.Body.(*bgp.BGPKeepAlive); !ok {
		t.Fatalf("body type %T not BGPKeepAlive", parsed.Body)
	}
}

func TestReadMessage_RejectsOversizeWithoutExtended(t *testing.T) {
	// Craft a synthetic header that advertises mlen=5000 (legal only
	// when RFC 8654 Extended Messages was negotiated). The body bytes
	// themselves are never read because ReadMessage must reject the
	// length first.
	var hdr [bgp.BGP_HEADER_LENGTH]byte
	for i := range 16 {
		hdr[i] = 0xff
	}
	hdr[16] = 0x13 // 5000 = 0x1388
	hdr[17] = 0x88
	hdr[18] = byte(bgp.BGP_MSG_UPDATE)
	stream := bytes.NewReader(hdr[:])

	_, _, err := ReadMessage(stream)
	if err == nil {
		t.Fatal("expected error for 5000-byte mlen without Extended Messages")
	}
}

func TestReadMessageMax_AllowsExtendedWhenBudgetIsExtended(t *testing.T) {
	// Same 5000-byte advertised length, but this time the caller is
	// the post-handshake reader that has negotiated Extended Messages.
	// ReadMessageMax must accept the header and then fail attempting
	// to read the body (the stream is short by design).
	var hdr [bgp.BGP_HEADER_LENGTH]byte
	for i := range 16 {
		hdr[i] = 0xff
	}
	hdr[16] = 0x13
	hdr[17] = 0x88
	hdr[18] = byte(bgp.BGP_MSG_UPDATE)
	stream := bytes.NewReader(hdr[:])

	_, _, _, err := ReadMessageMax(stream, packet.BGPExtendedMaxMessageLength)
	if err == nil {
		t.Fatal("expected EOF-style error while reading body, got nil")
	}
	// The error must NOT be the "exceeds max" length-check error.
	if msg := err.Error(); msg == "BGP message length 5000 exceeds max 4096" {
		t.Fatalf("unexpected length-cap error in extended mode: %v", err)
	}
}

func TestReadMessage_OneByOne(t *testing.T) {
	open, err := BuildOpen(65001, 180*time.Second, netip.MustParseAddr("10.0.0.1"), packet.CapsConfig{
		Families:    []bgp.Family{bgp.RF_IPv4_UC},
		FourOctetAS: 65001,
	})
	if err != nil {
		t.Fatalf("BuildOpen: %v", err)
	}
	kbuf, _ := BuildKeepalive().Serialize()
	obuf, _ := open.Serialize()
	stream := bytes.NewReader(append(obuf, kbuf...))

	_, m1, err := ReadMessage(stream)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	if _, ok := m1.Body.(*bgp.BGPOpen); !ok {
		t.Fatalf("first message not OPEN, got %T", m1.Body)
	}
	_, m2, err := ReadMessage(stream)
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if _, ok := m2.Body.(*bgp.BGPKeepAlive); !ok {
		t.Fatalf("second message not KEEPALIVE, got %T", m2.Body)
	}
}
