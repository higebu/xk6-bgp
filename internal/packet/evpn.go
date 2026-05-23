package packet

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// EVPN route types we support. RFC 7432 section 7 defines the wire
// format; RFC 9136 redefines Type 5 (IP Prefix). xk6-bgp leaves the
// label and tunnel-attribute semantics to the caller — VXLAN / MPLS /
// SRv6 mapping (RFC 8365 etc.) is just a matter of which value the
// caller stuffs into the label and which path attributes they attach.
const (
	EVPNTypeMacIP    = "mac-ip"    // RFC 7432 section 7.2
	EVPNTypeIMET     = "imet"      // RFC 7432 section 7.3
	EVPNTypeIPPrefix = "ip-prefix" // RFC 9136 section 3
)

// EVPNRoute is the Route implementation for the L2VPN-EVPN SAFI
// (AFI=25, SAFI=70). All four supported EVPN route types share this
// concrete type; per-type validation lives in the constructors.
type EVPNRoute struct {
	nlri    *bgp.EVPNNLRI
	wireLen int
}

func (r EVPNRoute) Family() bgp.Family { return bgp.RF_EVPN }
func (r EVPNRoute) NLRI() bgp.NLRI     { return r.nlri }
func (r EVPNRoute) WireLen() int       { return r.wireLen }

// Key returns the canonical receive-side key (gobgp NLRI.String()).
// EVPN's String() form embeds the route type, so all three Type-2/3/5
// shapes coexist in the same observed-set without collision.
func (r EVPNRoute) Key() string { return r.nlri.String() }

// NewEVPNMacIPRoute builds an EVPN Type 2 (MAC/IP Advertisement) NLRI
// per RFC 7432 section 7.2. ip may be the zero Addr to emit a MAC-only
// advertisement (IPAddressLength=0 on the wire). labels is the 1-or-2
// 24-bit label stack; for VXLAN deployments the caller sets labels to
// the VNI per RFC 8365 section 5.
func NewEVPNMacIPRoute(rd bgp.RouteDistinguisherInterface, esi bgp.EthernetSegmentIdentifier, ethTag uint32, mac net.HardwareAddr, ip netip.Addr, labels []uint32) (EVPNRoute, error) {
	if rd == nil {
		return EVPNRoute{}, fmt.Errorf("evpn mac-ip: rd is required")
	}
	if len(mac) != 6 {
		return EVPNRoute{}, fmt.Errorf("evpn mac-ip: mac must be a 6-byte EUI-48 (got %d bytes)", len(mac))
	}
	if len(labels) == 0 || len(labels) > 2 {
		return EVPNRoute{}, fmt.Errorf("evpn mac-ip: labels must contain 1 or 2 entries (got %d)", len(labels))
	}
	var ipLen uint8
	if ip.IsValid() {
		ip = ip.Unmap()
		ipLen = uint8(ip.BitLen()) // #nosec G115 -- netip.Addr.BitLen() returns 0, 32, or 128
		if ipLen != 32 && ipLen != 128 {
			return EVPNRoute{}, fmt.Errorf("evpn mac-ip: ip must be IPv4 or IPv6 (got %s)", ip)
		}
	}
	macCopy := make(net.HardwareAddr, 6)
	copy(macCopy, mac)
	nlri := bgp.NewEVPNNLRI(bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT, &bgp.EVPNMacIPAdvertisementRoute{
		RD:               rd,
		ESI:              esi,
		ETag:             ethTag,
		MacAddressLength: 48,
		MacAddress:       macCopy,
		IPAddressLength:  ipLen,
		IPAddress:        ip,
		Labels:           append([]uint32(nil), labels...),
	})
	return EVPNRoute{nlri: nlri, wireLen: nlri.Len()}, nil
}

// NewEVPNIMETRoute builds an EVPN Type 3 (Inclusive Multicast Ethernet
// Tag) NLRI per RFC 7432 section 7.3. The originating-router IP must
// be IPv4 or IPv6; gobgp encodes its length on the wire accordingly.
// Type-3 routes are normally paired with a PMSI Tunnel path attribute
// (see PathAttrs.PMSITunnel) — xk6-bgp leaves that as an independent
// caller choice.
func NewEVPNIMETRoute(rd bgp.RouteDistinguisherInterface, ethTag uint32, originIP netip.Addr) (EVPNRoute, error) {
	if rd == nil {
		return EVPNRoute{}, fmt.Errorf("evpn imet: rd is required")
	}
	if !originIP.IsValid() {
		return EVPNRoute{}, fmt.Errorf("evpn imet: originIp is required")
	}
	nlri, err := bgp.NewEVPNMulticastEthernetTagRoute(rd, ethTag, originIP)
	if err != nil {
		return EVPNRoute{}, fmt.Errorf("evpn imet: %w", err)
	}
	return EVPNRoute{nlri: nlri, wireLen: nlri.Len()}, nil
}

// NewEVPNIPPrefixRoute builds an EVPN Type 5 (IP Prefix) NLRI per
// RFC 9136 section 3. gateway may be the zero Addr; gobgp serializes
// it as the family-appropriate unspecified address (RFC 9136 section
// 3.1: zero GW IP when the overlay index is signalled via the
// Router's MAC ext-community instead). label is the 24-bit value the
// receiver MUST use for the data-plane lookup; for VXLAN the caller
// sets it to the L3 VNI per RFC 8365.
func NewEVPNIPPrefixRoute(rd bgp.RouteDistinguisherInterface, esi bgp.EthernetSegmentIdentifier, ethTag uint32, prefix netip.Prefix, gateway netip.Addr, label uint32) (EVPNRoute, error) {
	if rd == nil {
		return EVPNRoute{}, fmt.Errorf("evpn ip-prefix: rd is required")
	}
	if !prefix.IsValid() {
		return EVPNRoute{}, fmt.Errorf("evpn ip-prefix: invalid prefix")
	}
	addr := prefix.Addr().Unmap()
	wantV6 := addr.Is6()
	gw := gateway
	if !gw.IsValid() {
		if wantV6 {
			gw = netip.IPv6Unspecified()
		} else {
			gw = netip.IPv4Unspecified()
		}
	} else {
		gw = gw.Unmap()
		if gw.Is6() != wantV6 {
			return EVPNRoute{}, fmt.Errorf("evpn ip-prefix: gateway %s does not match prefix family %s", gw, prefix)
		}
	}
	prefixLen := uint8(prefix.Bits()) // #nosec G115 -- netip.Prefix.Bits() returns 0..128 (validated by IsValid above)
	nlri, err := bgp.NewEVPNIPPrefixRoute(rd, esi, ethTag, prefixLen, addr, gw, label)
	if err != nil {
		return EVPNRoute{}, fmt.Errorf("evpn ip-prefix: %w", err)
	}
	return EVPNRoute{nlri: nlri, wireLen: nlri.Len()}, nil
}

// ParseESI converts a string into an EthernetSegmentIdentifier. The
// accepted shapes mirror gobgp's `ParseEthernetSegmentIdentifier`:
//
//	""              → all-zero (single-homed)
//	"single-homed"  → all-zero
//	"lacp aa:bb:cc:dd:ee:ff 100"
//	"mac aa:bb:cc:dd:ee:ff 1234"
//	"routerid 10.0.0.1 1"
//	"as 65000 1"
//	"arbitrary 11:22:33:44:55:66:77:88:99"
//
// Single-homed deployments leave ESI empty; multihoming uses the
// type-specific forms above.
func ParseESI(s string) (bgp.EthernetSegmentIdentifier, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "single-homed" {
		return bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY, Value: make([]byte, 9)}, nil
	}
	return bgp.ParseEthernetSegmentIdentifier(strings.Fields(s))
}
