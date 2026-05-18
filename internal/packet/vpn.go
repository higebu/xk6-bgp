package packet

import (
	"fmt"
	"net/netip"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// VPNIPRoute is the Route implementation for the BGP IP-VPN NLRI
// (LabeledVPNIPAddrPrefix; SAFI=128) used by both classical MPLS L3VPN
// (RFC 4364) and SRv6 L3VPN (RFC 9252). xk6-bgp targets SRv6, so the
// MPLS Label field is set to a placeholder 0 — RFC 9252 section 4
// allows this when the SRv6 SID is signalled in full via the
// Prefix-SID attribute (i.e., no transposition; Transposition Length
// must also be 0 in the SID Structure Sub-Sub-TLV).
type VPNIPRoute struct {
	family bgp.Family
	nlri   *bgp.LabeledVPNIPAddrPrefix
	// wireLen caches LabeledVPNIPAddrPrefix.Len() so ChunkRoutes does
	// not call back into gobgp per route.
	wireLen int
}

// NewVPNIPRoute constructs a VPNIPRoute for the given family, RD, and
// customer prefix. family must be RF_IPv4_VPN or RF_IPv6_VPN and the
// prefix's address family must match.
func NewVPNIPRoute(family bgp.Family, rd bgp.RouteDistinguisherInterface, prefix netip.Prefix) (VPNIPRoute, error) {
	if family.Safi() != bgp.SAFI_MPLS_VPN {
		return VPNIPRoute{}, fmt.Errorf("vpn-ip: family %s is not l3vpn", family)
	}
	switch family.Afi() {
	case bgp.AFI_IP, bgp.AFI_IP6:
	default:
		return VPNIPRoute{}, fmt.Errorf("vpn-ip: family %s AFI is not IPv4 or IPv6", family)
	}
	if rd == nil {
		return VPNIPRoute{}, fmt.Errorf("vpn-ip: rd is required")
	}
	if !prefix.IsValid() {
		return VPNIPRoute{}, fmt.Errorf("vpn-ip: invalid prefix")
	}
	wantV6 := family.Afi() == bgp.AFI_IP6
	gotV6 := prefix.Addr().Is6() && !prefix.Addr().Is4In6()
	if wantV6 != gotV6 {
		return VPNIPRoute{}, fmt.Errorf("vpn-ip: prefix %s does not match family %s", prefix, family)
	}
	// Label = 0 placeholder; the real SRv6 SID is carried in the
	// Prefix-SID attribute (RFC 9252 section 4, no transposition case).
	nlri, err := bgp.NewLabeledVPNIPAddrPrefix(prefix, *bgp.NewMPLSLabelStack(0), rd)
	if err != nil {
		return VPNIPRoute{}, fmt.Errorf("vpn-ip: %w", err)
	}
	return VPNIPRoute{family: family, nlri: nlri, wireLen: nlri.Len()}, nil
}

// MustVPNIPRoute panics on error. Intended for tests and fixed in-tree
// fixtures where the inputs are known good at compile time.
func MustVPNIPRoute(family bgp.Family, rd bgp.RouteDistinguisherInterface, prefix netip.Prefix) VPNIPRoute {
	r, err := NewVPNIPRoute(family, rd, prefix)
	if err != nil {
		panic(err)
	}
	return r
}

func (r VPNIPRoute) Family() bgp.Family { return r.family }
func (r VPNIPRoute) NLRI() bgp.NLRI     { return r.nlri }
func (r VPNIPRoute) WireLen() int       { return r.wireLen }

// Key returns the canonical receive-side key
// (LabeledVPNIPAddrPrefix.String() = "<rd>:<prefix>"). waitForPrefixes
// resolves user-supplied L3VPN descriptors to this key so the
// observed-set lookup matches.
func (r VPNIPRoute) Key() string { return r.nlri.String() }
