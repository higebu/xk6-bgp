package packet

import (
	"fmt"
	"net/netip"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// MUP route types defined in draft-mpmz-bess-mup-safi-03 section 3.1.
// gobgp exposes these as untyped integer constants; we re-export them
// as strings for the JS-facing API so scripts can spell them out.
const (
	MUPTypeISD  = "isd"  // Interwork Segment Discovery (section 3.1.1)
	MUPTypeDSD  = "dsd"  // Direct Segment Discovery (section 3.1.2)
	MUPTypeT1ST = "t1st" // Type 1 Session Transformed (section 3.1.3)
	MUPTypeT2ST = "t2st" // Type 2 Session Transformed (section 3.1.4)
)

// MUPRoute is the Route implementation for the MUP SAFI (AFI=1 or 2,
// SAFI=85) per draft-mpmz-bess-mup-safi-03. It covers all four 3GPP-5G
// route types behind a single concrete type; the constructors validate
// per-type inputs and pre-build the gobgp NLRI so per-route encoding is
// allocation-free on the hot path. Future architecture types can be
// added when gobgp gains support.
type MUPRoute struct {
	family bgp.Family
	nlri   *bgp.MUPNLRI
	// wireLen caches MUPNLRI.Len() (route-type-data Len + 4-byte MUP
	// header) so ChunkRoutes does not call back into gobgp per route.
	wireLen int
}

// NewMUPInterworkSegmentDiscoveryRoute constructs a MUP ISD route
// (draft-mpmz-bess-mup-safi-03 section 3.1.1). family must be
// RF_MUP_IPv4 or RF_MUP_IPv6, and prefix's address family must match.
func NewMUPInterworkSegmentDiscoveryRoute(family bgp.Family, rd bgp.RouteDistinguisherInterface, prefix netip.Prefix) (MUPRoute, error) {
	if err := checkMUPFamilyForPrefix(family, prefix); err != nil {
		return MUPRoute{}, fmt.Errorf("mup-isd: %w", err)
	}
	if rd == nil {
		return MUPRoute{}, fmt.Errorf("mup-isd: rd is required")
	}
	nlri := bgp.NewMUPInterworkSegmentDiscoveryRoute(rd, prefix)
	return MUPRoute{family: family, nlri: nlri, wireLen: nlri.Len()}, nil
}

// NewMUPDirectSegmentDiscoveryRoute constructs a MUP DSD route
// (draft-mpmz-bess-mup-safi-03 section 3.1.2).
func NewMUPDirectSegmentDiscoveryRoute(family bgp.Family, rd bgp.RouteDistinguisherInterface, address netip.Addr) (MUPRoute, error) {
	if err := checkMUPFamilyForAddr(family, address); err != nil {
		return MUPRoute{}, fmt.Errorf("mup-dsd: %w", err)
	}
	if rd == nil {
		return MUPRoute{}, fmt.Errorf("mup-dsd: rd is required")
	}
	nlri := bgp.NewMUPDirectSegmentDiscoveryRoute(rd, address)
	return MUPRoute{family: family, nlri: nlri, wireLen: nlri.Len()}, nil
}

// NewMUPType1SessionTransformedRoute constructs a MUP T1ST route
// (draft-mpmz-bess-mup-safi-03 section 3.1.3). qfi is the 5G QoS Flow
// Identifier (6-bit, but the wire field is one octet). teid must be an
// IPv4-shaped netip.Addr because gobgp stores the 32-bit TEID in a
// 4-byte netip.Addr. endpoint and (optional) source addresses must
// match the family AFI.
func NewMUPType1SessionTransformedRoute(family bgp.Family, rd bgp.RouteDistinguisherInterface, prefix netip.Prefix, teid netip.Addr, qfi uint8, endpoint netip.Addr, source *netip.Addr) (MUPRoute, error) {
	if err := checkMUPFamilyForPrefix(family, prefix); err != nil {
		return MUPRoute{}, fmt.Errorf("mup-t1st: %w", err)
	}
	if rd == nil {
		return MUPRoute{}, fmt.Errorf("mup-t1st: rd is required")
	}
	if !teid.Is4() {
		return MUPRoute{}, fmt.Errorf("mup-t1st: teid must be an IPv4-shaped 4-byte address (got %s)", teid)
	}
	if !endpoint.IsValid() {
		return MUPRoute{}, fmt.Errorf("mup-t1st: endpoint address is required")
	}
	if err := checkMUPFamilyForAddr(family, endpoint); err != nil {
		return MUPRoute{}, fmt.Errorf("mup-t1st endpoint: %w", err)
	}
	if source != nil {
		if !source.IsValid() {
			return MUPRoute{}, fmt.Errorf("mup-t1st: source address is invalid")
		}
		if err := checkMUPFamilyForAddr(family, *source); err != nil {
			return MUPRoute{}, fmt.Errorf("mup-t1st source: %w", err)
		}
	}
	nlri := bgp.NewMUPType1SessionTransformedRoute(rd, prefix, teid, qfi, endpoint, source)
	return MUPRoute{family: family, nlri: nlri, wireLen: nlri.Len()}, nil
}

// NewMUPType2SessionTransformedRoute constructs a MUP T2ST route
// (draft-mpmz-bess-mup-safi-03 section 3.1.4). endpointAddressLength is
// the combined Endpoint Address + TEID bit length per the draft:
// IPv4 endpoint = 32 + TEID-bits (0..32), IPv6 endpoint = 128 +
// TEID-bits. teid must be IPv4-shaped (gobgp stores it in 4 bytes).
func NewMUPType2SessionTransformedRoute(family bgp.Family, rd bgp.RouteDistinguisherInterface, endpoint netip.Addr, endpointAddressLength uint8, teid netip.Addr) (MUPRoute, error) {
	if rd == nil {
		return MUPRoute{}, fmt.Errorf("mup-t2st: rd is required")
	}
	if !endpoint.IsValid() {
		return MUPRoute{}, fmt.Errorf("mup-t2st: endpoint address is required")
	}
	if err := checkMUPFamilyForAddr(family, endpoint); err != nil {
		return MUPRoute{}, fmt.Errorf("mup-t2st endpoint: %w", err)
	}
	switch family.Afi() {
	case bgp.AFI_IP:
		if endpointAddressLength < 32 || endpointAddressLength > 64 {
			return MUPRoute{}, fmt.Errorf("mup-t2st: endpointAddressLength %d out of range [32..64] for ipv4-mup", endpointAddressLength)
		}
	case bgp.AFI_IP6:
		if endpointAddressLength < 128 || endpointAddressLength > 160 {
			return MUPRoute{}, fmt.Errorf("mup-t2st: endpointAddressLength %d out of range [128..160] for ipv6-mup", endpointAddressLength)
		}
	}
	if !teid.Is4() {
		return MUPRoute{}, fmt.Errorf("mup-t2st: teid must be an IPv4-shaped 4-byte address (got %s)", teid)
	}
	nlri := bgp.NewMUPType2SessionTransformedRoute(rd, endpointAddressLength, endpoint, teid)
	return MUPRoute{family: family, nlri: nlri, wireLen: nlri.Len()}, nil
}

func (r MUPRoute) Family() bgp.Family { return r.family }
func (r MUPRoute) NLRI() bgp.NLRI     { return r.nlri }
func (r MUPRoute) WireLen() int       { return r.wireLen }

// Key returns the canonical receive-side key (gobgp's NLRI.String() of
// the underlying MUPNLRI). waitForPrefixes resolves user-supplied
// descriptors to this key so the observed-set lookup matches.
func (r MUPRoute) Key() string { return r.nlri.String() }

func checkMUPFamilyForPrefix(family bgp.Family, prefix netip.Prefix) error {
	if family.Safi() != bgp.SAFI_MUP {
		return fmt.Errorf("family %s is not MUP", family)
	}
	if !prefix.IsValid() {
		return fmt.Errorf("invalid prefix")
	}
	return checkMUPFamilyForAddr(family, prefix.Addr())
}

func checkMUPFamilyForAddr(family bgp.Family, addr netip.Addr) error {
	if family.Safi() != bgp.SAFI_MUP {
		return fmt.Errorf("family %s is not MUP", family)
	}
	wantV6 := family.Afi() == bgp.AFI_IP6
	gotV6 := addr.Is6() && !addr.Is4In6()
	if wantV6 != gotV6 {
		return fmt.Errorf("address %s does not match family %s", addr, family)
	}
	return nil
}
