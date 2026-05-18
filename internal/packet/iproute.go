package packet

import (
	"fmt"
	"net/netip"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// IPRoute is the Route implementation for IPv4 unicast (AFI=1, SAFI=1)
// and IPv6 unicast (AFI=2, SAFI=1). NewIPRoute validates the prefix
// against the requested family and pre-builds the gobgp NLRI so
// per-route encoding is allocation-free on the hot path.
type IPRoute struct {
	family bgp.Family
	prefix netip.Prefix
	nlri   *bgp.IPAddrPrefix
}

// NewIPRoute constructs an IPRoute for the given family and prefix.
// family must be RF_IPv4_UC or RF_IPv6_UC, and prefix.Addr() must
// match the family's AFI. The returned IPRoute caches the gobgp NLRI
// so Route.NLRI() is allocation-free.
func NewIPRoute(family bgp.Family, prefix netip.Prefix) (IPRoute, error) {
	if family.Safi() != bgp.SAFI_UNICAST {
		return IPRoute{}, fmt.Errorf("ip-route: family %s is not unicast", family)
	}
	switch family.Afi() {
	case bgp.AFI_IP, bgp.AFI_IP6:
	default:
		return IPRoute{}, fmt.Errorf("ip-route: family %s AFI is not IPv4 or IPv6", family)
	}
	if !prefix.IsValid() {
		return IPRoute{}, fmt.Errorf("ip-route: invalid prefix")
	}
	wantV6 := family.Afi() == bgp.AFI_IP6
	gotV6 := prefix.Addr().Is6() && !prefix.Addr().Is4In6()
	if wantV6 != gotV6 {
		return IPRoute{}, fmt.Errorf("ip-route: prefix %s does not match family %s", prefix, family)
	}
	nlri, err := bgp.NewIPAddrPrefix(prefix)
	if err != nil {
		return IPRoute{}, fmt.Errorf("ip-route: %w", err)
	}
	return IPRoute{family: family, prefix: prefix, nlri: nlri}, nil
}

// MustIPRoute panics on error. Intended for tests and fixed in-tree
// fixtures where the inputs are known good at compile time.
func MustIPRoute(family bgp.Family, prefix netip.Prefix) IPRoute {
	r, err := NewIPRoute(family, prefix)
	if err != nil {
		panic(err)
	}
	return r
}

func (r IPRoute) Family() bgp.Family { return r.family }
func (r IPRoute) NLRI() bgp.NLRI     { return r.nlri }
func (r IPRoute) Prefix() netip.Prefix { return r.prefix }

// WireLen returns the on-the-wire byte length for an IP-prefix NLRI:
// one length octet plus the minimum number of address octets required
// to carry Prefix.Bits() bits, per RFC 4271 section 4.3.
func (r IPRoute) WireLen() int {
	return 1 + (int(r.prefix.Bits())+7)/8
}
