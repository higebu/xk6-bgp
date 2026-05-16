package packet

import (
	"errors"
	"fmt"
	"net/netip"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

type Route struct {
	Prefix netip.Prefix
}

type PathAttrs struct {
	Origin    uint8 // 0 IGP, 1 EGP, 2 INCOMPLETE
	NextHop   netip.Addr
	LocalAS   uint32
	MED       *uint32
	LocalPref *uint32 // iBGP only
}

// EncodingOptions tunes how BuildUpdateMessage / ChunkRoutes encode an
// UPDATE on the packet. The defaults match the most common deployments;
// override only to compare encodings or accommodate a peer that
// expects a non-default form.
type EncodingOptions struct {
	// UseMpReachForIPv4Unicast forces IPv4 unicast NLRI (and
	// withdrawals) into MP_REACH_NLRI / MP_UNREACH_NLRI even though
	// RFC 4271 places them in the UPDATE message body's own NLRI /
	// Withdrawn-Routes fields. RFC 4760 section 1 allows both forms.
	// Default false: IPv4 unicast uses the traditional fields, which
	// some receivers process on a significantly faster path.
	UseMpReachForIPv4Unicast bool
	// UseExtendedMessages widens the per-UPDATE chunk budget from
	// 4096 bytes (RFC 4271) to 65535 bytes (RFC 8654). The capability
	// MUST have been advertised in OPEN and accepted by the peer for
	// this to be safe; otherwise the peer will close the session with
	// `Bad Message Length`. The Peer's `extendedMessage: true`
	// capability defaults already advertise it.
	UseExtendedMessages bool
}

// BGPExtendedMaxMessageLength is RFC 8654's relaxed max BGP message
// size when Extended Messages has been negotiated by both peers.
const BGPExtendedMaxMessageLength = 65535

// BuildUpdateMessage encodes a single UPDATE. IPv4 unicast is carried
// in the UPDATE's own NLRI / Withdrawn-Routes fields per RFC 4271 by
// default; every other AFI/SAFI is carried in MP_REACH_NLRI /
// MP_UNREACH_NLRI per RFC 4760. Set
// EncodingOptions.UseMpReachForIPv4Unicast to override IPv4 unicast.
func BuildUpdateMessage(family bgp.Family, withdraw bool, attrs PathAttrs, routes []Route, opts EncodingOptions) (*bgp.BGPMessage, error) {
	if len(routes) == 0 {
		return nil, errors.New("UPDATE requires at least one route")
	}
	nlris, err := buildPathNLRIs(family, routes)
	if err != nil {
		return nil, err
	}

	if family.Afi() == bgp.AFI_IP && family.Safi() == bgp.SAFI_UNICAST && !opts.UseMpReachForIPv4Unicast {
		return buildIPv4UnicastUpdate(withdraw, attrs, nlris)
	}

	if withdraw {
		mpu, err := bgp.NewPathAttributeMpUnreachNLRI(family, nlris)
		if err != nil {
			return nil, fmt.Errorf("build MP_UNREACH_NLRI: %w", err)
		}
		return bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{mpu}, nil), nil
	}

	if !attrs.NextHop.IsValid() {
		return nil, errors.New("path attrs: nextHop is required for advertisement")
	}
	if attrs.LocalAS == 0 {
		return nil, errors.New("path attrs: localAS is required for AS_PATH construction")
	}

	mpr, err := bgp.NewPathAttributeMpReachNLRI(family, nlris, attrs.NextHop)
	if err != nil {
		return nil, fmt.Errorf("build MP_REACH_NLRI: %w", err)
	}

	pa := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(attrs.Origin),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{attrs.LocalAS}),
		}),
		mpr,
	}
	// RFC 4271 section 5 lists NEXT_HOP as well-known mandatory whenever an
	// UPDATE advertises reachability. RFC 4760 section 3 lets MP_REACH carry
	// its own next-hop and is silent about omitting NEXT_HOP, but
	// strict receivers (FRR among them) reject an MP_REACH IPv4
	// unicast UPDATE that is then re-encoded into the traditional
	// NLRI form without NEXT_HOP. Emit NEXT_HOP alongside MP_REACH
	// for IPv4 next-hops so the route survives re-advertisement
	// through such receivers.
	if attrs.NextHop.Is4() || attrs.NextHop.Is4In6() {
		nh, err := bgp.NewPathAttributeNextHop(attrs.NextHop)
		if err != nil {
			return nil, fmt.Errorf("build NEXT_HOP: %w", err)
		}
		pa = append(pa, nh)
	}
	if attrs.MED != nil {
		pa = append(pa, bgp.NewPathAttributeMultiExitDisc(*attrs.MED))
	}
	if attrs.LocalPref != nil {
		pa = append(pa, bgp.NewPathAttributeLocalPref(*attrs.LocalPref))
	}

	return bgp.NewBGPUpdateMessage(nil, pa, nil), nil
}

func buildIPv4UnicastUpdate(withdraw bool, attrs PathAttrs, nlris []bgp.PathNLRI) (*bgp.BGPMessage, error) {
	if withdraw {
		return bgp.NewBGPUpdateMessage(nlris, nil, nil), nil
	}
	if !attrs.NextHop.IsValid() {
		return nil, errors.New("path attrs: nextHop is required for advertisement")
	}
	if attrs.LocalAS == 0 {
		return nil, errors.New("path attrs: localAS is required for AS_PATH construction")
	}
	if !attrs.NextHop.Is4() && !attrs.NextHop.Is4In6() {
		return nil, fmt.Errorf("path attrs: nextHop %s is not IPv4 for IPv4-unicast", attrs.NextHop)
	}
	nh, err := bgp.NewPathAttributeNextHop(attrs.NextHop)
	if err != nil {
		return nil, fmt.Errorf("build NEXT_HOP: %w", err)
	}
	pa := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(attrs.Origin),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{attrs.LocalAS}),
		}),
		nh,
	}
	if attrs.MED != nil {
		pa = append(pa, bgp.NewPathAttributeMultiExitDisc(*attrs.MED))
	}
	if attrs.LocalPref != nil {
		pa = append(pa, bgp.NewPathAttributeLocalPref(*attrs.LocalPref))
	}
	return bgp.NewBGPUpdateMessage(nil, pa, nlris), nil
}

func buildPathNLRIs(family bgp.Family, routes []Route) ([]bgp.PathNLRI, error) {
	out := make([]bgp.PathNLRI, 0, len(routes))
	wantIPv6 := family.Afi() == bgp.AFI_IP6

	for i, r := range routes {
		if !r.Prefix.IsValid() {
			return nil, fmt.Errorf("routes[%d]: invalid prefix", i)
		}
		gotIPv6 := r.Prefix.Addr().Is6() && !r.Prefix.Addr().Is4In6()
		if gotIPv6 != wantIPv6 {
			return nil, fmt.Errorf("routes[%d]: prefix %s does not match family %s", i, r.Prefix, family)
		}
		nlri, err := bgp.NewIPAddrPrefix(r.Prefix)
		if err != nil {
			return nil, fmt.Errorf("routes[%d]: %w", i, err)
		}
		out = append(out, bgp.PathNLRI{NLRI: nlri})
	}
	return out, nil
}

// SerializeMessage encodes a BGPMessage onto the packet. With Extended
// Messages negotiated (RFC 8654), an UPDATE may exceed gobgp's
// hard-coded 4096-byte ceiling in BGPMessage.Serialize; pre-set
// Header.Len so the check is skipped. Caller must ensure the peer has
// in fact negotiated Extended Messages, otherwise the receiver will
// drop the session.
func SerializeMessage(msg *bgp.BGPMessage, opts EncodingOptions) ([]byte, error) {
	if opts.UseExtendedMessages {
		body, err := msg.Body.Serialize()
		if err != nil {
			return nil, err
		}
		total := bgp.BGP_HEADER_LENGTH + len(body)
		if total > BGPExtendedMaxMessageLength {
			return nil, fmt.Errorf("message length %d exceeds extended max %d",
				total, BGPExtendedMaxMessageLength)
		}
		msg.Header.Len = uint16(total)
	}
	return msg.Serialize()
}

// nlriWireSize returns the byte length of a single NLRI on the wire
// for the IP-unicast families.
func nlriWireSize(r Route) int {
	return 1 + (int(r.Prefix.Bits())+7)/8
}

// ChunkRoutes splits routes into the largest possible sub-slices such
// that each chunk, when built into a single UPDATE with the same
// (family, withdraw, attrs), serializes within BGP_MAX_MESSAGE_LENGTH.
// It does so by computing the path-attribute overhead once and packing
// NLRIs greedily.
func ChunkRoutes(family bgp.Family, withdraw bool, attrs PathAttrs, routes []Route, opts EncodingOptions) ([][]Route, error) {
	if len(routes) == 0 {
		return nil, nil
	}
	overhead, err := shellOverhead(family, withdraw, attrs, routes[0], opts)
	if err != nil {
		return nil, err
	}
	maxLen := bgp.BGP_MAX_MESSAGE_LENGTH
	if opts.UseExtendedMessages {
		maxLen = BGPExtendedMaxMessageLength
	}
	budget := maxLen - bgp.BGP_HEADER_LENGTH - overhead
	if budget <= 0 {
		return nil, fmt.Errorf("path attrs overhead %dB leaves no room for NLRIs in a %dB message",
			overhead, maxLen)
	}

	var chunks [][]Route
	start, used := 0, 0
	for i, r := range routes {
		sz := nlriWireSize(r)
		if sz > budget {
			return nil, fmt.Errorf("routes[%d]: NLRI size %dB exceeds per-message budget %dB", i, sz, budget)
		}
		if used+sz > budget {
			chunks = append(chunks, routes[start:i])
			start, used = i, 0
		}
		used += sz
	}
	chunks = append(chunks, routes[start:])
	return chunks, nil
}

// shellOverhead returns the byte length of an UPDATE *body* (path
// attributes section, including the MP_REACH/MP_UNREACH header and
// AFI/SAFI/next-hop fields) excluding the NLRI bytes themselves. The
// "probe" route is used to compute and subtract its NLRI wire length
// because gobgp's serializer needs at least one NLRI to encode the
// MP attribute.
func shellOverhead(family bgp.Family, withdraw bool, attrs PathAttrs, probe Route, opts EncodingOptions) (int, error) {
	msg, err := BuildUpdateMessage(family, withdraw, attrs, []Route{probe}, opts)
	if err != nil {
		return 0, err
	}
	body, err := msg.Body.Serialize()
	if err != nil {
		return 0, err
	}
	return len(body) - nlriWireSize(probe), nil
}
