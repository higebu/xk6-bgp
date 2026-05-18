package packet

import (
	"errors"
	"fmt"
	"net/netip"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// Route is a single family-specific NLRI input to BuildUpdateMessage
// and ChunkRoutes. Each AFI/SAFI ships its own concrete Route type so
// per-family validation and JS-shape conversion stay close to the wire
// encoding rather than leaking into the generic encoder. The family is
// authoritative — BuildUpdateMessage derives the message family from
// the first route and rejects mixed families.
type Route interface {
	// Family returns the AFI/SAFI this route belongs to.
	Family() bgp.Family
	// NLRI returns the gobgp NLRI ready to be embedded in the UPDATE
	// NLRI / Withdrawn-Routes / MP_REACH_NLRI / MP_UNREACH_NLRI
	// fields. Construction-time errors are surfaced by the concrete
	// type's constructor; NLRI itself must be allocation-free.
	NLRI() bgp.NLRI
	// WireLen returns the byte length of NLRI on the wire (length
	// octet + prefix bytes for IP-prefix families, or the equivalent
	// for variable-length NLRI such as MUP / EVPN). ChunkRoutes uses
	// it to pack routes greedily into BGP_MAX_MESSAGE_LENGTH chunks.
	WireLen() int
}

type PathAttrs struct {
	Origin    uint8 // 0 IGP, 1 EGP, 2 INCOMPLETE
	NextHop   netip.Addr
	LocalAS   uint32
	MED       *uint32
	LocalPref *uint32 // iBGP only
	// ExtCommunities, when non-empty, is emitted as a transitive
	// EXTENDED_COMMUNITIES attribute (RFC 4360). Required for L3VPN
	// route distribution where the receiver imports based on
	// Route-Target ext-communities (RFC 4364 section 4.3.1).
	ExtCommunities []bgp.ExtendedCommunityInterface
	// SRv6L3Service, when non-nil, is emitted as a PathAttributePrefixSID
	// holding a single SRv6 L3 Service TLV (RFC 9252). Shared by every
	// NLRI in the UPDATE — the common "one SID per VRF" L3VPN deployment
	// pattern. Per-prefix SID variation would need separate UPDATEs.
	SRv6L3Service *SRv6L3ServiceConfig
}

// SRv6L3ServiceConfig describes the contents of an RFC 9252 SRv6 L3
// Service TLV. The SID is signalled in full (no transposition), so the
// MPLS Label field of the VPN NLRI must stay 0 and Transposition Length
// / Offset stay 0. Locator Block + Node + Function + Argument lengths
// describe the SID Structure Sub-Sub-TLV (RFC 9252 section 3.2.1) and
// help the receiver decode the SID layout when it programs the dataplane.
type SRv6L3ServiceConfig struct {
	SID                 netip.Addr
	EndpointBehavior    bgp.SRBehavior
	LocatorBlockLength  uint8
	LocatorNodeLength   uint8
	FunctionLength      uint8
	ArgumentLength      uint8
	TranspositionLength uint8
	TranspositionOffset uint8
}

func (c *SRv6L3ServiceConfig) buildAttr() (*bgp.PathAttributePrefixSID, error) {
	if !c.SID.Is6() || c.SID.Is4In6() {
		return nil, fmt.Errorf("srv6L3Service: sid %s is not a plain IPv6 address", c.SID)
	}
	return bgp.NewPathAttributePrefixSID(
		bgp.NewSRv6ServiceTLV(
			bgp.TLVTypeSRv6L3Service,
			bgp.NewSRv6InformationSubTLV(
				c.SID,
				c.EndpointBehavior,
				bgp.NewSRv6SIDStructureSubSubTLV(
					c.LocatorBlockLength,
					c.LocatorNodeLength,
					c.FunctionLength,
					c.ArgumentLength,
					c.TranspositionLength,
					c.TranspositionOffset,
				),
			),
		),
	), nil
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

// BuildUpdateMessage encodes a single UPDATE. The family is taken from
// routes[0]; all routes must share that family. IPv4 unicast is carried
// in the UPDATE's own NLRI / Withdrawn-Routes fields per RFC 4271 by
// default; every other AFI/SAFI is carried in MP_REACH_NLRI /
// MP_UNREACH_NLRI per RFC 4760. Set
// EncodingOptions.UseMpReachForIPv4Unicast to override IPv4 unicast.
func BuildUpdateMessage(withdraw bool, attrs PathAttrs, routes []Route, opts EncodingOptions) (*bgp.BGPMessage, error) {
	if len(routes) == 0 {
		return nil, errors.New("UPDATE requires at least one route")
	}
	family := routes[0].Family()
	nlris := make([]bgp.PathNLRI, len(routes))
	for i, r := range routes {
		if r.Family() != family {
			return nil, fmt.Errorf("routes[%d]: family %s does not match routes[0] family %s",
				i, r.Family(), family)
		}
		nlris[i] = bgp.PathNLRI{NLRI: r.NLRI()}
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
	if len(attrs.ExtCommunities) > 0 {
		pa = append(pa, bgp.NewPathAttributeExtendedCommunities(attrs.ExtCommunities))
	}
	if attrs.SRv6L3Service != nil {
		psid, err := attrs.SRv6L3Service.buildAttr()
		if err != nil {
			return nil, err
		}
		pa = append(pa, psid)
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
	if len(attrs.ExtCommunities) > 0 {
		pa = append(pa, bgp.NewPathAttributeExtendedCommunities(attrs.ExtCommunities))
	}
	if attrs.SRv6L3Service != nil {
		psid, err := attrs.SRv6L3Service.buildAttr()
		if err != nil {
			return nil, err
		}
		pa = append(pa, psid)
	}
	return bgp.NewBGPUpdateMessage(nil, pa, nlris), nil
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

// ChunkRoutes splits routes into the largest possible sub-slices such
// that each chunk, when built into a single UPDATE with the same
// (withdraw, attrs), serializes within BGP_MAX_MESSAGE_LENGTH. It does
// so by computing the path-attribute overhead once and packing NLRIs
// greedily using Route.WireLen().
func ChunkRoutes(withdraw bool, attrs PathAttrs, routes []Route, opts EncodingOptions) ([][]Route, error) {
	if len(routes) == 0 {
		return nil, nil
	}
	overhead, err := shellOverhead(withdraw, attrs, routes[0], opts)
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
		sz := r.WireLen()
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
func shellOverhead(withdraw bool, attrs PathAttrs, probe Route, opts EncodingOptions) (int, error) {
	msg, err := BuildUpdateMessage(withdraw, attrs, []Route{probe}, opts)
	if err != nil {
		return 0, err
	}
	body, err := msg.Body.Serialize()
	if err != nil {
		return 0, err
	}
	return len(body) - probe.WireLen(), nil
}
