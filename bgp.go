package bgp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/grafana/sobek"
	gobgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"go.k6.io/k6/js/common"
	"go.k6.io/k6/lib/types"
	k6metrics "go.k6.io/k6/metrics"

	xmetrics "github.com/higebu/xk6-bgp/internal/metrics"
	"github.com/higebu/xk6-bgp/internal/packet"
	"github.com/higebu/xk6-bgp/internal/peer"
	"github.com/higebu/xk6-bgp/internal/timing"
)

// Peer is the JS-facing BGP peer object, a thin facade over
// internal/peer.Peer. The JS-side Peer also caches the resolved Family
// map so per-Advertise family strings stay off the allocation hot path.
type Peer struct {
	mi       *ModuleInstance
	impl     *peer.Peer
	families map[string]gobgp.Family
	peerTag  string
	tags     *k6metrics.TagSet
}

func (mi *ModuleInstance) newPeer(call sobek.ConstructorCall) *sobek.Object {
	rt := mi.vu.Runtime()

	if len(call.Arguments) < 1 {
		panic(rt.NewTypeError("bgp.Peer: missing config argument"))
	}
	obj := call.Argument(0).ToObject(rt)
	if obj == nil {
		panic(rt.NewTypeError("bgp.Peer: config must be an object"))
	}

	cfg, families, err := parsePeerConfig(rt, obj)
	if err != nil {
		panic(rt.NewTypeError("bgp.Peer: " + err.Error()))
	}
	impl, err := peer.New(cfg)
	if err != nil {
		panic(rt.NewTypeError("bgp.Peer: " + err.Error()))
	}

	// peerTag is opt-in via `tags: { peer: "..." }` from JS. Defaulting
	// to cfg.Target would put host:port into every metric label —
	// high-cardinality in Prometheus/Cloud output.
	peerTag := ""
	if v, ok := cfg.Tags["peer"]; ok {
		peerTag = v
	}
	p := &Peer{mi: mi, impl: impl, families: families, peerTag: peerTag}

	// Plain sobek Object so we can mix data properties (methods) with
	// an accessor property (`state`). The reflect-bound host object
	// returned by rt.ToValue(p).ToObject(rt) refuses
	// DefineAccessorProperty, which is why we wire each member by hand.
	jsObj := rt.NewObject()
	bind := func(name string, fn any) {
		if err := jsObj.Set(name, fn); err != nil {
			panic(rt.NewTypeError("bgp.Peer: bind " + name + ": " + err.Error()))
		}
	}
	bind("open", p.Open)
	bind("close", p.Close)
	bind("advertise", p.Advertise)
	bind("withdraw", p.Withdraw)
	bind("waitForPrefixes", p.WaitForPrefixes)
	bind("stats", p.Stats)

	// `state` is a read-only accessor property, not a method, so that
	// `peer.state` returns the FSM state string (e.g. `'Established'`)
	// directly. Writing `if (peer.state === 'Established')` would
	// silently never match if it were a method.
	getter := rt.ToValue(func() string { return p.impl.State().String() })
	if err := jsObj.DefineAccessorProperty("state", getter, sobek.Undefined(),
		sobek.FLAG_FALSE, sobek.FLAG_TRUE); err != nil {
		panic(rt.NewTypeError("bgp.Peer: bind state accessor: " + err.Error()))
	}
	return jsObj
}

// parsePeerConfig reads the JS config object into a peer.Config plus a
// pre-resolved family lookup map. The Caps defaults (extendedMessage,
// routeRefresh, GR with N-bit) are enabled when the JS side leaves them
// unset.
func parsePeerConfig(rt *sobek.Runtime, obj *sobek.Object) (peer.Config, map[string]gobgp.Family, error) {
	cfg := peer.Config{
		LocalAS: optUint32(obj, "localAs"),
		PeerAS:  optUint32(obj, "peerAs"),
		Target:  optString(obj, "target"),
		Caps: packet.CapsConfig{
			ExtendedMessage: true,
			RouteRefresh:    true,
			GracefulRestart: &packet.GRConfig{RestartTime: 120, Notification: true},
		},
	}

	if s := optString(obj, "routerId"); s != "" {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return cfg, nil, fmt.Errorf("routerId: %w", err)
		}
		cfg.RouterID = addr
	}

	if s := optString(obj, "localAddress"); s != "" {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return cfg, nil, fmt.Errorf("localAddress: %w", err)
		}
		cfg.LocalAddress = addr
	}

	families := map[string]gobgp.Family{}
	if v := obj.Get("families"); !common.IsNullish(v) {
		fam, ok := v.Export().([]any)
		if !ok {
			return cfg, nil, errors.New("families must be a string array")
		}
		for i, x := range fam {
			s, ok := x.(string)
			if !ok {
				return cfg, nil, fmt.Errorf("families[%d] must be a string", i)
			}
			f, err := packet.ResolveFamily(s)
			if err != nil {
				return cfg, nil, err
			}
			cfg.Families = append(cfg.Families, f)
			families[s] = f
		}
	}

	if v := obj.Get("timers"); !common.IsNullish(v) {
		tobj := v.ToObject(rt)
		var err error
		if cfg.Timers.HoldTime, err = optDuration(tobj, "holdtime"); err != nil {
			return cfg, nil, fmt.Errorf("timers.holdtime: %w", err)
		}
		if cfg.Timers.OpenTimeout, err = optDuration(tobj, "openTimeout"); err != nil {
			return cfg, nil, fmt.Errorf("timers.openTimeout: %w", err)
		}
	}

	if v := obj.Get("capabilities"); !common.IsNullish(v) {
		cobj := v.ToObject(rt)
		if vv := cobj.Get("extendedMessage"); !common.IsNullish(vv) {
			cfg.Caps.ExtendedMessage = vv.ToBoolean()
		}
		if vv := cobj.Get("routeRefresh"); !common.IsNullish(vv) {
			cfg.Caps.RouteRefresh = vv.ToBoolean()
		}
		if vv := cobj.Get("enhancedRouteRefresh"); !common.IsNullish(vv) {
			cfg.Caps.EnhancedRefresh = vv.ToBoolean()
		}
		if vv := cobj.Get("gracefulRestart"); !common.IsNullish(vv) {
			gr, err := parseGracefulRestart(rt, vv)
			if err != nil {
				return cfg, nil, err
			}
			cfg.Caps.GracefulRestart = gr
		}
		if vv := cobj.Get("addPath"); !common.IsNullish(vv) {
			ap, err := parseAddPath(rt, vv)
			if err != nil {
				return cfg, nil, err
			}
			cfg.Caps.AddPath = ap
		}
	}

	if v := obj.Get("tags"); !common.IsNullish(v) {
		tobj := v.ToObject(rt)
		cfg.Tags = map[string]string{}
		for _, k := range tobj.Keys() {
			cfg.Tags[k] = tobj.Get(k).String()
		}
	}

	return cfg, families, nil
}

func parseGracefulRestart(rt *sobek.Runtime, v sobek.Value) (*packet.GRConfig, error) {
	if b, ok := v.Export().(bool); ok {
		if !b {
			return nil, nil
		}
		return &packet.GRConfig{RestartTime: 120, Notification: true}, nil
	}
	gobj := v.ToObject(rt)
	if gobj == nil {
		return nil, errors.New("capabilities.gracefulRestart must be an object or boolean")
	}
	return &packet.GRConfig{
		RestartTime:  uint16(optUint32(gobj, "restartTime")), // #nosec G115 -- Restart Time is a 12-bit value carried in a 16-bit field per RFC 4724 section 3
		Notification: optBool(gobj, "notification"),
	}, nil
}

// parseAddPath reads the RFC 7911 capability config from a JS object
// mapping family name to direction:
//
//	capabilities: { addPath: { 'ipv4-unicast': 'both' } }
//
// Directions are 'receive', 'send', or 'both'. Every family listed
// here must also appear in the Peer's `families`.
func parseAddPath(rt *sobek.Runtime, v sobek.Value) (map[gobgp.Family]gobgp.BGPAddPathMode, error) {
	obj := v.ToObject(rt)
	if obj == nil {
		return nil, errors.New("capabilities.addPath must be an object mapping family to direction")
	}
	keys := obj.Keys()
	if len(keys) == 0 {
		return nil, errors.New("capabilities.addPath must not be empty")
	}
	out := make(map[gobgp.Family]gobgp.BGPAddPathMode, len(keys))
	for _, k := range keys {
		f, err := packet.ResolveFamily(k)
		if err != nil {
			return nil, fmt.Errorf("capabilities.addPath: %w", err)
		}
		m, err := packet.ResolveAddPathMode(obj.Get(k).String())
		if err != nil {
			return nil, fmt.Errorf("capabilities.addPath[%s]: %w", k, err)
		}
		out[f] = m
	}
	return out, nil
}

// Open completes the OPEN/KEEPALIVE handshake and returns a JS object
// carrying the per-call observation `sessionUpUs` (`OpenSent →
// Established` µs). Scripts that need to log per-iteration session-up
// numbers consume this value directly; the same value is also emitted
// as the `bgp_session_up` Trend metric for dashboard consumption.
func (p *Peer) Open() (sobek.Value, error) {
	// Cannot defer-cancel a parent-derived ctx: the read/keepalive
	// goroutines outlive this call and must live until Close().
	if err := p.impl.Open(p.mi.vu.Context()); err != nil {
		return nil, err
	}
	if st := p.mi.vu.State(); st != nil {
		p.tags = xmetrics.BuildPeerTags(st.Tags.GetCurrentValues().Tags, p.peerTag)
	}
	us := p.impl.SessionUpDuration()
	if m := p.mi.metrics; m != nil && p.tags != nil {
		xmetrics.PushTrendMicros(p.mi.vu.Context(), p.mi.vu.State().Samples,
			m.SessionUp, p.tags, us)
	}
	return p.mi.vu.Runtime().ToValue(map[string]any{
		"sessionUpUs": us,
	}), nil
}

func (p *Peer) Close() error { return p.impl.Close() }

// Stats returns a snapshot of the receive-side counters accumulated
// since Open. Cheap to call; does not block like waitForPrefixes.
func (p *Peer) Stats() sobek.Value {
	s := p.impl.Stats()
	return p.mi.vu.Runtime().ToValue(map[string]any{
		"updates":           s.Updates,
		"advertised":        s.AdvertisedNLRI,
		"withdrawn":         s.WithdrawnNLRI,
		"uniquePrefixes":    s.UniquePrefixes,
		"firstUpdateWallNs": s.FirstUpdateAt.WallNs(),
		"firstUpdateMonoNs": s.FirstUpdateAt.MonoNs(),
		"lastUpdateWallNs":  s.LastUpdateAt.WallNs(),
		"lastUpdateMonoNs":  s.LastUpdateAt.MonoNs(),
	})
}

func (p *Peer) Advertise(arg sobek.Value) (sobek.Value, error) {
	rt := p.mi.vu.Runtime()
	req, err := p.parseAdvertiseArg(rt, arg, false)
	if err != nil {
		return nil, err
	}
	res, err := p.impl.Advertise(req)
	if err != nil {
		return nil, err
	}
	p.recordSent(res.Sent)
	return resultToJS(rt, res), nil
}

func (p *Peer) Withdraw(arg sobek.Value) (sobek.Value, error) {
	rt := p.mi.vu.Runtime()
	req, err := p.parseAdvertiseArg(rt, arg, true)
	if err != nil {
		return nil, err
	}
	res, err := p.impl.Withdraw(peer.WithdrawRequest{Family: req.Family, Routes: req.Routes, Encoding: req.Encoding, UpdateRate: req.UpdateRate})
	if err != nil {
		return nil, err
	}
	return resultToJS(rt, res), nil
}

func (p *Peer) recordSent(n int) {
	if p.mi.metrics == nil || p.tags == nil || n <= 0 {
		return
	}
	xmetrics.PushCounter(p.mi.vu.Context(), p.mi.vu.State().Samples,
		p.mi.metrics.PrefixSent, p.tags, float64(n))
}

// WaitForPrefixes blocks until all listed prefixes have been observed
// on the receive side or the timeout expires. Errors (including
// timeout) are thrown back to JS — match the Advertise/Withdraw shape so
// scripts can wrap the call in try/catch. sentAtMonoNs, when provided,
// (a) anchors bgp_prefix_received_duration and (b) filters observations
// that predate the advertise so a re-used Peer does not match leftovers
// from a previous iteration.
//
// JS shape:
//
//	peer.waitForPrefixes({
//	  prefixes:     ['10.0.0.0/24', ...],
//	  timeout:      '5s',
//	  sentAtMonoNs: adv.sentAtMonoNs,
//	})
func (p *Peer) WaitForPrefixes(arg sobek.Value) (sobek.Value, error) {
	rt := p.mi.vu.Runtime()
	if common.IsNullish(arg) {
		return nil, errors.New("waitForPrefixes: missing argument")
	}
	obj := arg.ToObject(rt)

	prefixes, err := parsePrefixList(rt, obj)
	if err != nil {
		return nil, err
	}
	timeout, err := optDuration(obj, "timeout")
	if err != nil {
		return nil, fmt.Errorf("waitForPrefixes.timeout: %w", err)
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	sentMono := optInt64(obj, "sentAtMonoNs")
	var onlyAfter timing.Timestamp
	if sentMono > 0 {
		onlyAfter = timing.FromMonoNs(sentMono)
	}

	res, waitErr := p.impl.WaitForPrefixes(prefixes, timeout, onlyAfter)
	out := rt.ToValue(map[string]any{
		"matched":         res.Matched,
		"missing":         res.Missing,
		"firstSeenWallNs": res.FirstSeen.WallNs(),
		"firstSeenMonoNs": res.FirstSeen.MonoNs(),
		"lastSeenWallNs":  res.LastSeen.WallNs(),
		"lastSeenMonoNs":  res.LastSeen.MonoNs(),
	})
	if waitErr != nil {
		return out, waitErr
	}

	if p.mi.metrics != nil && p.tags != nil {
		if sentMono > 0 {
			us := (res.LastSeen.MonoNs() - sentMono) / 1000
			if us >= 0 {
				xmetrics.PushTrendMicros(p.mi.vu.Context(), p.mi.vu.State().Samples,
					p.mi.metrics.PrefixReceivedDuration, p.tags, us)
			}
		}
		xmetrics.PushCounter(p.mi.vu.Context(), p.mi.vu.State().Samples,
			p.mi.metrics.PrefixReceived, p.tags, float64(res.Matched))
	}
	return out, nil
}

// parsePrefixList collects the user's prefix array and canonicalizes
// each entry into the gobgp NLRI.String() form so it matches the
// observed-set keys recorded by the receive path. Bare strings are
// treated as IP prefixes (IP unicast); object form is accepted for MUP
// descriptors (same shape as advertise's routes — see parseMUPRoute).
// Like parseRoutesArray, this walks the sobek Array directly to avoid
// the []any allocation Value.Export() would do.
func parsePrefixList(rt *sobek.Runtime, obj *sobek.Object) ([]string, error) {
	pv := obj.Get("prefixes")
	if common.IsNullish(pv) {
		return nil, errors.New("waitForPrefixes: prefixes is required")
	}
	arr := pv.ToObject(rt)
	if arr == nil {
		return nil, errors.New("waitForPrefixes: prefixes must be an array")
	}
	lenV := arr.Get("length")
	if common.IsNullish(lenV) {
		return nil, errors.New("waitForPrefixes: prefixes must be an array")
	}
	n := int(lenV.ToInteger())
	if n <= 0 {
		return nil, errors.New("waitForPrefixes: prefixes must be a non-empty array")
	}
	out := make([]string, n)
	for i := range n {
		elem := arr.Get(strconv.Itoa(i))
		if elem == nil || common.IsNullish(elem) {
			return nil, fmt.Errorf("waitForPrefixes: prefixes[%d] is nullish", i)
		}
		if isStringValue(elem) {
			base, idSuffix, err := splitPathID(elem.String())
			if err != nil {
				return nil, fmt.Errorf("waitForPrefixes: prefixes[%d]: %w", i, err)
			}
			pref, err := netip.ParsePrefix(base)
			if err != nil {
				return nil, fmt.Errorf("waitForPrefixes: prefixes[%d]: %w", i, err)
			}
			out[i] = pref.String() + idSuffix
			continue
		}
		eobj := elem.ToObject(rt)
		if eobj == nil {
			return nil, fmt.Errorf("waitForPrefixes: prefixes[%d] must be a string or object", i)
		}
		key, err := descriptorKey(eobj)
		if err != nil {
			return nil, fmt.Errorf("waitForPrefixes: prefixes[%d]: %w", i, err)
		}
		if v := eobj.Get("pathId"); !common.IsNullish(v) {
			id := uint32(v.ToInteger()) // #nosec G115 -- Path Identifier is a 4-octet field per RFC 7911 section 3
			key += ":" + strconv.FormatUint(uint64(id), 10)
		}
		out[i] = key
	}
	return out, nil
}

// splitPathID strips an optional RFC 7911 ":<path-id>" suffix off a
// prefix string and returns the bare prefix plus the canonicalized
// suffix (":<id>", or "" when absent). Only the ADD-PATH receive path
// keys the observed-set this way. The prefix length always follows the
// last '/', so a ':' after it can only start a path-id suffix — IPv6
// colons all precede the '/'.
func splitPathID(s string) (string, string, error) {
	slash := strings.LastIndexByte(s, '/')
	if slash < 0 {
		return s, "", nil // not a prefix; ParsePrefix reports it
	}
	colon := strings.IndexByte(s[slash+1:], ':')
	if colon < 0 {
		return s, "", nil
	}
	idStr := s[slash+1+colon+1:]
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		return "", "", fmt.Errorf("path id %q: %w", idStr, err)
	}
	return s[:slash+1+colon], ":" + strconv.FormatUint(id, 10), nil
}

// descriptorKey routes a JS route-descriptor object to the per-family
// canonicalizer that produces the gobgp NLRI.String() used as the
// observed-set key. The `type` discriminator selects between MUP and
// EVPN by value (MUP: isd/dsd/t1st/t2st, EVPN: mac-ip/imet/ip-prefix).
// L3VPN descriptors carry `rd` + `prefix` with no `type`.
func descriptorKey(obj *sobek.Object) (string, error) {
	if !common.IsNullish(obj.Get("type")) {
		ts := optString(obj, "type")
		switch ts {
		case packet.EVPNTypeMacIP, packet.EVPNTypeIMET, packet.EVPNTypeIPPrefix:
			return evpnDescriptorKey(obj)
		}
		return mupDescriptorKey(obj)
	}
	if !common.IsNullish(obj.Get("rd")) {
		return vpnDescriptorKey(obj)
	}
	return "", errors.New("descriptor must carry either `type` (MUP/EVPN) or `rd` (L3VPN)")
}

// evpnDescriptorKey turns an EVPN route descriptor into the canonical
// gobgp EVPNNLRI.String() form so waitForPrefixes can match against
// the receive observed-set.
func evpnDescriptorKey(obj *sobek.Object) (string, error) {
	r, err := parseEVPNRoute(obj)
	if err != nil {
		return "", err
	}
	er, ok := r.(packet.EVPNRoute)
	if !ok {
		return "", fmt.Errorf("internal: parseEVPNRoute returned %T", r)
	}
	return er.Key(), nil
}

// vpnDescriptorKey turns an L3VPN route descriptor into the canonical
// gobgp LabeledVPNIPAddrPrefix.String() form ("<rd>:<prefix>"). The
// family AFI is auto-derived from the prefix because the receive side
// keys by NLRI.String(), which never embeds the AFI/SAFI.
func vpnDescriptorKey(obj *sobek.Object) (string, error) {
	pref, err := requirePrefix(obj, "prefix")
	if err != nil {
		return "", err
	}
	family := gobgp.RF_IPv4_VPN
	if pref.Addr().Is6() && !pref.Addr().Is4In6() {
		family = gobgp.RF_IPv6_VPN
	}
	r, err := parseVPNIPRoute(family, obj)
	if err != nil {
		return "", err
	}
	vr, ok := r.(packet.VPNIPRoute)
	if !ok {
		return "", fmt.Errorf("internal: parseVPNIPRoute returned %T", r)
	}
	return vr.Key(), nil
}

// mupDescriptorKey turns a MUP route descriptor into the canonical
// gobgp NLRI.String() form, which is the key used by the receive side
// observed-set. The family AFI is auto-derived from the descriptor's
// contained prefix/address so JS callers do not need to repeat it.
func mupDescriptorKey(obj *sobek.Object) (string, error) {
	rt := optString(obj, "type")
	if rt == "" {
		return "", errors.New("mup descriptor missing type")
	}
	// Pick an arbitrary MUP family for construction; the resulting
	// NLRI.String() never embeds the AFI/SAFI, so it is family-agnostic
	// once we pass the per-type validation in the constructors.
	var family gobgp.Family
	switch rt {
	case packet.MUPTypeISD, packet.MUPTypeT1ST:
		p, err := requirePrefix(obj, "prefix")
		if err != nil {
			return "", err
		}
		family = mupFamilyForAddr(p.Addr())
	case packet.MUPTypeDSD:
		a, err := requireAddr(obj, "address")
		if err != nil {
			return "", err
		}
		family = mupFamilyForAddr(a)
	case packet.MUPTypeT2ST:
		a, err := requireAddr(obj, "endpoint")
		if err != nil {
			return "", err
		}
		family = mupFamilyForAddr(a)
	default:
		return "", fmt.Errorf("unknown mup route type %q", rt)
	}
	r, err := parseMUPRoute(family, obj)
	if err != nil {
		return "", err
	}
	mr, ok := r.(packet.MUPRoute)
	if !ok {
		return "", fmt.Errorf("internal: parseMUPRoute returned %T", r)
	}
	return mr.Key(), nil
}

func mupFamilyForAddr(a netip.Addr) gobgp.Family {
	if a.Is6() && !a.Is4In6() {
		return gobgp.RF_MUP_IPv6
	}
	return gobgp.RF_MUP_IPv4
}

func resultToJS(rt *sobek.Runtime, r peer.AdvertiseResult) sobek.Value {
	return rt.ToValue(map[string]any{
		"count":        r.Sent,
		"sentAtWallNs": r.SentAt.WallNs(),
		"sentAtMonoNs": r.SentAt.MonoNs(),
	})
}

func (p *Peer) parseAdvertiseArg(rt *sobek.Runtime, arg sobek.Value, withdraw bool) (peer.AdvertiseRequest, error) {
	if common.IsNullish(arg) {
		return peer.AdvertiseRequest{}, errors.New("missing argument")
	}
	obj := arg.ToObject(rt)
	if obj == nil {
		return peer.AdvertiseRequest{}, errors.New("argument must be an object")
	}

	famStr := optString(obj, "family")
	if famStr == "" {
		return peer.AdvertiseRequest{}, errors.New("family is required")
	}
	fam, ok := p.families[famStr]
	if !ok {
		return peer.AdvertiseRequest{}, fmt.Errorf("family %q was not advertised on this Peer", famStr)
	}

	var attrs packet.PathAttrs
	if !withdraw {
		nh := optString(obj, "nextHop")
		if nh == "" {
			return peer.AdvertiseRequest{}, errors.New("nextHop is required for advertise")
		}
		addr, err := netip.ParseAddr(nh)
		if err != nil {
			return peer.AdvertiseRequest{}, fmt.Errorf("nextHop: %w", err)
		}
		attrs.NextHop = addr
		attrs.LocalAS = optUint32(obj, "localAs")
		origin := optUint32(obj, "origin")
		if origin > 2 {
			return peer.AdvertiseRequest{}, fmt.Errorf("origin: must be 0 (IGP), 1 (EGP), or 2 (INCOMPLETE) per RFC 4271 section 5.1.1, got %d", origin)
		}
		attrs.Origin = uint8(origin) // #nosec G115 -- range checked above
		if v := obj.Get("med"); !common.IsNullish(v) {
			m := uint32(v.ToInteger()) // #nosec G115 -- MULTI_EXIT_DISC is a 4-octet field per RFC 4271 section 5.1.4
			attrs.MED = &m
		}
		if v := obj.Get("localPref"); !common.IsNullish(v) {
			lp := uint32(v.ToInteger()) // #nosec G115 -- LOCAL_PREF is a 4-octet field per RFC 4271 section 5.1.5
			attrs.LocalPref = &lp
		}
		if v := obj.Get("extCommunities"); !common.IsNullish(v) {
			ecs, err := parseExtCommunities(rt, v)
			if err != nil {
				return peer.AdvertiseRequest{}, fmt.Errorf("extCommunities: %w", err)
			}
			attrs.ExtCommunities = ecs
		}
		if v := obj.Get("srv6L3Service"); !common.IsNullish(v) {
			cfg, err := parseSRv6L3Service(rt, v)
			if err != nil {
				return peer.AdvertiseRequest{}, fmt.Errorf("srv6L3Service: %w", err)
			}
			attrs.SRv6L3Service = cfg
		}
		if v := obj.Get("pmsiTunnel"); !common.IsNullish(v) {
			cfg, err := parsePMSITunnel(rt, v)
			if err != nil {
				return peer.AdvertiseRequest{}, fmt.Errorf("pmsiTunnel: %w", err)
			}
			attrs.PMSITunnel = cfg
		}
	}

	routes, err := parseRoutesArray(rt, fam, obj.Get("routes"))
	if err != nil {
		return peer.AdvertiseRequest{}, err
	}

	var enc packet.EncodingOptions
	if v := obj.Get("useMpReach"); !common.IsNullish(v) {
		enc.UseMpReachForIPv4Unicast = v.ToBoolean()
	}
	if v := obj.Get("useExtendedMessages"); !common.IsNullish(v) {
		enc.UseExtendedMessages = v.ToBoolean()
	}

	var rate float64
	if v := obj.Get("updateRate"); !common.IsNullish(v) {
		rate = v.ToFloat()
	}

	return peer.AdvertiseRequest{Family: fam, Attrs: attrs, Routes: routes, Encoding: enc, UpdateRate: rate}, nil
}

// parseRoutesArray walks the sobek Array of routes element-by-element
// instead of routing it through Value.Export(). Export() would
// materialize a []any of len(arr) plus a Go string (or map[string]any)
// per element, which dominates the JS↔Go boundary cost when COUNT runs
// into the tens of thousands. Each element may be either a bare
// prefix string or an object with {prefix}. family selects which
// packet.Route constructor to use (currently IPv4/IPv6 unicast via
// packet.NewIPRoute); per-family dispatch grows here as new SAFIs land.
func parseRoutesArray(rt *sobek.Runtime, family gobgp.Family, v sobek.Value) ([]packet.Route, error) {
	if common.IsNullish(v) {
		return nil, errors.New("routes is required and must be a non-empty array")
	}
	arr := v.ToObject(rt)
	if arr == nil {
		return nil, errors.New("routes must be an array")
	}
	lenV := arr.Get("length")
	if common.IsNullish(lenV) {
		return nil, errors.New("routes must be an array")
	}
	n := int(lenV.ToInteger())
	if n <= 0 {
		return nil, errors.New("routes must be a non-empty array")
	}
	routes := make([]packet.Route, n)
	for i := range n {
		elem := arr.Get(strconv.Itoa(i))
		if elem == nil || common.IsNullish(elem) {
			return nil, fmt.Errorf("routes[%d]: nullish entry", i)
		}
		r, err := parseRoute(rt, family, elem)
		if err != nil {
			return nil, fmt.Errorf("routes[%d]: %w", i, err)
		}
		routes[i] = r
	}
	return routes, nil
}

// parseRoute converts one JS element into a packet.Route. For IP
// unicast families a bare prefix string or {prefix: "..."} object is
// accepted. For MUP families the element must be an object whose
// `type` discriminates the route type (isd/dsd/t1st/t2st); see
// parseMUPRoute. For L3VPN families the element must be an object
// carrying `{ rd, prefix }`; see parseVPNIPRoute.
func parseRoute(rt *sobek.Runtime, family gobgp.Family, elem sobek.Value) (packet.Route, error) {
	if isStringValue(elem) {
		switch {
		case family.Safi() == gobgp.SAFI_MUP:
			return nil, errors.New("mup route must be an object with a type field")
		case family.Safi() == gobgp.SAFI_MPLS_VPN:
			return nil, errors.New("l3vpn route must be an object with rd and prefix")
		case family == gobgp.RF_EVPN:
			return nil, errors.New("evpn route must be an object with a type field")
		}
		pref, err := netip.ParsePrefix(elem.String())
		if err != nil {
			return nil, err
		}
		return newRouteForFamily(family, pref)
	}

	eobj := elem.ToObject(rt)
	if eobj == nil {
		return nil, errors.New("expected string or object")
	}
	var r packet.Route
	var err error
	switch {
	case family.Safi() == gobgp.SAFI_MUP:
		r, err = parseMUPRoute(family, eobj)
	case family.Safi() == gobgp.SAFI_MPLS_VPN:
		r, err = parseVPNIPRoute(family, eobj)
	case family == gobgp.RF_EVPN:
		r, err = parseEVPNRoute(eobj)
	default:
		pv := eobj.Get("prefix")
		if common.IsNullish(pv) {
			return nil, errors.New("missing prefix")
		}
		var pref netip.Prefix
		pref, err = netip.ParsePrefix(pv.String())
		if err != nil {
			return nil, err
		}
		r, err = newRouteForFamily(family, pref)
	}
	if err != nil {
		return nil, err
	}
	if v := eobj.Get("pathId"); !common.IsNullish(v) {
		return packet.WithPathID(r, uint32(v.ToInteger())), nil // #nosec G115 -- Path Identifier is a 4-octet field per RFC 7911 section 3
	}
	return r, nil
}

// newRouteForFamily picks the packet.Route constructor for the family.
// Only IPv4/IPv6 unicast can be built from a bare prefix; MUP / VPN /
// EVPN require their own descriptor objects (see parseRoute).
func newRouteForFamily(family gobgp.Family, pref netip.Prefix) (packet.Route, error) {
	switch family {
	case gobgp.RF_IPv4_UC, gobgp.RF_IPv6_UC:
		return packet.NewIPRoute(family, pref)
	default:
		return nil, fmt.Errorf("family %s is not supported for prefix-only route input", family)
	}
}

// parseVPNIPRoute converts a JS L3VPN route descriptor into a
// packet.Route. Shape:
//
//	{ rd: '65000:1', prefix: '10.0.0.0/24' }
//
// The MPLS Label is fixed at 0 because the SRv6 SID is signalled via
// the Prefix-SID attribute (RFC 9252 section 4, no transposition).
func parseVPNIPRoute(family gobgp.Family, obj *sobek.Object) (packet.Route, error) {
	rd, err := parseRD(obj)
	if err != nil {
		return nil, err
	}
	pref, err := requirePrefix(obj, "prefix")
	if err != nil {
		return nil, err
	}
	return packet.NewVPNIPRoute(family, rd, pref)
}

// parseEVPNRoute converts a JS EVPN route descriptor into a
// packet.Route. The `type` discriminator selects the route format:
//
//	{ type: 'mac-ip',    rd, esi?, ethTag?, mac, ip?, labels:[..] }
//	{ type: 'imet',      rd, ethTag?, originIp }
//	{ type: 'ip-prefix', rd, esi?, ethTag?, prefix, gwIp?, label }
//
// labels / label are 24-bit values stuffed verbatim into the NLRI's
// MPLS Label field. The mapping to a transport (VXLAN VNI, MPLS
// label, …) is left to the caller per RFC 8365 section 5.
func parseEVPNRoute(obj *sobek.Object) (packet.Route, error) {
	rt := optString(obj, "type")
	if rt == "" {
		return nil, errors.New("missing type")
	}
	rd, err := parseRD(obj)
	if err != nil {
		return nil, err
	}
	ethTag := optUint32(obj, "ethTag")
	switch rt {
	case packet.EVPNTypeMacIP:
		esi, err := parseESI(obj)
		if err != nil {
			return nil, err
		}
		macStr := optString(obj, "mac")
		if macStr == "" {
			return nil, errors.New("missing mac")
		}
		mac, err := net.ParseMAC(macStr)
		if err != nil {
			return nil, fmt.Errorf("mac: %w", err)
		}
		var ip netip.Addr
		if v := obj.Get("ip"); !common.IsNullish(v) {
			ip, err = netip.ParseAddr(v.String())
			if err != nil {
				return nil, fmt.Errorf("ip: %w", err)
			}
		}
		labels, err := parseLabels(obj)
		if err != nil {
			return nil, err
		}
		return packet.NewEVPNMacIPRoute(rd, esi, ethTag, mac, ip, labels)
	case packet.EVPNTypeIMET:
		originIP, err := requireAddr(obj, "originIp")
		if err != nil {
			return nil, err
		}
		return packet.NewEVPNIMETRoute(rd, ethTag, originIP)
	case packet.EVPNTypeIPPrefix:
		esi, err := parseESI(obj)
		if err != nil {
			return nil, err
		}
		pref, err := requirePrefix(obj, "prefix")
		if err != nil {
			return nil, err
		}
		var gw netip.Addr
		if v := obj.Get("gwIp"); !common.IsNullish(v) {
			gw, err = netip.ParseAddr(v.String())
			if err != nil {
				return nil, fmt.Errorf("gwIp: %w", err)
			}
		}
		label := optUint32(obj, "label")
		return packet.NewEVPNIPPrefixRoute(rd, esi, ethTag, pref, gw, label)
	}
	return nil, fmt.Errorf("unknown evpn route type %q", rt)
}

// parseESI reads the optional `esi` field. Empty / missing /
// "single-homed" maps to the all-zero ESI. Multi-homed deployments
// pass a gobgp-style space-separated form (see packet.ParseESI).
func parseESI(obj *sobek.Object) (gobgp.EthernetSegmentIdentifier, error) {
	v := obj.Get("esi")
	if common.IsNullish(v) {
		return packet.ParseESI("")
	}
	esi, err := packet.ParseESI(v.String())
	if err != nil {
		return gobgp.EthernetSegmentIdentifier{}, fmt.Errorf("esi: %w", err)
	}
	return esi, nil
}

// parseLabels reads the `labels` array (preferred) or a single
// `label` scalar. Both are accepted so a caller advertising VXLAN
// VNIs can spell either form. The output is 1 or 2 entries.
func parseLabels(obj *sobek.Object) ([]uint32, error) {
	if v := obj.Get("labels"); !common.IsNullish(v) {
		exp, ok := v.Export().([]any)
		if !ok {
			return nil, errors.New("labels must be a number array")
		}
		if len(exp) == 0 || len(exp) > 2 {
			return nil, fmt.Errorf("labels must contain 1 or 2 entries (got %d)", len(exp))
		}
		out := make([]uint32, len(exp))
		for i, x := range exp {
			switch t := x.(type) {
			case int64:
				out[i] = uint32(t) // #nosec G115 -- 20-bit label; range checked by gobgp's labelSerialize
			case float64:
				out[i] = uint32(t) // #nosec G115 -- ditto
			default:
				return nil, fmt.Errorf("labels[%d]: expected number, got %T", i, x)
			}
		}
		return out, nil
	}
	if v := obj.Get("label"); !common.IsNullish(v) {
		return []uint32{uint32(v.ToInteger())}, nil // #nosec G115 -- 20-bit label
	}
	return nil, errors.New("missing label (or labels)")
}

// parseMUPRoute converts a JS MUP route descriptor into a packet.Route.
// Field shapes per draft-mpmz-bess-mup-safi-03 sections 3.1.1-3.1.4:
//
//	{ type: 'isd',  rd: '65000:1', prefix: '10.0.0.0/24' }
//	{ type: 'dsd',  rd: '65000:1', address: '10.0.0.1' }
//	{ type: 't1st', rd: '65000:1', prefix: '10.0.0.1/32', teid: '0.0.0.1', qfi: 9, endpoint: '10.0.0.1', source?: '10.0.0.99' }
//	{ type: 't2st', rd: '65000:1', endpoint: '10.0.0.1', endpointAddressLength: 64, teid: '0.0.0.1' }
func parseMUPRoute(family gobgp.Family, obj *sobek.Object) (packet.Route, error) {
	rt := optString(obj, "type")
	if rt == "" {
		return nil, errors.New("missing type")
	}
	rd, err := parseRD(obj)
	if err != nil {
		return nil, err
	}
	switch rt {
	case packet.MUPTypeISD:
		pref, err := requirePrefix(obj, "prefix")
		if err != nil {
			return nil, err
		}
		return packet.NewMUPInterworkSegmentDiscoveryRoute(family, rd, pref)
	case packet.MUPTypeDSD:
		addr, err := requireAddr(obj, "address")
		if err != nil {
			return nil, err
		}
		return packet.NewMUPDirectSegmentDiscoveryRoute(family, rd, addr)
	case packet.MUPTypeT1ST:
		pref, err := requirePrefix(obj, "prefix")
		if err != nil {
			return nil, err
		}
		teid, err := requireAddr(obj, "teid")
		if err != nil {
			return nil, err
		}
		endpoint, err := requireAddr(obj, "endpoint")
		if err != nil {
			return nil, err
		}
		var source *netip.Addr
		if v := obj.Get("source"); !common.IsNullish(v) {
			s, err := netip.ParseAddr(v.String())
			if err != nil {
				return nil, fmt.Errorf("source: %w", err)
			}
			source = &s
		}
		qfi := uint8(optUint32(obj, "qfi")) // #nosec G115 -- QFI is a 6-bit field carried in one octet per draft-mpmz-bess-mup-safi-03 section 3.1.3
		return packet.NewMUPType1SessionTransformedRoute(family, rd, pref, teid, qfi, endpoint, source)
	case packet.MUPTypeT2ST:
		endpoint, err := requireAddr(obj, "endpoint")
		if err != nil {
			return nil, err
		}
		teid, err := requireAddr(obj, "teid")
		if err != nil {
			return nil, err
		}
		eal := obj.Get("endpointAddressLength")
		if common.IsNullish(eal) {
			return nil, errors.New("missing endpointAddressLength")
		}
		return packet.NewMUPType2SessionTransformedRoute(family, rd, endpoint, uint8(eal.ToInteger()), teid) // #nosec G115 -- Endpoint Address Length is a 1-octet field per draft-mpmz-bess-mup-safi-03 section 3.1.4
	default:
		return nil, fmt.Errorf("unknown mup route type %q", rt)
	}
}

// parseExtCommunities turns a JS array of ext-community strings into
// gobgp ExtendedCommunityInterface values. Strings may carry an optional
// type prefix ("rt:65000:1" / "soo:65000:1"); a bare value
// ("65000:1") defaults to Route-Target so the common L3VPN case stays
// terse. Backed by gobgp's ParseExtendedCommunity (RFC 4360 / RFC 4364
// section 4.3.1).
func parseExtCommunities(rt *sobek.Runtime, v sobek.Value) ([]gobgp.ExtendedCommunityInterface, error) {
	arr := v.ToObject(rt)
	if arr == nil {
		return nil, errors.New("must be an array of strings")
	}
	lenV := arr.Get("length")
	if common.IsNullish(lenV) {
		return nil, errors.New("must be an array of strings")
	}
	n := int(lenV.ToInteger())
	if n <= 0 {
		return nil, errors.New("must be a non-empty array of strings")
	}
	out := make([]gobgp.ExtendedCommunityInterface, 0, n)
	for i := range n {
		elem := arr.Get(strconv.Itoa(i))
		if elem == nil || common.IsNullish(elem) {
			return nil, fmt.Errorf("[%d]: nullish entry", i)
		}
		s := elem.String()
		ec, err := parseExtCommunity(s)
		if err != nil {
			return nil, fmt.Errorf("[%d] %q: %w", i, s, err)
		}
		out = append(out, ec)
	}
	return out, nil
}

// parseExtCommunity converts a single ext-community shorthand into a
// gobgp ExtendedCommunityInterface. Supported prefixes:
//
//	rt:<asn:val|ip:val>          — Route-Target (RFC 4360 / RFC 4364)
//	soo:<asn:val|ip:val>         — Site-of-Origin (RFC 4360)
//	encap:<vxlan|mpls|geneve|…>  — Encapsulation EC (RFC 9012 / RFC 8365)
//	routermac:<MAC>              — EVPN Router's MAC EC (RFC 9135 § 9)
//
// A bare value without a recognized prefix defaults to Route-Target
// (the L3VPN-99%-case shorthand).
func parseExtCommunity(s string) (gobgp.ExtendedCommunityInterface, error) {
	idx := strings.Index(s, ":")
	if idx <= 0 {
		return gobgp.ParseExtendedCommunity(gobgp.EC_SUBTYPE_ROUTE_TARGET, s)
	}
	prefix := strings.ToLower(s[:idx])
	rest := s[idx+1:]
	switch prefix {
	case "rt":
		return gobgp.ParseExtendedCommunity(gobgp.EC_SUBTYPE_ROUTE_TARGET, rest)
	case "soo":
		return gobgp.ParseExtendedCommunity(gobgp.EC_SUBTYPE_ROUTE_ORIGIN, rest)
	case "encap":
		return gobgp.ParseExtendedCommunity(gobgp.EC_SUBTYPE_ENCAPSULATION, rest)
	case "routermac":
		mac, err := net.ParseMAC(rest)
		if err != nil {
			return nil, fmt.Errorf("routermac: %w", err)
		}
		return gobgp.NewRoutersMacExtended(mac.String()), nil
	}
	return gobgp.ParseExtendedCommunity(gobgp.EC_SUBTYPE_ROUTE_TARGET, s)
}

// parseSRv6L3Service builds the SRv6 L3 Service config from a JS object:
//
//	{
//	  sid:      'fc00:0:1::',
//	  behavior: 'END_DT4',          // or 'END_DT6' / 'END_DT46' / 'END_DX4' / 'END_DX6'
//	  structure?: {                  // SRv6 SID Structure Sub-Sub-TLV (RFC 9252 § 3.2.1)
//	    locatorBlockLength:  40,
//	    locatorNodeLength:   24,
//	    functionLength:      16,
//	    argumentLength:      0,
//	    transpositionLength: 0,
//	    transpositionOffset: 0,
//	  },
//	}
//
// `structure` defaults to (40, 24, 16, 0, 0, 0) — a common production
// shape with no transposition, matching the label=0 placeholder NLRI
// emitted by VPNIPRoute.
func parseSRv6L3Service(rt *sobek.Runtime, v sobek.Value) (*packet.SRv6L3ServiceConfig, error) {
	obj := v.ToObject(rt)
	if obj == nil {
		return nil, errors.New("must be an object")
	}
	sidStr := optString(obj, "sid")
	if sidStr == "" {
		return nil, errors.New("missing sid")
	}
	sid, err := netip.ParseAddr(sidStr)
	if err != nil {
		return nil, fmt.Errorf("sid: %w", err)
	}
	behStr := optString(obj, "behavior")
	if behStr == "" {
		return nil, errors.New("missing behavior")
	}
	beh, err := srBehaviorByName(behStr)
	if err != nil {
		return nil, err
	}
	cfg := &packet.SRv6L3ServiceConfig{
		SID:                 sid,
		EndpointBehavior:    beh,
		LocatorBlockLength:  40,
		LocatorNodeLength:   24,
		FunctionLength:      16,
		ArgumentLength:      0,
		TranspositionLength: 0,
		TranspositionOffset: 0,
	}
	if sv := obj.Get("structure"); !common.IsNullish(sv) {
		sobj := sv.ToObject(rt)
		if sobj == nil {
			return nil, errors.New("structure must be an object")
		}
		if v := sobj.Get("locatorBlockLength"); !common.IsNullish(v) {
			cfg.LocatorBlockLength = uint8(v.ToInteger()) // #nosec G115 -- LBL is a 1-octet field per RFC 9252 § 3.2.1
		}
		if v := sobj.Get("locatorNodeLength"); !common.IsNullish(v) {
			cfg.LocatorNodeLength = uint8(v.ToInteger()) // #nosec G115 -- LNL is a 1-octet field per RFC 9252 § 3.2.1
		}
		if v := sobj.Get("functionLength"); !common.IsNullish(v) {
			cfg.FunctionLength = uint8(v.ToInteger()) // #nosec G115 -- FL is a 1-octet field per RFC 9252 § 3.2.1
		}
		if v := sobj.Get("argumentLength"); !common.IsNullish(v) {
			cfg.ArgumentLength = uint8(v.ToInteger()) // #nosec G115 -- AL is a 1-octet field per RFC 9252 § 3.2.1
		}
		if v := sobj.Get("transpositionLength"); !common.IsNullish(v) {
			cfg.TranspositionLength = uint8(v.ToInteger()) // #nosec G115 -- TL is a 1-octet field per RFC 9252 § 3.2.1
		}
		if v := sobj.Get("transpositionOffset"); !common.IsNullish(v) {
			cfg.TranspositionOffset = uint8(v.ToInteger()) // #nosec G115 -- TO is a 1-octet field per RFC 9252 § 3.2.1
		}
	}
	if cfg.TranspositionLength != 0 {
		return nil, errors.New("transpositionLength must be 0 (xk6-bgp emits the SID in full; label=0)")
	}
	return cfg, nil
}

// parsePMSITunnel builds a PMSITunnelConfig from a JS object:
//
//	{
//	  tunnel:             6,                // PMSI Tunnel Type (RFC 6514 § 11) or string alias
//	  isLeafInfoRequired: false,
//	  label:              10100,             // 20-bit value placed in the 24-bit label field
//	  endpoint:           '10.0.0.1',        // tunnel-ID payload (e.g. Ingress-Repl egress PE)
//	}
//
// `tunnel` may also be one of the common name aliases:
// "no-tunnel-info", "rsvp-te-p2mp", "mldp-p2mp", "pim-ssm", "pim-sm",
// "bidir-pim", "ingress-repl", "mldp-mp2mp" — matching the IANA
// "P-Multicast Service Interface Tunnel Tunnel Types" registry.
func parsePMSITunnel(rt *sobek.Runtime, v sobek.Value) (*packet.PMSITunnelConfig, error) {
	obj := v.ToObject(rt)
	if obj == nil {
		return nil, errors.New("must be an object")
	}
	tv := obj.Get("tunnel")
	if common.IsNullish(tv) {
		return nil, errors.New("missing tunnel")
	}
	var tunnel uint8
	if isStringValue(tv) {
		t, err := pmsiTunnelByName(tv.String())
		if err != nil {
			return nil, err
		}
		tunnel = t
	} else {
		tunnel = uint8(tv.ToInteger()) // #nosec G115 -- PMSI Tunnel Type is a 1-octet field per RFC 6514 § 5
	}
	cfg := &packet.PMSITunnelConfig{
		Tunnel:             tunnel,
		IsLeafInfoRequired: optBool(obj, "isLeafInfoRequired"),
		Label:              optUint32(obj, "label"),
	}
	if ev := obj.Get("endpoint"); !common.IsNullish(ev) {
		ep, err := netip.ParseAddr(ev.String())
		if err != nil {
			return nil, fmt.Errorf("endpoint: %w", err)
		}
		cfg.Endpoint = ep
	}
	return cfg, nil
}

func pmsiTunnelByName(s string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "no-tunnel-info":
		return uint8(gobgp.PMSI_TUNNEL_TYPE_NO_TUNNEL), nil
	case "rsvp-te-p2mp":
		return uint8(gobgp.PMSI_TUNNEL_TYPE_RSVP_TE_P2MP), nil
	case "mldp-p2mp":
		return uint8(gobgp.PMSI_TUNNEL_TYPE_MLDP_P2MP), nil
	case "pim-ssm":
		return uint8(gobgp.PMSI_TUNNEL_TYPE_PIM_SSM_TREE), nil
	case "pim-sm":
		return uint8(gobgp.PMSI_TUNNEL_TYPE_PIM_SM_TREE), nil
	case "bidir-pim":
		return uint8(gobgp.PMSI_TUNNEL_TYPE_BIDIR_PIM_TREE), nil
	case "ingress-repl":
		return uint8(gobgp.PMSI_TUNNEL_TYPE_INGRESS_REPL), nil
	case "mldp-mp2mp":
		return uint8(gobgp.PMSI_TUNNEL_TYPE_MLDP_MP2MP), nil
	}
	return 0, fmt.Errorf("unknown pmsi tunnel type %q", s)
}

// srBehaviorByName maps the L3-VPN-relevant Endpoint Behavior names from
// the IANA SRv6 Endpoint Behaviors registry (RFC 8986) to gobgp's
// SRBehavior constants. We expose only the behaviors that make sense
// for a BGP L3VPN PE; other SRv6 functions live in different signalling
// paths.
func srBehaviorByName(s string) (gobgp.SRBehavior, error) {
	switch strings.ToUpper(s) {
	case "END_DT4":
		return gobgp.END_DT4, nil
	case "END_DT6":
		return gobgp.END_DT6, nil
	case "END_DT46":
		return gobgp.END_DT46, nil
	case "END_DX4":
		return gobgp.END_DX4, nil
	case "END_DX6":
		return gobgp.END_DX6, nil
	}
	return 0, fmt.Errorf("unknown endpoint behavior %q (supported: END_DT4, END_DT6, END_DT46, END_DX4, END_DX6)", s)
}

func parseRD(obj *sobek.Object) (gobgp.RouteDistinguisherInterface, error) {
	s := optString(obj, "rd")
	if s == "" {
		return nil, errors.New("missing rd")
	}
	rd, err := gobgp.ParseRouteDistinguisher(s)
	if err != nil {
		return nil, fmt.Errorf("rd: %w", err)
	}
	return rd, nil
}

func requirePrefix(obj *sobek.Object, key string) (netip.Prefix, error) {
	v := obj.Get(key)
	if common.IsNullish(v) {
		return netip.Prefix{}, fmt.Errorf("missing %s", key)
	}
	p, err := netip.ParsePrefix(v.String())
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%s: %w", key, err)
	}
	return p, nil
}

func requireAddr(obj *sobek.Object, key string) (netip.Addr, error) {
	v := obj.Get(key)
	if common.IsNullish(v) {
		return netip.Addr{}, fmt.Errorf("missing %s", key)
	}
	a, err := netip.ParseAddr(v.String())
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%s: %w", key, err)
	}
	return a, nil
}

// isStringValue reports whether v carries a JS string primitive
// (as opposed to an object/array). ExportType is cheaper than Export
// because it only inspects the value's type tag.
func isStringValue(v sobek.Value) bool {
	t := v.ExportType()
	return t != nil && t.Kind() == reflect.String
}

func optString(obj *sobek.Object, key string) string {
	v := obj.Get(key)
	if common.IsNullish(v) {
		return ""
	}
	return v.String()
}

func optUint32(obj *sobek.Object, key string) uint32 {
	v := obj.Get(key)
	if common.IsNullish(v) {
		return 0
	}
	return uint32(v.ToInteger()) // #nosec G115 -- callers cast into BGP-protocol-sized fields whose ranges are checked at the use site
}

func optInt64(obj *sobek.Object, key string) int64 {
	v := obj.Get(key)
	if common.IsNullish(v) {
		return 0
	}
	return v.ToInteger()
}

func optBool(obj *sobek.Object, key string) bool {
	v := obj.Get(key)
	if common.IsNullish(v) {
		return false
	}
	return v.ToBoolean()
}

// optDuration accepts a duration string (passed to k6's
// types.ParseExtendedDuration so "12d" etc. work), a seconds-number, or
// nullish (returns 0).
func optDuration(obj *sobek.Object, key string) (time.Duration, error) {
	return valueDuration(obj.Get(key))
}

func valueDuration(v sobek.Value) (time.Duration, error) {
	if common.IsNullish(v) {
		return 0, nil
	}
	switch t := v.Export().(type) {
	case string:
		return types.ParseExtendedDuration(t)
	case int64:
		return time.Duration(t) * time.Second, nil
	case float64:
		return time.Duration(t * float64(time.Second)), nil
	default:
		return 0, fmt.Errorf("expected duration string or seconds number, got %T", t)
	}
}
