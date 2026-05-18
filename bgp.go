package bgp

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
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
		if cfg.Timers.Keepalive, err = optDuration(tobj, "keepalive"); err != nil {
			return cfg, nil, fmt.Errorf("timers.keepalive: %w", err)
		}
		if cfg.Timers.HoldTime, err = optDuration(tobj, "holdtime"); err != nil {
			return cfg, nil, fmt.Errorf("timers.holdtime: %w", err)
		}
		if cfg.Timers.ConnectRetry, err = optDuration(tobj, "connectRetry"); err != nil {
			return cfg, nil, fmt.Errorf("timers.connectRetry: %w", err)
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
// each entry through netip so non-canonical IPv6 input (e.g.
// "2001:0db8::/32") matches the observed-set keys, which use the
// canonical form gobgp NLRI.String() emits. Like parseRoutesArray,
// this walks the sobek Array directly to avoid the []any allocation
// Value.Export() would do.
func parsePrefixList(rt *sobek.Runtime, obj *sobek.Object) ([]string, error) {
	pv := obj.Get("prefixes")
	if common.IsNullish(pv) {
		return nil, errors.New("waitForPrefixes: prefixes is required")
	}
	arr := pv.ToObject(rt)
	if arr == nil {
		return nil, errors.New("waitForPrefixes: prefixes must be an array of strings")
	}
	lenV := arr.Get("length")
	if common.IsNullish(lenV) {
		return nil, errors.New("waitForPrefixes: prefixes must be an array of strings")
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
		if !isStringValue(elem) {
			return nil, fmt.Errorf("waitForPrefixes: prefixes[%d] must be a string", i)
		}
		pref, err := netip.ParsePrefix(elem.String())
		if err != nil {
			return nil, fmt.Errorf("waitForPrefixes: prefixes[%d]: %w", i, err)
		}
		out[i] = pref.String()
	}
	return out, nil
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
		attrs.Origin = uint8(optUint32(obj, "origin")) // #nosec G115 -- ORIGIN is one of {0,1,2} per RFC 4271 section 5.1.1
		if v := obj.Get("med"); !common.IsNullish(v) {
			m := uint32(v.ToInteger()) // #nosec G115 -- MULTI_EXIT_DISC is a 4-octet field per RFC 4271 section 5.1.4
			attrs.MED = &m
		}
		if v := obj.Get("localPref"); !common.IsNullish(v) {
			lp := uint32(v.ToInteger()) // #nosec G115 -- LOCAL_PREF is a 4-octet field per RFC 4271 section 5.1.5
			attrs.LocalPref = &lp
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

// parseRoute converts one JS element into a packet.Route. Bare prefix
// strings and {prefix: "..."} objects are both accepted. The family
// argument selects the per-SAFI constructor; for IPv4/IPv6 unicast it
// routes to packet.NewIPRoute.
func parseRoute(rt *sobek.Runtime, family gobgp.Family, elem sobek.Value) (packet.Route, error) {
	if isStringValue(elem) {
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
	pv := eobj.Get("prefix")
	if common.IsNullish(pv) {
		return nil, errors.New("missing prefix")
	}
	pref, err := netip.ParsePrefix(pv.String())
	if err != nil {
		return nil, err
	}
	return newRouteForFamily(family, pref)
}

// newRouteForFamily picks the packet.Route constructor for the family.
// Only IPv4/IPv6 unicast are wired today; add new cases when adding a
// SAFI (MUP, VPN, EVPN, ...).
func newRouteForFamily(family gobgp.Family, pref netip.Prefix) (packet.Route, error) {
	switch family {
	case gobgp.RF_IPv4_UC, gobgp.RF_IPv6_UC:
		return packet.NewIPRoute(family, pref)
	default:
		return nil, fmt.Errorf("family %s is not supported for prefix-only route input", family)
	}
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
	v := obj.Get(key)
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
