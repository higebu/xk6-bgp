// Package packet wraps gobgp's pkg/packet/bgp encoders behind plain
// Go values so the rest of xk6-bgp stays out of AFI/SAFI bit
// fiddling.
package packet

import (
	"errors"
	"fmt"
	"strings"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

type GRConfig struct {
	RestartTime  uint16 // seconds, max 0xfff
	Notification bool   // RFC 8538 N-bit
	Restarting   bool   // R-bit
}

type CapsConfig struct {
	Families        []bgp.Family
	FourOctetAS     uint32
	RouteRefresh    bool // RFC 2918
	ExtendedMessage bool // RFC 8654
	GracefulRestart *GRConfig
	EnhancedRefresh bool // RFC 7313
	// AddPath holds the per-family RFC 7911 Send/Receive value to
	// advertise (1 receive, 2 send, 3 both). Families absent from the
	// map do not appear in the ADD-PATH capability. Every key must also
	// be present in Families.
	AddPath map[bgp.Family]bgp.BGPAddPathMode
}

// BGPCapExtendedMessage is RFC 8654 capability code 6. gobgp v4 has no
// named constant for it, so we both emit and detect it by this code.
const BGPCapExtendedMessage bgp.BGPCapabilityCode = 6

// HasExtendedMessageCap reports whether caps contains an RFC 8654
// Extended Messages capability advertisement.
func HasExtendedMessageCap(caps []bgp.ParameterCapabilityInterface) bool {
	for _, c := range caps {
		if c.Code() == BGPCapExtendedMessage {
			return true
		}
	}
	return false
}

func BuildCapabilities(c CapsConfig) ([]bgp.ParameterCapabilityInterface, error) {
	if len(c.Families) == 0 {
		return nil, errors.New("at least one address family is required")
	}
	if c.FourOctetAS == 0 {
		return nil, errors.New("local AS must be > 0")
	}

	caps := []bgp.ParameterCapabilityInterface{}

	for _, f := range c.Families {
		caps = append(caps, bgp.NewCapMultiProtocol(f))
	}
	caps = append(caps, bgp.NewCapFourOctetASNumber(c.FourOctetAS))

	if c.RouteRefresh {
		caps = append(caps, bgp.NewCapRouteRefresh())
	}
	if c.EnhancedRefresh {
		caps = append(caps, bgp.NewCapEnhancedRouteRefresh())
	}
	if c.ExtendedMessage {
		caps = append(caps, &bgp.DefaultParameterCapability{
			CapCode: BGPCapExtendedMessage,
		})
	}
	if len(c.AddPath) > 0 {
		advertised := make(map[bgp.Family]struct{}, len(c.Families))
		for _, f := range c.Families {
			advertised[f] = struct{}{}
		}
		for f, m := range c.AddPath {
			if m < bgp.BGP_ADD_PATH_RECEIVE || m > bgp.BGP_ADD_PATH_BOTH {
				return nil, fmt.Errorf("addPath: invalid Send/Receive value %d for %s (RFC 7911 section 4 allows 1-3)", m, f)
			}
			if _, ok := advertised[f]; !ok {
				return nil, fmt.Errorf("addPath: family %s is not in the advertised families", f)
			}
		}
		// Iterate Families, not the map, so the tuple order in the
		// serialized capability is deterministic.
		tuples := make([]*bgp.CapAddPathTuple, 0, len(c.AddPath))
		for _, f := range c.Families {
			if m, ok := c.AddPath[f]; ok {
				tuples = append(tuples, bgp.NewCapAddPathTuple(f, m))
			}
		}
		caps = append(caps, bgp.NewCapAddPath(tuples))
	}
	if gr := c.GracefulRestart; gr != nil {
		tuples := make([]*bgp.CapGracefulRestartTuple, 0, len(c.Families))
		for _, f := range c.Families {
			tuples = append(tuples, bgp.NewCapGracefulRestartTuple(f, false))
		}
		caps = append(caps, bgp.NewCapGracefulRestart(gr.Restarting, gr.Notification, gr.RestartTime, tuples))
	}

	return caps, nil
}

// ResolveAddPathMode maps the user-facing mode names onto RFC 7911
// section 4 Send/Receive values.
func ResolveAddPathMode(name string) (bgp.BGPAddPathMode, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "receive":
		return bgp.BGP_ADD_PATH_RECEIVE, nil
	case "send":
		return bgp.BGP_ADD_PATH_SEND, nil
	case "both":
		return bgp.BGP_ADD_PATH_BOTH, nil
	}
	return 0, fmt.Errorf("unknown addPath mode %q (want receive, send, or both)", name)
}

func ResolveFamily(name string) (bgp.Family, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if f, ok := bgp.AddressFamilyValueMap[name]; ok {
		return f, nil
	}
	return 0, fmt.Errorf("unknown address family %q", name)
}
