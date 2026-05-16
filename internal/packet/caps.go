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
	if gr := c.GracefulRestart; gr != nil {
		tuples := make([]*bgp.CapGracefulRestartTuple, 0, len(c.Families))
		for _, f := range c.Families {
			tuples = append(tuples, bgp.NewCapGracefulRestartTuple(f, false))
		}
		caps = append(caps, bgp.NewCapGracefulRestart(gr.Restarting, gr.Notification, gr.RestartTime, tuples))
	}

	return caps, nil
}

func ResolveFamily(name string) (bgp.Family, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if f, ok := bgp.AddressFamilyValueMap[name]; ok {
		return f, nil
	}
	return 0, fmt.Errorf("unknown address family %q", name)
}
