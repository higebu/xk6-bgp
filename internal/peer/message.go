package peer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/higebu/xk6-bgp/internal/packet"
	"github.com/higebu/xk6-bgp/internal/timing"
)

// BuildOpen constructs an OPEN message ready to serialize. routerID must
// be an IPv4 address per RFC 4271. Local AS values > 0xffff are advertised
// via AS_TRANS in MyAS + the 4-octet AS capability per RFC 6793 section 9.
func BuildOpen(localAS uint32, holdTime time.Duration, routerID netip.Addr, caps packet.CapsConfig) (*bgp.BGPMessage, error) {
	if !routerID.Is4() {
		return nil, fmt.Errorf("routerId must be an IPv4 address, got %s", routerID)
	}

	myAS := uint16(localAS) // #nosec G115 -- AS values > 0xffff are masked to AS_TRANS immediately below per RFC 6793 section 9
	if localAS > 0xffff {
		myAS = bgp.AS_TRANS
	}

	if caps.FourOctetAS == 0 {
		caps.FourOctetAS = localAS
	}

	params, err := packet.BuildCapabilities(caps)
	if err != nil {
		return nil, err
	}

	hold := uint16(holdTime / time.Second) // #nosec G115 -- HoldTime is a 2-octet field per RFC 4271 section 4.2; values exceeding it are user misconfiguration
	open, err := bgp.NewBGPOpenMessage(myAS, hold, routerID, []bgp.OptionParameterInterface{
		bgp.NewOptionParameterCapability(params),
	})
	if err != nil {
		return nil, fmt.Errorf("NewBGPOpenMessage: %w", err)
	}
	return open, nil
}

func BuildKeepalive() *bgp.BGPMessage { return bgp.NewBGPKeepAliveMessage() }

func BuildNotification(code, subcode uint8, data []byte) *bgp.BGPMessage {
	return bgp.NewBGPNotificationMessage(code, subcode, data)
}

// ROUTE-REFRESH message subtypes. RFC 2918 section 3 defines the field
// as Reserved (0); RFC 7313 section 3 redefines it as the message
// subtype carrying the demarcations.
const (
	RouteRefreshNormal uint8 = 0 // RFC 2918 route refresh request
	RouteRefreshBoRR   uint8 = 1 // RFC 7313 Beginning of Route Refresh
	RouteRefreshEoRR   uint8 = 2 // RFC 7313 End of Route Refresh
)

// BuildRouteRefresh constructs a ROUTE-REFRESH message for the family.
// demarcation must be one of the RouteRefresh* subtypes; senders that
// only request a refresh use RouteRefreshNormal per RFC 2918.
func BuildRouteRefresh(family bgp.Family, demarcation uint8) *bgp.BGPMessage {
	return bgp.NewBGPRouteRefreshMessage(family.Afi(), demarcation, family.Safi())
}

// ReadMessage pulls one BGP message off r and returns both the raw
// header+body bytes and the parsed message. Enforces the RFC 4271
// 4096-byte cap on the message length; for sessions that negotiated
// RFC 8654 Extended Messages use ReadMessageMax with the higher cap.
// Callers that just want to re-emit can skip Serialize.
func ReadMessage(r io.Reader, options ...*bgp.MarshallingOption) ([]byte, *bgp.BGPMessage, error) {
	raw, msg, _, err := ReadMessageMax(r, bgp.BGP_MAX_MESSAGE_LENGTH, options...)
	return raw, msg, err
}

// ReadMessageMax is the variant of ReadMessage that bounds the
// allocated body buffer at maxLen bytes. Pass
// packet.BGPExtendedMaxMessageLength only after the RFC 8654 capability
// has been negotiated by both sides; otherwise a buggy or hostile peer
// could force the allocation of a 64 KiB read buffer per message.
// The returned Timestamp is captured right after the last byte of the
// message is read, before ParseBGPMessage — for a large UPDATE the
// parse cost must not leak into bgp_prefix_received_duration.
// options must carry the session's negotiated MarshallingOption when
// ADD-PATH receive or a 2-octet-AS peer is in play, otherwise the NLRI
// or AS_PATH bytes are misparsed.
func ReadMessageMax(r io.Reader, maxLen int, options ...*bgp.MarshallingOption) ([]byte, *bgp.BGPMessage, timing.Timestamp, error) {
	var hdr [bgp.BGP_HEADER_LENGTH]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, nil, timing.Timestamp{}, err
	}
	for i := range 16 {
		if hdr[i] != 0xff {
			return nil, nil, timing.Timestamp{}, errors.New("BGP header marker is not all-ones")
		}
	}
	mlen := int(binary.BigEndian.Uint16(hdr[16:18]))
	if mlen < bgp.BGP_HEADER_LENGTH {
		return nil, nil, timing.Timestamp{}, fmt.Errorf("BGP message length %d too small", mlen)
	}
	if mlen > maxLen {
		return nil, nil, timing.Timestamp{}, fmt.Errorf("BGP message length %d exceeds max %d", mlen, maxLen)
	}
	full := make([]byte, mlen)
	copy(full[:bgp.BGP_HEADER_LENGTH], hdr[:])
	if mlen > bgp.BGP_HEADER_LENGTH {
		if _, err := io.ReadFull(r, full[bgp.BGP_HEADER_LENGTH:]); err != nil {
			return nil, nil, timing.Timestamp{}, err
		}
	}
	ts := timing.Now()
	msg, err := bgp.ParseBGPMessage(full, options...)
	if err != nil {
		return full, nil, ts, err
	}
	return full, msg, ts, nil
}

// WriteMessage serializes msg and writes it as a single Write. The
// caller owns synchronization.
func WriteMessage(w io.Writer, msg *bgp.BGPMessage) error {
	buf, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("BGP serialize: %w", err)
	}
	_, err = w.Write(buf)
	return err
}
