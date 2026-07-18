package peer

import (
	"errors"
	"fmt"
	"time"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/higebu/xk6-bgp/internal/timing"
	"github.com/higebu/xk6-bgp/internal/packet"
)

type AdvertiseRequest struct {
	// Family is the AFI/SAFI the caller intends to advertise. Peer.Advertise
	// rejects routes whose Route.Family() does not match this value and
	// rejects families not negotiated on the session.
	Family   bgp.Family
	Attrs    packet.PathAttrs
	Routes   []packet.Route
	Encoding packet.EncodingOptions
	// UpdateRate caps the per-Peer UPDATE send rate at this many
	// messages per second. 0 (default) sends the chunked UPDATEs
	// back-to-back. Useful when a DUT struggles with the burst (many
	// peers fanning in to a shared best-path table) and a small drip
	// lets it keep up. Matches k6's constant-arrival-rate idiom
	// (`rate, timeUnit: '1s'`).
	UpdateRate float64
}

type WithdrawRequest struct {
	Family     bgp.Family
	Routes     []packet.Route
	Encoding   packet.EncodingOptions
	UpdateRate float64
}

type AdvertiseResult struct {
	Sent   int
	SentAt timing.Timestamp
}

// ErrExtendedMessagesNotNegotiated is returned by Advertise / Withdraw
// when the caller asks for RFC 8654 Extended Messages but the remote
// peer did not advertise capability 6 in OPEN. Sending an extended-size
// UPDATE in that state would force the peer to terminate the session
// with `Bad Message Length`.
var ErrExtendedMessagesNotNegotiated = errors.New("xk6-bgp: useExtendedMessages requires the peer to have advertised RFC 8654 capability 6")

// ErrAddPathNotNegotiated is returned by Advertise / Withdraw when a
// route carries an RFC 7911 Path Identifier but ADD-PATH send was not
// negotiated for the family — the peer would misparse the NLRI field
// if the 4-octet ID were emitted, and silently dropping the ID would
// collapse the caller's multiple paths into one.
var ErrAddPathNotNegotiated = errors.New("xk6-bgp: pathId requires the ADD-PATH send direction to be negotiated for the family (RFC 7911)")

func (p *Peer) Advertise(req AdvertiseRequest) (AdvertiseResult, error) {
	if p.fsm == nil || p.fsm.State() != StateEstablished {
		return AdvertiseResult{}, ErrSessionNotReady
	}
	if len(req.Routes) == 0 {
		return AdvertiseResult{}, errors.New("advertise: routes must be non-empty")
	}
	if err := validateRouteFamily(req.Family, req.Routes); err != nil {
		return AdvertiseResult{}, fmt.Errorf("advertise: %w", err)
	}
	if req.Encoding.UseExtendedMessages && !p.fsm.extendedMessagesNegotiated {
		return AdvertiseResult{}, ErrExtendedMessagesNotNegotiated
	}
	if err := p.fsm.validatePathIDs(req.Family, req.Routes); err != nil {
		return AdvertiseResult{}, fmt.Errorf("advertise: %w", err)
	}
	ts, sent, err := p.fsm.writeUpdates(false, req.Attrs, req.Routes, req.Encoding, req.UpdateRate)
	if err != nil {
		return AdvertiseResult{}, fmt.Errorf("advertise: %w", err)
	}
	return AdvertiseResult{Sent: sent, SentAt: ts}, nil
}

func (p *Peer) Withdraw(req WithdrawRequest) (AdvertiseResult, error) {
	if p.fsm == nil || p.fsm.State() != StateEstablished {
		return AdvertiseResult{}, ErrSessionNotReady
	}
	if len(req.Routes) == 0 {
		return AdvertiseResult{}, errors.New("withdraw: routes must be non-empty")
	}
	if err := validateRouteFamily(req.Family, req.Routes); err != nil {
		return AdvertiseResult{}, fmt.Errorf("withdraw: %w", err)
	}
	if req.Encoding.UseExtendedMessages && !p.fsm.extendedMessagesNegotiated {
		return AdvertiseResult{}, ErrExtendedMessagesNotNegotiated
	}
	if err := p.fsm.validatePathIDs(req.Family, req.Routes); err != nil {
		return AdvertiseResult{}, fmt.Errorf("withdraw: %w", err)
	}
	ts, sent, err := p.fsm.writeUpdates(true, packet.PathAttrs{}, req.Routes, req.Encoding, req.UpdateRate)
	if err != nil {
		return AdvertiseResult{}, fmt.Errorf("withdraw: %w", err)
	}
	return AdvertiseResult{Sent: sent, SentAt: ts}, nil
}

// validateRouteFamily checks that every Route belongs to the family the
// caller declared. The check is cheap (a single Family() call per
// route) and catches JS-side wiring mistakes before they reach the
// packet encoder, where the diagnostic would be more cryptic.
func validateRouteFamily(want bgp.Family, routes []packet.Route) error {
	for i, r := range routes {
		if r.Family() != want {
			return fmt.Errorf("routes[%d]: family %s does not match request family %s",
				i, r.Family(), want)
		}
	}
	return nil
}

// validatePathIDs rejects routes carrying an RFC 7911 Path Identifier
// when ADD-PATH send was not negotiated for the family. Routes without
// a pathId are always fine — with ADD-PATH active they go out with
// Path Identifier 0.
func (f *fsm) validatePathIDs(fam bgp.Family, routes []packet.Route) error {
	if f.addPathNegotiated[fam]&bgp.BGP_ADD_PATH_SEND != 0 {
		return nil
	}
	for i, r := range routes {
		if _, ok := r.(packet.PathIDRoute); ok {
			return fmt.Errorf("routes[%d]: %w", i, ErrAddPathNotNegotiated)
		}
	}
	return nil
}

// writeUpdates serializes routes into one or more UPDATE messages,
// each within BGP_MAX_MESSAGE_LENGTH, and writes them atomically with
// respect to other writers (the keepalive goroutine in particular).
// The family is derived from the routes themselves via Route.Family().
// SentAt is the timestamp captured immediately before the *first*
// Write — the "submitted to TCP" anchor for delivery math.
func (f *fsm) writeUpdates(withdraw bool, attrs packet.PathAttrs, routes []packet.Route, encoding packet.EncodingOptions, updateRate float64) (timing.Timestamp, int, error) {
	if len(routes) == 0 {
		return timing.Timestamp{}, 0, nil
	}
	// The negotiation outcome overrides whatever the caller put in the
	// encoding: ADD-PATH modes and the AS_PATH octet size are session
	// properties, not per-advertise choices.
	encoding.AddPath = f.addPathNegotiated
	encoding.Use2ByteAS = !f.fourOctetASNegotiated
	chunks, err := packet.ChunkRoutes(withdraw, attrs, routes, encoding)
	if err != nil {
		return timing.Timestamp{}, 0, err
	}

	var interval time.Duration
	if updateRate > 0 {
		interval = time.Duration(float64(time.Second) / updateRate)
	}

	var firstTs timing.Timestamp
	total := 0
	for i, chunk := range chunks {
		msg, err := packet.BuildUpdateMessage(withdraw, attrs, chunk, encoding)
		if err != nil {
			return firstTs, total, err
		}
		buf, err := packet.SerializeMessage(msg, encoding)
		if err != nil {
			return firstTs, total, fmt.Errorf("serialize: %w", err)
		}
		// Lock per chunk, not across the whole batch: messages are
		// atomic units, so a KEEPALIVE interleaving between two UPDATEs
		// is fine — and with a low updateRate the keepalive goroutine
		// must be able to grab writeMu during the drip, or the DUT's
		// hold timer expires mid-advertise.
		f.writeMu.Lock()
		ts := timing.Now()
		_, err = f.conn.Write(buf)
		f.writeMu.Unlock()
		if err != nil {
			return firstTs, total, fmt.Errorf("write: %w", err)
		}
		if firstTs.Time().IsZero() {
			firstTs = ts
		}
		total += len(chunk)
		if interval > 0 && i < len(chunks)-1 {
			time.Sleep(interval)
		}
	}
	return firstTs, total, nil
}
