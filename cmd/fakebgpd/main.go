// fakebgpd is a tiny stand-in BGP speaker used for xk6-bgp's E2E
// smokes. It listens on one address, completes OPEN/KEEPALIVE for every
// accepted connection, and (with -reflect) re-advertises every UPDATE
// it receives to all other connected sessions. That last part lets the
// delivery example talk to itself: a sender Peer + a receiver Peer
// both connect to fakebgpd, and the advertises show up on the receiver.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/higebu/xk6-bgp/internal/packet"
	xpeer "github.com/higebu/xk6-bgp/internal/peer"
)

type hub struct {
	mu      sync.Mutex
	clients map[*session]struct{}
}

func (h *hub) add(s *session) {
	h.mu.Lock()
	h.clients[s] = struct{}{}
	h.mu.Unlock()
}

func (h *hub) remove(s *session) {
	h.mu.Lock()
	delete(h.clients, s)
	h.mu.Unlock()
}

func (h *hub) broadcast(from *session, raw []byte) {
	h.mu.Lock()
	peers := make([]*session, 0, len(h.clients))
	for s := range h.clients {
		if s != from {
			peers = append(peers, s)
		}
	}
	h.mu.Unlock()
	for _, s := range peers {
		s.writeRaw(raw)
	}
}

type session struct {
	conn net.Conn
	wmu  sync.Mutex
}

func (s *session) writeRaw(b []byte) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, _ = s.conn.Write(b)
}

func main() {
	addr := flag.String("listen", "127.0.0.1:1790", "listen address")
	myAS := flag.Uint("as", 65000, "local AS")
	rid := flag.String("router-id", "10.0.0.2", "router-id")
	reflectMode := flag.Bool("reflect", false, "re-broadcast UPDATEs to all other connected sessions")
	famsFlag := flag.String("families", "ipv4-unicast", "comma-separated AFI/SAFI to advertise")
	addPath := flag.Bool("addpath", false, "advertise RFC 7911 ADD-PATH send/receive for all families")
	flag.Parse()

	families, err := parseFamilies(*famsFlag)
	if err != nil {
		log.Fatalf("--families: %v", err)
	}

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("fakebgpd listening on %s as AS %d families=%v reflectMode=%v addPath=%v",
		*addr, *myAS, *famsFlag, *reflectMode, *addPath)

	h := &hub{clients: map[*session]struct{}{}}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn, h, uint32(*myAS), *rid, families, *reflectMode, *addPath) // #nosec G115 -- AS values are bounded by RFC 6793; out-of-range is a CLI misuse, not a vulnerability
	}
}

func parseFamilies(s string) ([]bgp.Family, error) {
	parts := strings.Split(s, ",")
	out := make([]bgp.Family, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		f, err := packet.ResolveFamily(p)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one family is required")
	}
	return out, nil
}

func handleConn(conn net.Conn, h *hub, myAS uint32, rid string, families []bgp.Family, reflectMode, addPath bool) {
	defer conn.Close()
	log.Printf("accepted %s", conn.RemoteAddr())

	const holdTime = 90 * time.Second

	var peerOpen *bgp.BGPOpen
	if _, msg, err := xpeer.ReadMessage(conn); err != nil {
		log.Printf("%s: read OPEN: %v", conn.RemoteAddr(), err)
		return
	} else if po, ok := msg.Body.(*bgp.BGPOpen); ok {
		peerOpen = po
	} else {
		log.Printf("%s: expected OPEN, got %T", conn.RemoteAddr(), msg.Body)
		return
	}

	// RFC 4271 section 4.2: HoldTime is min(local, peer); 0 disables the
	// hold timer.
	localHold := uint16(holdTime / time.Second) // #nosec G115 -- holdTime is a fixed 90s constant, well within the 2-octet field
	negotiatedHold := time.Duration(min(localHold, peerOpen.HoldTime)) * time.Second

	caps := packet.CapsConfig{
		Families:        families,
		FourOctetAS:     myAS,
		RouteRefresh:    true,
		ExtendedMessage: true,
	}
	var rxOpts []*bgp.MarshallingOption
	if addPath {
		caps.AddPath = make(map[bgp.Family]bgp.BGPAddPathMode, len(families))
		for _, f := range families {
			caps.AddPath[f] = bgp.BGP_ADD_PATH_BOTH
		}
		if modes := addPathReceiveModes(peerOpen); len(modes) > 0 {
			rxOpts = []*bgp.MarshallingOption{{AddPath: modes}}
		}
	}

	open, err := xpeer.BuildOpen(myAS, holdTime, netip.MustParseAddr(rid), caps)
	if err != nil {
		log.Printf("%s: BuildOpen: %v", conn.RemoteAddr(), err)
		return
	}
	if err := xpeer.WriteMessage(conn, open); err != nil {
		log.Printf("%s: write OPEN: %v", conn.RemoteAddr(), err)
		return
	}

	// h.add MUST happen before the KA write: the peer transitions to
	// Established the moment it reads our KA, so any later advertise()
	// on another session would broadcast before this session is in the
	// hub. The window between the OPEN write and the KA write is the
	// safe place to publish — the peer is in OpenConfirm and will not
	// accept UPDATEs yet, so no broadcast can land mis-sequenced here.
	s := &session{conn: conn}
	h.add(s)
	defer h.remove(s)

	if err := xpeer.WriteMessage(conn, xpeer.BuildKeepalive()); err != nil {
		log.Printf("%s: write KA: %v", conn.RemoteAddr(), err)
		return
	}

	stopKA := make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopKA:
				return
			case <-ticker.C:
				ka, _ := xpeer.BuildKeepalive().Serialize()
				s.writeRaw(ka)
			}
		}
	}()
	defer close(stopKA)

	updates := 0
	for {
		if negotiatedHold > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(negotiatedHold))
		}
		raw, msg, err := xpeer.ReadMessage(conn, rxOpts...)
		if err != nil {
			log.Printf("%s: read: %v (UPDATEs=%d)", conn.RemoteAddr(), err, updates)
			return
		}
		switch m := msg.Body.(type) {
		case *bgp.BGPUpdate:
			updates++
			describeUpdate(conn.RemoteAddr(), updates, m)
			if reflectMode {
				h.broadcast(s, raw)
			}
		case *bgp.BGPKeepAlive:
		case *bgp.BGPNotification:
			log.Printf("%s: NOTIFICATION code=%d sub=%d", conn.RemoteAddr(), m.ErrorCode, m.ErrorSubcode)
			return
		}
	}
}

// addPathReceiveModes returns the per-family decode option for a
// client that advertised ADD-PATH send: inbound NLRI from it carry
// Path Identifiers, so fakebgpd must parse with receive enabled.
// Reflection is unaffected — the raw bytes are re-sent verbatim, which
// is only wire-correct when every connected client negotiated the same
// ADD-PATH families (run all example Peers with matching capabilities).
func addPathReceiveModes(open *bgp.BGPOpen) map[bgp.Family]bgp.BGPAddPathMode {
	var modes map[bgp.Family]bgp.BGPAddPathMode
	for _, p := range open.OptParams {
		ocp, ok := p.(*bgp.OptionParameterCapability)
		if !ok {
			continue
		}
		for _, c := range ocp.Capability {
			ap, ok := c.(*bgp.CapAddPath)
			if !ok {
				continue
			}
			for _, t := range ap.Tuples {
				if t.Mode&bgp.BGP_ADD_PATH_SEND == 0 {
					continue
				}
				if modes == nil {
					modes = map[bgp.Family]bgp.BGPAddPathMode{}
				}
				modes[t.Family] |= bgp.BGP_ADD_PATH_RECEIVE
			}
		}
	}
	return modes
}

func describeUpdate(remote net.Addr, n int, u *bgp.BGPUpdate) {
	advertised, withdrawn := len(u.NLRI), len(u.WithdrawnRoutes)
	for _, a := range u.PathAttributes {
		switch v := a.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			advertised += len(v.Value)
		case *bgp.PathAttributeMpUnreachNLRI:
			withdrawn += len(v.Value)
		}
	}
	if advertised == 0 && withdrawn == 0 {
		return
	}
	fmt.Printf("[%s] UPDATE#%d advertised=%d withdrawn=%d\n", remote, n, advertised, withdrawn)
}
