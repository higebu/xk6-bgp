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

	xpeer "github.com/higebu/xk6-bgp/internal/peer"
	"github.com/higebu/xk6-bgp/internal/packet"
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
	flag.Parse()

	families, err := parseFamilies(*famsFlag)
	if err != nil {
		log.Fatalf("--families: %v", err)
	}

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("fakebgpd listening on %s as AS %d families=%v reflectMode=%v",
		*addr, *myAS, *famsFlag, *reflectMode)

	h := &hub{clients: map[*session]struct{}{}}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleConn(conn, h, uint32(*myAS), *rid, families, *reflectMode) // #nosec G115 -- AS values are bounded by RFC 6793; out-of-range is a CLI misuse, not a vulnerability
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

func handleConn(conn net.Conn, h *hub, myAS uint32, rid string, families []bgp.Family, reflectMode bool) {
	defer conn.Close()
	log.Printf("accepted %s", conn.RemoteAddr())

	if _, msg, err := xpeer.ReadMessage(conn); err != nil {
		log.Printf("%s: read OPEN: %v", conn.RemoteAddr(), err)
		return
	} else if _, ok := msg.Body.(*bgp.BGPOpen); !ok {
		log.Printf("%s: expected OPEN, got %T", conn.RemoteAddr(), msg.Body)
		return
	}

	open, err := xpeer.BuildOpen(myAS, 90*time.Second, netip.MustParseAddr(rid), packet.CapsConfig{
		Families:        families,
		FourOctetAS:     myAS,
		RouteRefresh:    true,
		ExtendedMessage: true,
	})
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
		raw, msg, err := xpeer.ReadMessage(conn)
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

func describeUpdate(remote net.Addr, n int, u *bgp.BGPUpdate) {
	advertised, withdrawn := 0, 0
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
