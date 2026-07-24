// xk6-bgp route refresh benchmark example.
//
// Topology (logical, no physical wiring required):
//
//   sender Peer  ──advertise──▶  Target BGP daemon  ──readvertise──▶  receiver Peer
//                                       │
//                                       │◀─ROUTE-REFRESH── receiver Peer
//                                       └──BoRR, Adj-RIB-Out replay, EoRR──▶
//
// After steady state (the receiver has seen every advertised prefix),
// the receiver sends a ROUTE-REFRESH (RFC 2918) and measures how long
// the target takes to finish its Adj-RIB-Out walk. With Enhanced Route
// Refresh (RFC 7313) negotiated, completion is demarcated by the
// target's EoRR — the RFC-exact refresh boundary — and emitted as
// bgp_route_refresh_duration.
//
// Without RFC 7313 on the target, drop `enhancedRouteRefresh`, skip
// waitForRouteRefreshEnd, and compose routeRefresh() with
// waitForPrefixes({ sentAtMonoNs: rr.sentAtMonoNs }) instead. Note the
// firstSeen-sticky cutoff: waitForPrefixes only re-matches prefixes the
// session observes anew after the refresh, so this fallback fits fresh
// sessions per iteration (as in this script), not long-lived ones.
//
// Metrics emitted (see internal/metrics/registry.go):
//   bgp_session_up               Trend  OPEN→Established µs for each Peer
//   bgp_prefix_received_duration Trend  T_tx(sender) → T_rx(receiver) µs
//   bgp_route_refresh_duration   Trend  T_tx(refresh) → T_rx(EoRR) µs
//   bgp_prefix_sent      Counter
//   bgp_prefix_received  Counter
//
// Run (against fakebgpd):
//   go run ./cmd/fakebgpd -listen 127.0.0.1:11790 -reflect &
//   ./k6 run \
//     -e TARGET=127.0.0.1:11790 -e PEER_AS=65000 \
//     -e SENDER_AS=65001 -e RECEIVER_AS=65002 -e COUNT=100 \
//     examples/route_refresh.js

import bgp from 'k6/x/bgp';

const TARGET      = __ENV.TARGET      || '127.0.0.1:11790';
const PEER_AS     = parseInt(__ENV.PEER_AS     || '65000', 10);
const SENDER_AS   = parseInt(__ENV.SENDER_AS   || '65001', 10);
const RECEIVER_AS = parseInt(__ENV.RECEIVER_AS || '65002', 10);
const COUNT       = parseInt(__ENV.COUNT       || '100',   10);
const TIMEOUT     = __ENV.TIMEOUT || '10s';

export const options = {
  iterations: 1,
  vus: 1,
};

function mkPeer(role, localAs, routerId) {
  return new bgp.Peer({
    localAs:  localAs,
    peerAs:   PEER_AS,
    routerId: routerId,
    target:   TARGET,
    families: ['ipv4-unicast'],
    tags:     { peer: role },
    timers: {
      holdtime:    '90s',
      openTimeout: '5s',
    },
    capabilities: {
      routeRefresh:         true,
      enhancedRouteRefresh: true,
    },
  });
}

export default function () {
  const sender   = mkPeer('sender',   SENDER_AS,   '10.0.0.1');
  const receiver = mkPeer('receiver', RECEIVER_AS, '10.0.0.2');

  receiver.open();
  sender.open();

  const routes = [];
  for (let i = 0; i < COUNT; i++) {
    routes.push(`10.99.${(i >> 8) & 0xff}.${i & 0xff}/32`);
  }

  const adv = sender.advertise({
    family:  'ipv4-unicast',
    nextHop: '10.0.0.1',
    localAs: SENDER_AS,
    routes:  routes,
  });

  try {
    // Steady state: the target has delivered every prefix once.
    receiver.waitForPrefixes({
      prefixes:     routes,
      timeout:      TIMEOUT,
      sentAtMonoNs: adv.sentAtMonoNs,
    });

    // Refresh: force the target to walk its Adj-RIB-Out again.
    const rr = receiver.routeRefresh({ family: 'ipv4-unicast' });
    const eorr = receiver.waitForRouteRefreshEnd({
      family:       'ipv4-unicast',
      timeout:      TIMEOUT,
      sentAtMonoNs: rr.sentAtMonoNs,
    });

    const us = Math.round((eorr.eorrMonoNs - rr.sentAtMonoNs) / 1000);
    const s = receiver.stats();
    console.log(`route refresh replay: duration_us=${us} borr=${s.borrReceived} eorr=${s.eorrReceived}`);
  } catch (e) {
    console.error(`route refresh scenario failed: ${e}`);
  } finally {
    receiver.close();
    sender.close();
  }
}
