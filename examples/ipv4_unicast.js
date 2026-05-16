// xk6-bgp basic UPDATE delivery example.
//
// Topology (logical, no physical wiring required):
//
//   sender Peer  ──advertise──▶  Target BGP daemon  ──readvertise──▶  receiver Peer
//                                       │
//                                       └ Loc-RIB → ADJ-RIB-Out
//
// The script runs entirely from a single k6 VU. Both Peers are
// instances of `bgp.Peer` connected to the same target. The target
// must be configured so that advertisements from the sender are
// re-advertised to the receiver (route reflector, full-mesh iBGP,
// or eBGP with a permissive export policy).
//
// Metrics emitted (see internal/metrics/registry.go):
//   bgp_session_up            Trend  OPEN→Established µs for each Peer
//   bgp_prefix_received_duration    Trend  T_tx(sender) → T_rx(receiver) µs
//   bgp_prefix_sent       Counter
//   bgp_prefix_received   Counter
//
// Run:
//   ./k6 run \
//     -e TARGET=127.0.0.1:11790 -e PEER_AS=65000 \
//     -e SENDER_AS=65001 -e RECEIVER_AS=65002 -e COUNT=100 \
//     examples/ipv4_unicast.js

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
      keepalive:   '30s',
      holdtime:    '90s',
      openTimeout: '5s',
    },
    capabilities: {
      extendedMessage: true,
      routeRefresh:    true,
    },
  });
}

export default function () {
  const sender   = mkPeer('sender',   SENDER_AS,   '10.0.0.1');
  const receiver = mkPeer('receiver', RECEIVER_AS, '10.0.0.2');

  const recOpen = receiver.open();
  const sndOpen = sender.open();
  console.log(`session up: sender=${sndOpen.sessionUpUs}us receiver=${recOpen.sessionUpUs}us`);

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
  console.log(`advertised ${adv.count} routes`);

  let res;
  try {
    res = receiver.waitForPrefixes({
      prefixes:    routes,
      timeout:     TIMEOUT,
      sentAtMonoNs: adv.sentAtMonoNs,
    });
  } catch (e) {
    console.error(`waitForPrefixes error: ${e}`);
    receiver.close();
    sender.close();
    return;
  }

  const us = Math.round((res.lastSeenMonoNs - adv.sentAtMonoNs) / 1000);
  console.log(`received: matched=${res.matched} duration_us=${us}`);

  receiver.close();
  sender.close();
}
