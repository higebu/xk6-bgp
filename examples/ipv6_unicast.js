// xk6-bgp IPv6-unicast UPDATE delivery example.
//
// Mirrors examples/ipv4_unicast.js but exercises
// AFI=IPv6 / SAFI=unicast end to end:
//   - both Peers negotiate the ipv6-unicast family in OPEN
//   - sender pushes /128 advertisements with an IPv6 next-hop
//   - receiver waits for those prefixes and emits the four core
//     metrics (see internal/metrics/registry.go)
//
// The target speaker must re-advertise IPv6-unicast UPDATEs from the
// sender to the receiver — i.e. negotiate the ipv6-unicast family with
// both Peers. For local smokes, run fakebgpd with
// `-reflect -families ipv6-unicast` so it advertises ipv6-unicast in
// its OPEN and reflects every UPDATE between connected sessions.
//
// Run:
//   ./k6 run \
//     -e TARGET=[::1]:11790 -e PEER_AS=65000 \
//     -e SENDER_AS=65001 -e RECEIVER_AS=65002 -e COUNT=100 \
//     examples/ipv6_unicast.js

import bgp from 'k6/x/bgp';

const TARGET      = __ENV.TARGET      || '[::1]:11790';
const PEER_AS     = parseInt(__ENV.PEER_AS     || '65000', 10);
const SENDER_AS   = parseInt(__ENV.SENDER_AS   || '65001', 10);
const RECEIVER_AS = parseInt(__ENV.RECEIVER_AS || '65002', 10);
const COUNT       = parseInt(__ENV.COUNT       || '100',   10);
const TIMEOUT     = __ENV.TIMEOUT || '10s';

// IPv6 next-hop for sender's advertisements. Router-ID stays an IPv4
// 32-bit ID per RFC 4271; only the MP_REACH next-hop is IPv6.
const SENDER_NEXTHOP = __ENV.SENDER_NEXTHOP || '2001:db8::1';

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
    families: ['ipv6-unicast'],
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

function buildRoutes(n) {
  const out = [];
  for (let i = 0; i < n; i++) {
    const hi = (i >> 8) & 0xff;
    const lo = i & 0xff;
    out.push(`2001:db8:1:${hi.toString(16)}::${lo.toString(16)}/128`);
  }
  return out;
}

export default function () {
  const sender   = mkPeer('sender',   SENDER_AS,   '10.0.0.1');
  const receiver = mkPeer('receiver', RECEIVER_AS, '10.0.0.2');

  const recOpen = receiver.open();
  const sndOpen = sender.open();
  console.log(`session up: sender=${sndOpen.sessionUpUs}us receiver=${recOpen.sessionUpUs}us`);

  const routes = buildRoutes(COUNT);

  const adv = sender.advertise({
    family:  'ipv6-unicast',
    nextHop: SENDER_NEXTHOP,
    localAs: SENDER_AS,
    routes:  routes,
  });
  console.log(`advertised ${adv.count} routes`);

  let res;
  try {
    res = receiver.waitForPrefixes({
      prefixes:     routes,
      timeout:      TIMEOUT,
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
