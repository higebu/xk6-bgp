// xk6-bgp IPv4-unicast smoke example.
//
// Drives one BGP/IPv4-unicast session and advertises a small batch of
// prefixes against a target speaker. The target is expected to be a
// gobgpd / FRR / RustyBGP instance listening on TARGET, configured as
// a passive neighbor for AS 65001 from this script's source IP.
//
// Run:
//   ./k6 run -e TARGET=10.131.18.41:179 -e PEER_AS=65000 \
//       examples/smoke.js
//
// Optional environment variables:
//   LOCAL_AS  (default 65001)
//   ROUTER_ID (default 10.0.0.1)
//   COUNT     (default 5)

import bgp from 'k6/x/bgp';
import { sleep } from 'k6';

const TARGET    = __ENV.TARGET    || '127.0.0.1:179';
const LOCAL_AS  = parseInt(__ENV.LOCAL_AS  || '65001', 10);
const PEER_AS   = parseInt(__ENV.PEER_AS   || '65000', 10);
const ROUTER_ID = __ENV.ROUTER_ID || '10.0.0.1';
const COUNT     = parseInt(__ENV.COUNT     || '5', 10);

export const options = {
  iterations: 1,
  vus: 1,
};

export default function () {
  const peer = new bgp.Peer({
    localAs:  LOCAL_AS,
    peerAs:   PEER_AS,
    routerId: ROUTER_ID,
    target:   TARGET,
    families: ['ipv4-unicast'],
    timers: {
      holdtime:    '90s',
      openTimeout: '5s',
    },
    capabilities: {
      extendedMessage:      true,
      routeRefresh:         true,
      enhancedRouteRefresh: false,
      gracefulRestart:      { restartTime: 120, notification: true },
    },
  });

  const opened = peer.open();
  console.log('session up: state=' + peer.state + ' session_up=' + opened.sessionUpUs + 'us');

  const routes = [];
  for (let i = 0; i < COUNT; i++) {
    routes.push('10.99.' + i + '.0/24');
  }
  const adv = peer.advertise({
    family:  'ipv4-unicast',
    nextHop: ROUTER_ID,
    localAs: LOCAL_AS,
    routes:  routes,
  });
  console.log('advertised ' + adv.count + ' routes at wall=' + adv.sentAtWallNs);

  // Hold the session briefly so the target installs the routes before the
  // withdraw goes out. See ipv4_unicast.js for the deterministic
  // waitForPrefixes-based variant.
  sleep(2);

  const wd = peer.withdraw({
    family: 'ipv4-unicast',
    routes: routes,
  });
  console.log('withdrew ' + wd.count + ' routes at wall=' + wd.sentAtWallNs);

  peer.close();
}
