// xk6-bgp throughput: BGP UPDATE delivery bench.
//
// One sender Peer pushes COUNT prefixes to the target BGP daemon in
// a single advertise(). A separate receiver Peer (which the target
// must readvertise to) measures the moment those prefixes land. The
// loop advertises, waits, and loops again for ITERATIONS times so
// the four core metrics show stable per-iteration values:
//
//   bgp_session_up            Trend  per Peer
//   bgp_prefix_received_duration    Trend  per iteration
//   bgp_prefix_sent       Counter
//   bgp_prefix_received   Counter
//
// Per-iteration throughput is derived as
//   bgp_prefix_sent / iteration_duration
// in post-processing (k6 prints rate-per-second for counters).
//
// Local smoke against fakebgpd (any AFI/SAFI just toggle FAMILY):
//   ./fakebgpd -listen 127.0.0.1:11790 -families ipv4-unicast -reflect &
//   ./k6 run -e TARGET=127.0.0.1:11790 -e COUNT=10000 \
//       examples/throughput.js
//
// Real-target bench (gobgpd as DUT, route reflector or eBGP with
// permissive export so the receiver sees advertisements back):
//   ./k6 run \
//     -e TARGET=10.0.0.99:179 -e PEER_AS=65000 \
//     -e SENDER_AS=65001 -e RECEIVER_AS=65002 \
//     -e COUNT=20000 -e ITERATIONS=5 -e TIMEOUT=60s \
//     examples/throughput.js
//
// Two-target real bench (split sender / receiver TCP endpoints, e.g.
// two gobgpd instances bridged by iBGP so the source IP is allowed
// to be the same on both ends):
//   ./k6 run \
//     -e TARGET_SENDER=127.0.0.1:1790 \
//     -e TARGET_RECEIVER=127.0.0.1:1791 \
//     -e PEER_AS=65000 -e SENDER_AS=65001 -e RECEIVER_AS=65002 \
//     -e COUNT=20000 -e ITERATIONS=5 \
//     examples/throughput.js
//
// One-target real bench, two source IPs (one BGP daemon, two peerings
// distinguished by source IP — loopback aliases or eno1 aliases). The
// daemon must re-advertise sender → receiver, which any normal eBGP
// setup with two external neighbors does by default:
//   ./k6 run \
//     -e TARGET=10.99.0.10:179 \
//     -e SENDER_LOCAL_ADDRESS=10.99.0.1 \
//     -e RECEIVER_LOCAL_ADDRESS=10.99.0.2 \
//     -e PEER_AS=65000 -e SENDER_AS=65001 -e RECEIVER_AS=65002 \
//     -e COUNT=20000 -e ITERATIONS=5 \
//     examples/throughput.js

import bgp from 'k6/x/bgp';
import { sleep } from 'k6';

const TARGET           = __ENV.TARGET           || '127.0.0.1:11790';
const TARGET_SENDER    = __ENV.TARGET_SENDER    || TARGET;
const TARGET_RECEIVER  = __ENV.TARGET_RECEIVER  || TARGET;
const PEER_AS          = parseInt(__ENV.PEER_AS          || '65000', 10);
const PEER_AS_SENDER   = parseInt(__ENV.PEER_AS_SENDER   || String(PEER_AS), 10);
const PEER_AS_RECEIVER = parseInt(__ENV.PEER_AS_RECEIVER || String(PEER_AS), 10);
const SENDER_AS   = parseInt(__ENV.SENDER_AS   || '65001', 10);
const RECEIVER_AS = parseInt(__ENV.RECEIVER_AS || '65002', 10);
const FAMILY      = __ENV.FAMILY      || 'ipv4-unicast';
const COUNT       = parseInt(__ENV.COUNT       || '10000', 10);
const ITERATIONS  = parseInt(__ENV.ITERATIONS  || '1', 10);
const TIMEOUT     = __ENV.TIMEOUT     || '30s';
const USE_MP_REACH = (__ENV.USE_MP_REACH || '') === '1';
// ADVERTISE_UPDATE_RATE caps each Peer's UPDATE send rate at N
// messages per second. 0 (default) sends back-to-back; positive
// values drip them out for DUTs that struggle with the burst.
const UPDATE_RATE = parseFloat(__ENV.ADVERTISE_UPDATE_RATE || '0');
const EXTENDED_MESSAGES = (__ENV.EXTENDED_MESSAGES || '') === '1';

const SENDER_NEXTHOP   = __ENV.SENDER_NEXTHOP   || (FAMILY === 'ipv6-unicast' ? '2001:db8::1' : '10.0.0.1');
const SENDER_ROUTER_ID = __ENV.SENDER_ROUTER_ID || '10.0.0.1';
const RECEIVER_ROUTER_ID = __ENV.RECEIVER_ROUTER_ID || '10.0.0.2';
const SENDER_LOCAL_ADDRESS   = __ENV.SENDER_LOCAL_ADDRESS   || '';
const RECEIVER_LOCAL_ADDRESS = __ENV.RECEIVER_LOCAL_ADDRESS || '';

// k6 binds VU lifecycle to scenario iterations; one VU running
// ITERATIONS shared iters reuses the same Peer pair across iters via
// setup/teardown only if we hoist them. To keep this script
// self-contained and easy to read, we tear sessions down per iter —
// the session-up cost is amortized by Trend percentiles, and the
// advertise/wait step is what we're profiling.
export const options = {
  scenarios: {
    bench: {
      executor: 'shared-iterations',
      vus: 1,
      iterations: ITERATIONS,
      maxDuration: '30m',
    },
  },
  thresholds: {
    // Fail the run if any iteration left prefixes un-converged.
    bgp_prefix_received: [`count>=${COUNT * ITERATIONS}`],
    bgp_prefix_sent:     [`count>=${COUNT * ITERATIONS}`],
  },
};

function mkPeer(role, localAs, routerId, target, peerAs, localAddress) {
  return new bgp.Peer({
    localAs:      localAs,
    peerAs:       peerAs,
    routerId:     routerId,
    target:       target,
    localAddress: localAddress,
    families:     [FAMILY],
    tags:         { peer: role },
    timers: {
      keepalive:   '30s',
      holdtime:    '90s',
      openTimeout: '10s',
    },
    capabilities: {
      extendedMessage: true,
      routeRefresh:    true,
    },
  });
}

function buildRoutes(n) {
  const out = new Array(n);
  if (FAMILY === 'ipv6-unicast') {
    for (let i = 0; i < n; i++) {
      const hi = (i >> 16) & 0xffff;
      const lo = i & 0xffff;
      out[i] = `2001:db8:1:${hi.toString(16)}::${lo.toString(16)}/128`;
    }
  } else {
    // 10.0.0.0/8 covers 16M /32s; this scales past any sane COUNT.
    for (let i = 0; i < n; i++) {
      out[i] = `10.${(i >> 16) & 0xff}.${(i >> 8) & 0xff}.${i & 0xff}/32`;
    }
  }
  return out;
}

export default function () {
  const sender   = mkPeer('sender',   SENDER_AS,   SENDER_ROUTER_ID,   TARGET_SENDER,   PEER_AS_SENDER,   SENDER_LOCAL_ADDRESS);
  const receiver = mkPeer('receiver', RECEIVER_AS, RECEIVER_ROUTER_ID, TARGET_RECEIVER, PEER_AS_RECEIVER, RECEIVER_LOCAL_ADDRESS);

  receiver.open();
  sender.open();

  try {
    const routes = buildRoutes(COUNT);
    const adv = sender.advertise({
      family:              FAMILY,
      nextHop:             SENDER_NEXTHOP,
      localAs:             SENDER_AS,
      routes:              routes,
      useMpReach:          USE_MP_REACH,
      useExtendedMessages: EXTENDED_MESSAGES,
      updateRate:          UPDATE_RATE,
    });

    const res = receiver.waitForPrefixes({
      prefixes:     routes,
      timeout:      TIMEOUT,
      sentAtMonoNs: adv.sentAtMonoNs,
    });
    const us = Math.round((res.lastSeenMonoNs - adv.sentAtMonoNs) / 1000);
    const ratePerS = us > 0 ? Math.round((res.matched * 1e6) / us) : 0;
    console.log(`iter sent=${adv.count} matched=${res.matched} duration_us=${us} rate=${ratePerS} routes/s`);
  } finally {
    // Close in a finally so a waitForPrefixes timeout does not leak
    // the sessions; the bgp_prefix_received threshold still fails the
    // run on missing prefixes.
    receiver.close();
    sender.close();
  }

  // Give the DUT time to fully tear down the previous TCP session
  // before the next iteration opens new peers from the same source IP;
  // some BGP daemons (gobgpd dynamic-neighbors in particular) RST a
  // new connection that arrives while the prior FSM is still cleaning
  // up. Tunable via ITER_SLEEP (seconds, default 2).
  sleep(parseFloat(__ENV.ITER_SLEEP || '2'));
}
