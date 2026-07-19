// xk6-bgp session_up: OPEN -> Established scalability bench.
//
// Spawns NUM_PEERS k6 VUs, each running a single bgp.Peer against the
// target. All VUs rendezvous through a shared barrier so their OPEN
// messages reach the DUT at roughly the same wall-clock time, then
// each VU records the per-peer OPEN -> Established latency in
// bgp_session_up (Trend, µs, pushed automatically by peer.open()).
// No advertise / withdraw is issued — this isolates the FSM startup
// path from any RIB / best-path work the DUT might do on UPDATE,
// which is what makes gobgpd / RustyBGP slow to converge at 1000
// peers.
//
// Read the result from the k6 summary; aggregating across VUs yields
// the p95 / max latency the slowest peer experienced under the open
// burst:
//   bgp_session_up..............: avg=... min=... med=... max=... p(95)=...
// k6's --summary-trend-stats="avg,min,med,max,p(90),p(95),p(99),count"
// exposes the tail percentiles useful for scale comparisons.
//
// Run:
//   ./k6 run \
//     -e TARGET=127.0.0.1:11790 -e PEER_AS=65000 -e LOCAL_AS=65001 \
//     -e NUM_PEERS=1000 \
//     examples/session_up.js

import bgp from 'k6/x/bgp';
import { sleep } from 'k6';

const TARGET    = __ENV.TARGET    || '127.0.0.1:11790';
const PEER_AS   = parseInt(__ENV.PEER_AS   || '65000', 10);
const LOCAL_AS  = parseInt(__ENV.LOCAL_AS  || '65001', 10);

const FAMILY    = __ENV.FAMILY    || 'ipv4-unicast';
const NUM_PEERS = parseInt(__ENV.NUM_PEERS || '100', 10);

// LOCAL_PREFIX, when set (e.g. "10.200.0"), binds each VU's BGP
// socket to a distinct source IP "<prefix>.<vu>" so the DUT sees
// distinct peers without needing dynamic-neighbor ranges per VU.
// Configure matching loopback aliases on the k6 host beforehand.
const LOCAL_PREFIX = __ENV.LOCAL_PREFIX || '';

// Upper bound on every barrier wait. Must exceed openTimeout, or slow
// (but successful) opens get cut off. Without it a single VU whose
// open() failed would leave every other VU blocked in arrive() until
// the scenario's maxDuration.
const BARRIER_TIMEOUT = __ENV.BARRIER_TIMEOUT || '6m';

export const options = {
  scenarios: {
    open: {
      executor: 'per-vu-iterations',
      vus: NUM_PEERS,
      iterations: 1,
      maxDuration: '30m',
    },
  },
};

function vuRouterId(vu) {
  const hi = Math.floor(vu / 256);
  const lo = vu % 256;
  return `10.0.${hi}.${lo}`;
}

function vuLocalAddress(prefix, vu) {
  return `${prefix}.${vu}`;
}

export default function () {
  const vu = __VU;
  const localAddress = LOCAL_PREFIX ? vuLocalAddress(LOCAL_PREFIX, vu) : '';

  const peer = new bgp.Peer({
    localAs:      LOCAL_AS,
    peerAs:       PEER_AS,
    routerId:     vuRouterId(vu),
    target:       TARGET,
    localAddress: localAddress,
    families:     [FAMILY],
    tags:         { peer: 'vu-' + vu },
    timers: {
      holdtime:    '90s',
      // 1000 simultaneous OPENs queue inside the DUT — gobgpd in
      // particular serializes them well beyond the default 10 s
      // openTimeout. 5 minutes leaves room for very slow daemons.
      openTimeout: '5m',
    },
    capabilities: {
      extendedMessage: true,
      routeRefresh:    true,
    },
  });

  // Rendezvous before open() so all VUs send their OPEN at roughly
  // the same wall-clock time. Without this barrier, k6 staggers VU
  // start by a few ms, letting early VUs reach Established before
  // later ones even dial — the resulting bgp_session_up
  // distribution would underestimate the open-burst load.
  bgp.barrier('pre-open', NUM_PEERS).arrive(BARRIER_TIMEOUT);

  let opened;
  try {
    opened = peer.open();
  } catch (e) {
    // Still arrive: a timed-out or failed open must not leave the
    // other VUs waiting on this VU's arrival.
    bgp.barrier('all-established', NUM_PEERS).arrive(BARRIER_TIMEOUT);
    throw e;
  }
  console.log(`vu=${vu} session_up_us=${opened.sessionUpUs}`); // µs from OpenSent to Established

  // Hold every session up until the last VU has finished open();
  // otherwise early-finishing VUs would FIN their TCP sockets while
  // the DUT is still processing late OPENs, perturbing both sides'
  // measurements.
  bgp.barrier('all-established', NUM_PEERS).arrive(BARRIER_TIMEOUT);

  peer.close();

  sleep(parseFloat(__ENV.ITER_SLEEP || '0'));
}
