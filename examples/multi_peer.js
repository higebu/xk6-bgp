// xk6-bgp multi_peer: bgperf2-style many-peer bench.
//
// Spawns NUM_PEERS k6 VUs, each running its own sender / receiver Peer
// pair, and each VU advertises COUNT_PER_PEER prefixes that fall in its
// own slice of the address space. The DUT must re-advertise sender →
// receiver so each VU's receiver observes its own prefixes.
//
// Per-VU UPDATE delivery time is recorded in
// bgp_prefix_received_duration with a {peer: "vu-N"} tag, and the script
// logs each VU's duration_us as well. Aggregate the values across
// VUs to compare against bgperf2's "100 peers × 100 routes" scenario.
//
// AS / router-id assignment per VU. gobgpd's peer-group can only
// accept a single AS, so all sender VUs share one AS and identify
// themselves by router-id + source IP (loopback alias) — same for
// receivers. The DUT side just needs SENDER_LOCAL_PREFIX and
// RECEIVER_LOCAL_PREFIX to fall in two different dynamic-neighbor
// prefixes routed to two peer-groups.
//   sender   AS: SENDER_AS   (default 65001)
//   receiver AS: RECEIVER_AS (default 65002)
//   sender   Router-ID: 10.0.<floor(vu/256)>.<vu%256>
//   receiver Router-ID: 10.1.<floor(vu/256)>.<vu%256>
//
// IPv4 prefix slice per VU (default): 10.<vu>.<i/256>.<i%256>/32 for
// i in [0, COUNT_PER_PEER). IPv6: 2001:db8:<vu hex>:<i hex>::/64.

import bgp from 'k6/x/bgp';
import { sleep } from 'k6';

const TARGET           = __ENV.TARGET           || '127.0.0.1:11790';
const TARGET_SENDER    = __ENV.TARGET_SENDER    || TARGET;
const TARGET_RECEIVER  = __ENV.TARGET_RECEIVER  || TARGET;

const PEER_AS          = parseInt(__ENV.PEER_AS          || '65000', 10);
const PEER_AS_SENDER   = parseInt(__ENV.PEER_AS_SENDER   || String(PEER_AS), 10);
const PEER_AS_RECEIVER = parseInt(__ENV.PEER_AS_RECEIVER || String(PEER_AS), 10);
const SENDER_AS        = parseInt(__ENV.SENDER_AS        || '65001', 10);
const RECEIVER_AS      = parseInt(__ENV.RECEIVER_AS      || '65002', 10);

const FAMILY        = __ENV.FAMILY        || 'ipv4-unicast';
const NUM_PEERS     = parseInt(__ENV.NUM_PEERS     || '100', 10);
const COUNT_PER_PEER= parseInt(__ENV.COUNT_PER_PEER|| '100', 10);
const TIMEOUT       = __ENV.TIMEOUT       || '120s';
const USE_MP_REACH  = (__ENV.USE_MP_REACH  || '') === '1';
// ADVERTISE_UPDATE_RATE caps each Peer's UPDATE send rate at N
// messages per second. 0 (default) sends the chunked UPDATEs
// back-to-back. Positive values drip them out, which lets a
// many-peer DUT serialize lock acquisitions across peers instead
// of fighting for them all at once.
const UPDATE_RATE        = parseFloat(__ENV.ADVERTISE_UPDATE_RATE || '0');
// EXTENDED_MESSAGES=1 packs each UPDATE up to 65535 bytes per RFC 8654
// instead of the 4096-byte RFC 4271 ceiling. Both sides must have
// negotiated the capability (the Peer defaults advertise it).
const EXTENDED_MESSAGES  = (__ENV.EXTENDED_MESSAGES || '') === '1';
// WAIT_ALL_ESTABLISHED rendezvouses every VU through a shared
// `bgp.barrier` after both Peers in this VU are Established. Each VU
// arrives once, so the barrier count is NUM_PEERS even though every VU
// holds a sender and a receiver Peer. Advertises fire only after all
// NUM_PEERS VUs have both their sender and receiver up. Defaults to
// on — without it the 2*NUM_PEERS OPENs would hit the DUT in a burst
// that most BGP daemons cannot handle inside openTimeout. Set
// WAIT_ALL_ESTABLISHED=0 only to reproduce the legacy "racing burst"
// measurement.
const WAIT_ALL_ESTABLISHED = (__ENV.WAIT_ALL_ESTABLISHED || '1') === '1';

const SENDER_NEXTHOP_V4 = __ENV.SENDER_NEXTHOP_V4 || '10.99.0.99';
const SENDER_NEXTHOP_V6 = __ENV.SENDER_NEXTHOP_V6 || '2001:db8::99';

export const options = {
  scenarios: {
    parallel: {
      executor: 'per-vu-iterations',
      vus: NUM_PEERS,
      iterations: 1,
      maxDuration: '30m',
    },
  },
  thresholds: {
    bgp_prefix_received: [`count>=${NUM_PEERS * COUNT_PER_PEER}`],
    bgp_prefix_sent:     [`count>=${NUM_PEERS * COUNT_PER_PEER}`],
  },
};

function vuRouterId(prefix, vu) {
  const hi = Math.floor(vu / 256);
  const lo = vu % 256;
  return `${prefix}.${hi}.${lo}`;
}

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
      // 100 simultaneous OPENs queue inside the DUT — gobgpd in
      // particular serializes them well beyond the default 10 s
      // timeout. 5 minutes leaves room for very slow daemons.
      openTimeout: '5m',
    },
    capabilities: {
      extendedMessage: true,
      routeRefresh:    true,
    },
  });
}

// vu is 1..NUM_PEERS (max 254 to fit in the last IPv4 octet).
function vuLocalAddress(prefix, vu) {
  return `${prefix}.${vu}`;
}

function buildRoutes(vu, n) {
  const out = new Array(n);
  if (FAMILY === 'ipv6-unicast') {
    const vuHex = vu.toString(16);
    for (let i = 0; i < n; i++) {
      out[i] = `2001:db8:${vuHex}:${i.toString(16)}::/64`;
    }
  } else {
    const vuOct = vu & 0xff;
    for (let i = 0; i < n; i++) {
      out[i] = `10.${vuOct}.${(i >> 8) & 0xff}.${i & 0xff}/32`;
    }
  }
  return out;
}

export default function () {
  const vu = __VU;
  const senderRid   = vuRouterId('10.0', vu);
  const receiverRid = vuRouterId('10.1', vu);

  const senderLocal   = __ENV.SENDER_LOCAL_PREFIX
    ? vuLocalAddress(__ENV.SENDER_LOCAL_PREFIX, vu)   : '';
  const receiverLocal = __ENV.RECEIVER_LOCAL_PREFIX
    ? vuLocalAddress(__ENV.RECEIVER_LOCAL_PREFIX, vu) : '';

  const sender   = mkPeer('vu-' + vu + '-sender',
    SENDER_AS,   senderRid,   TARGET_SENDER,   PEER_AS_SENDER,   senderLocal);
  const receiver = mkPeer('vu-' + vu + '-receiver',
    RECEIVER_AS, receiverRid, TARGET_RECEIVER, PEER_AS_RECEIVER, receiverLocal);

  receiver.open();
  sender.open();

  if (WAIT_ALL_ESTABLISHED) {
    bgp.barrier('all-established', NUM_PEERS).arrive();
  }

  const routes = buildRoutes(vu, COUNT_PER_PEER);
  const adv = sender.advertise({
    family:              FAMILY,
    nextHop:             FAMILY === 'ipv6-unicast' ? SENDER_NEXTHOP_V6 : SENDER_NEXTHOP_V4,
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
  console.log(`vu=${vu} sent=${adv.count} matched=${res.matched} duration_us=${us} rate=${ratePerS} routes/s`);

  receiver.close();
  sender.close();

  sleep(parseFloat(__ENV.ITER_SLEEP || '0'));
}
