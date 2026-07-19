// xk6-bgp RFC 7911 ADD-PATH delivery example.
//
// The sender advertises PATHS distinct paths (pathId 1..PATHS) for each
// of COUNT prefixes; the receiver waits for every (prefix, pathId)
// pair. Without ADD-PATH the target would collapse the paths into one
// best route per prefix — with it, each path is delivered and measured
// individually under the "<prefix>:<pathId>" key.
//
// The target must negotiate ADD-PATH in both directions (fakebgpd:
// run with -addpath -reflect; note reflection is a raw byte re-send,
// so every connected Peer must use the same addPath capabilities).
//
// Run:
//   ./fakebgpd -listen 127.0.0.1:11790 -reflect -addpath &
//   ./k6 run \
//     -e TARGET=127.0.0.1:11790 -e PEER_AS=65000 \
//     -e SENDER_AS=65001 -e RECEIVER_AS=65002 -e COUNT=100 -e PATHS=2 \
//     examples/ipv4_addpath.js

import bgp from 'k6/x/bgp';

const TARGET      = __ENV.TARGET      || '127.0.0.1:11790';
const PEER_AS     = parseInt(__ENV.PEER_AS     || '65000', 10);
const SENDER_AS   = parseInt(__ENV.SENDER_AS   || '65001', 10);
const RECEIVER_AS = parseInt(__ENV.RECEIVER_AS || '65002', 10);
const COUNT       = parseInt(__ENV.COUNT       || '100',   10);
const PATHS       = parseInt(__ENV.PATHS       || '2',     10);
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
      extendedMessage: true,
      routeRefresh:    true,
      addPath:         { 'ipv4-unicast': 'both' },
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
  const expected = [];
  for (let i = 0; i < COUNT; i++) {
    const prefix = `10.99.${(i >> 8) & 0xff}.${i & 0xff}/32`;
    for (let id = 1; id <= PATHS; id++) {
      routes.push({ prefix: prefix, pathId: id });
      expected.push(`${prefix}:${id}`);
    }
  }

  const adv = sender.advertise({
    family:  'ipv4-unicast',
    nextHop: '10.0.0.1',
    localAs: SENDER_AS,
    routes:  routes,
  });
  console.log(`advertised ${adv.count} paths (${COUNT} prefixes x ${PATHS})`);

  let res;
  try {
    res = receiver.waitForPrefixes({
      prefixes:     expected,
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
