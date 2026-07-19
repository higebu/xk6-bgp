// xk6-bgp MUP (ipv4-mup) advertise / wait example.
//
// Sender advertises one route of each MUP route type defined in
// draft-mpmz-bess-mup-safi-03 section 3.1, Receiver waits for them to
// be reflected by the target. The target is expected to redistribute
// MUP NLRIs between iBGP peers (route reflector, full-mesh iBGP, or
// eBGP with a permissive export policy).
//
// Route types:
//   isd  — Interwork Segment Discovery (RD + IP prefix)
//   dsd  — Direct Segment Discovery (RD + IP address)
//   t1st — Type 1 Session Transformed (RD + prefix + TEID + QFI + endpoint [+ source])
//   t2st — Type 2 Session Transformed (RD + endpoint + EAL + TEID)
//
// Run:
//   ./k6 run \
//     -e TARGET=127.0.0.1:11790 -e PEER_AS=65000 \
//     -e SENDER_AS=65001 -e RECEIVER_AS=65002 \
//     examples/mup.js

import bgp from 'k6/x/bgp';

const TARGET      = __ENV.TARGET      || '127.0.0.1:11790';
const PEER_AS     = parseInt(__ENV.PEER_AS     || '65000', 10);
const SENDER_AS   = parseInt(__ENV.SENDER_AS   || '65001', 10);
const RECEIVER_AS = parseInt(__ENV.RECEIVER_AS || '65002', 10);
const RD          = __ENV.RD          || '65000:1';
const TIMEOUT     = __ENV.TIMEOUT     || '10s';

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
    families: ['ipv4-mup'],
    tags:     { peer: role },
    timers: {
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

  const routes = [
    { type: 'isd',  rd: RD, prefix: '10.10.10.0/24' },
    { type: 'dsd',  rd: RD, address: '10.10.10.1' },
    { type: 't1st', rd: RD, prefix: '192.0.2.0/24', teid: '0.0.0.100', qfi: 9, endpoint: '10.10.10.1' },
    { type: 't2st', rd: RD, endpoint: '10.10.10.1', endpointAddressLength: 64, teid: '0.0.0.100' },
  ];

  const adv = sender.advertise({
    family:  'ipv4-mup',
    nextHop: '10.0.0.1',
    localAs: SENDER_AS,
    routes:  routes,
  });
  console.log(`advertised ${adv.count} mup routes`);

  try {
    const res = receiver.waitForPrefixes({
      prefixes:     routes,
      timeout:      TIMEOUT,
      sentAtMonoNs: adv.sentAtMonoNs,
    });
    const us = Math.round((res.lastSeenMonoNs - adv.sentAtMonoNs) / 1000);
    console.log(`received: matched=${res.matched} duration_us=${us}`);
  } catch (e) {
    console.error(`waitForPrefixes error: ${e}`);
  }

  receiver.close();
  sender.close();
}
