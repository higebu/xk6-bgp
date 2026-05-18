// xk6-bgp SRv6 L3VPN advertise / wait example
// (RFC 9252 — BGP Overlay Services Based on Segment Routing over IPv6).
//
// Sender advertises L3VPN-IPv4 prefixes carrying:
//   - the RD + customer prefix in the LabeledVPNIPAddrPrefix NLRI
//     (MPLS Label field is 0; RFC 9252 §4 no-transposition mode)
//   - a Route-Target ext-community (RFC 4364 §4.3.1)
//   - a Prefix-SID attribute holding an SRv6 L3 Service TLV with the
//     End.DT4 SID for the VRF (RFC 9252 §3)
//
// Receiver waits for the same routes to be reflected by the target.
// The target must be configured as an SRv6-aware PE / route reflector
// that imports and re-advertises VPN routes for the supplied RT.
//
// Run:
//   ./k6 run \
//     -e TARGET=127.0.0.1:11790 -e PEER_AS=65000 \
//     -e SENDER_AS=65001 -e RECEIVER_AS=65002 -e COUNT=100 \
//     examples/srv6_l3vpn.js

import bgp from 'k6/x/bgp';

const TARGET      = __ENV.TARGET      || '127.0.0.1:11790';
const PEER_AS     = parseInt(__ENV.PEER_AS     || '65000', 10);
const SENDER_AS   = parseInt(__ENV.SENDER_AS   || '65001', 10);
const RECEIVER_AS = parseInt(__ENV.RECEIVER_AS || '65002', 10);
const COUNT       = parseInt(__ENV.COUNT       || '100',   10);
const RD          = __ENV.RD          || '65000:1';
const RT          = __ENV.RT          || '65000:100';
const SID         = __ENV.SID         || 'fc00:0:1::';
const BEHAVIOR    = __ENV.BEHAVIOR    || 'END_DT4';
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
    families: ['l3vpn-ipv4'],
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
    routes.push({
      rd:     RD,
      prefix: `10.99.${(i >> 8) & 0xff}.${i & 0xff}/32`,
    });
  }

  const adv = sender.advertise({
    family:         'l3vpn-ipv4',
    nextHop:        '10.0.0.1',
    localAs:        SENDER_AS,
    extCommunities: [`rt:${RT}`],
    srv6L3Service: {
      sid:      SID,
      behavior: BEHAVIOR,
      structure: {
        locatorBlockLength: 40,
        locatorNodeLength:  24,
        functionLength:     16,
        argumentLength:     0,
      },
    },
    routes: routes,
  });
  console.log(`advertised ${adv.count} srv6-l3vpn routes`);

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
