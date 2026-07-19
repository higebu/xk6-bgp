// xk6-bgp EVPN (l2vpn-evpn) advertise / wait example.
//
// Sender advertises one route of each EVPN route type supported by
// xk6-bgp, Receiver waits for them to be reflected by the target.
// The target is expected to redistribute EVPN NLRIs between iBGP
// peers (route reflector, full-mesh iBGP, or eBGP with a permissive
// export policy).
//
// Route types:
//   mac-ip    — RFC 7432 §7.2 MAC/IP Advertisement
//   imet      — RFC 7432 §7.3 Inclusive Multicast Ethernet Tag
//   ip-prefix — RFC 9136 §3   IP Prefix
//
// xk6-bgp leaves the dataplane mapping (VXLAN VNI / MPLS / SRv6) to
// the caller — the values supplied for label, labels, and pmsiTunnel
// are placed on the wire verbatim per RFC 7432 / 8365 / 9136.
//
// Run:
//   ./k6 run \
//     -e TARGET=127.0.0.1:11790 -e PEER_AS=65000 \
//     -e SENDER_AS=65001 -e RECEIVER_AS=65002 \
//     examples/evpn.js

import bgp from 'k6/x/bgp';

const TARGET      = __ENV.TARGET      || '127.0.0.1:11790';
const PEER_AS     = parseInt(__ENV.PEER_AS     || '65000', 10);
const SENDER_AS   = parseInt(__ENV.SENDER_AS   || '65001', 10);
const RECEIVER_AS = parseInt(__ENV.RECEIVER_AS || '65002', 10);
const RD          = __ENV.RD          || '65000:1';
const RT          = __ENV.RT          || '65000:100';
const L2_LABEL    = parseInt(__ENV.L2_LABEL    || '10100', 10);
const L3_LABEL    = parseInt(__ENV.L3_LABEL    || '50100', 10);
const ENCAP       = __ENV.ENCAP       || 'vxlan';
const ORIGIN_IP   = __ENV.ORIGIN_IP   || '10.0.0.1';
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
    families: ['l2vpn-evpn'],
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
    // Type 2 (MAC/IP Advertisement) — labels[0] = L2 label.
    {
      type:   'mac-ip',
      rd:     RD,
      mac:    'aa:bb:cc:dd:ee:01',
      ip:     '10.1.1.1',
      labels: [L2_LABEL],
    },
    // Type 3 (Inclusive Multicast Ethernet Tag).
    {
      type:     'imet',
      rd:       RD,
      originIp: ORIGIN_IP,
    },
    // Type 5 (IP Prefix) — gwIp omitted, overlay index is the
    // router's MAC carried as a Router's MAC ext-community below.
    {
      type:   'ip-prefix',
      rd:     RD,
      prefix: '10.1.0.0/24',
      label:  L3_LABEL,
    },
  ];

  const adv = sender.advertise({
    family:         'l2vpn-evpn',
    nextHop:        '10.0.0.1',
    localAs:        SENDER_AS,
    extCommunities: [
      `rt:${RT}`,
      `encap:${ENCAP}`,
      'routermac:aa:bb:cc:dd:ee:99',
    ],
    pmsiTunnel: {
      tunnel:   'ingress-repl',
      label:    L2_LABEL,
      endpoint: ORIGIN_IP,
    },
    routes: routes,
  });
  console.log(`advertised ${adv.count} evpn routes`);

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
