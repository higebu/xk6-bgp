# EVPN SAFI

BGP MPLS-Based Ethernet VPN
([RFC 7432](https://www.rfc-editor.org/rfc/rfc7432.txt)) with the IP
Prefix Advertisement extension
([RFC 9136](https://www.rfc-editor.org/rfc/rfc9136.txt)). xk6-bgp
supports Type 2 (MAC/IP Advertisement), Type 3 (Inclusive Multicast
Ethernet Tag) and Type 5 (IP Prefix) routes.

| Family string | gobgp constant | AFI | SAFI |
|---|---|---|---|
| `l2vpn-evpn` | `RF_EVPN` | 25 | 70 |

The MPLS label fields in the NLRI are passed through verbatim — xk6-bgp
does not assume a particular dataplane encapsulation. To drive
EVPN/VXLAN ([RFC 8365](https://www.rfc-editor.org/rfc/rfc8365.txt))
place the VNI in `label` / `labels`; for EVPN/MPLS use the MPLS label;
for EVPN/SRv6 ([RFC 9251](https://www.rfc-editor.org/rfc/rfc9251.txt))
leave it `0` and attach the SRv6 service TLV through `srv6L3Service`
on Type 5.

## Route descriptors

`routes` entries are objects with a `type` discriminator. The same
shape is shared between `advertise` / `withdraw` / `waitForPrefixes`.

| `type` | Required | Optional | Reference |
|---|---|---|---|
| `'mac-ip'`    | `rd`, `mac`, `label` or `labels` | `esi`, `ethTag`, `ip` | RFC 7432 § 7.2 |
| `'imet'`      | `rd`, `originIp` | `ethTag` | RFC 7432 § 7.3 |
| `'ip-prefix'` | `rd`, `prefix`, `label` | `esi`, `ethTag`, `gwIp` | RFC 9136 § 3 |

### Common fields

- `rd` accepts any RD form gobgp parses (`asn:n`, `asn.asn:n`, `ipv4:n`).
- `ethTag` is the 4-octet Ethernet Tag ID; defaults to `0`.
- `esi` is the 10-octet Ethernet Segment Identifier in gobgp's
  space-separated text form. `""`, `"single-homed"` (or omitting the
  field) selects the all-zero ESI. Multi-homed deployments use one of:
  `"lacp <MAC> <port-key>"`, `"mstp <MAC> <bridge-priority>"`,
  `"mac <MAC> <local-disc>"`, `"routerid <IPv4> <local-disc>"`,
  `"as <ASN> <local-disc>"`, or
  `"arbitrary <9-byte-colon-hex>"`.

### Type 2 — MAC/IP Advertisement

- `mac` is the EUI-48 in any form `net.ParseMAC` accepts
  (`"aa:bb:cc:dd:ee:01"`).
- `ip` is optional; omit it (or pass an empty value) for a MAC-only
  advertisement (IP Address Length = 0 on the wire per RFC 7432 § 7.2).
- `label` / `labels` carries the 24-bit MPLS Label1 (and optional
  Label2 when sending two labels). `label: <n>` is shorthand for
  `labels: [<n>]`.

### Type 3 — Inclusive Multicast Ethernet Tag

- `originIp` is the Originating Router's IP Address (IPv4 or IPv6).
- For BUM replication, pair Type 3 with the
  [`pmsiTunnel`](#pmsi-tunnel) advertise option (see below).

### Type 5 — IP Prefix

- `prefix` is the customer IP prefix (IPv4 or IPv6); the gateway IP's
  family is derived from the prefix.
- `gwIp` is the Overlay Index gateway IP. Omit for the
  family-appropriate unspecified address — the typical case where the
  overlay index is signalled through a Router's MAC EC instead
  (RFC 9136 § 3.1).
- `label` is the 24-bit MPLS Label.

## Path attributes

### `extCommunities`

EVPN reuses the standard ext-community syntax (`rt:` / `soo:`); two
extra prefixes are recognized:

- `encap:<vxlan|mpls|geneve|nvgre|gre|...>` — Encapsulation EC
  ([RFC 9012](https://www.rfc-editor.org/rfc/rfc9012.txt)). Often
  paired with EVPN to advertise the dataplane in use
  ([RFC 8365 § 6](https://www.rfc-editor.org/rfc/rfc8365.txt)).
- `routermac:<MAC>` — EVPN Router's MAC EC ([RFC 9135 § 9](https://www.rfc-editor.org/rfc/rfc9135.txt)).
  Required on Type 5 when the gateway IP is unspecified and the
  overlay index is the router's MAC.

### `pmsiTunnel`

PMSI Tunnel attribute ([RFC 6514 § 5](https://www.rfc-editor.org/rfc/rfc6514.txt))
typically attached to Type 3 routes to signal how BUM traffic is
replicated.

| Field | Required | Description |
|---|---|---|
| `tunnel` | yes | PMSI Tunnel Type. Accepts a number (IANA value) or one of the aliases `'no-tunnel-info'`, `'rsvp-te-p2mp'`, `'mldp-p2mp'`, `'pim-ssm'`, `'pim-sm'`, `'bidir-pim'`, `'ingress-repl'`, `'mldp-mp2mp'` |
| `label` | no | 20-bit MPLS Label (default `0`) |
| `endpoint` | for `ingress-repl` | Tunnel endpoint IP. For Ingress Replication this is the egress endpoint per RFC 7432 § 11.1 / RFC 8365 § 5.1.3 |
| `isLeafInfoRequired` | no | Leaf-Info-Required flag (RFC 6514 § 5) |

## Example

See [`examples/evpn.js`](../examples/evpn.js) for a runnable script
that covers all three route types.

```javascript
peer.advertise({
  family:         'l2vpn-evpn',
  nextHop:        '10.0.0.1',
  localAs:        65001,
  extCommunities: ['rt:65000:100', 'encap:vxlan'],
  pmsiTunnel: {
    tunnel:   'ingress-repl',
    label:    10100,
    endpoint: '10.0.0.1',
  },
  routes: [
    { type: 'mac-ip',    rd: '65000:1', mac: 'aa:bb:cc:dd:ee:01',
      ip: '10.1.1.1', labels: [10100] },
    { type: 'imet',      rd: '65000:1', originIp: '10.0.0.1' },
    { type: 'ip-prefix', rd: '65000:1', prefix: '10.1.0.0/24',
      label: 50100 },
  ],
});
```
