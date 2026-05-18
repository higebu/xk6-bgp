# SRv6 L3VPN SAFI

BGP/MPLS IP VPN ([RFC 4364](https://www.rfc-editor.org/rfc/rfc4364.txt))
carried over Segment Routing over IPv6
([RFC 9252](https://www.rfc-editor.org/rfc/rfc9252.txt)).

| Family string | gobgp constant | AFI | SAFI |
|---|---|---|---|
| `l3vpn-ipv4` | `RF_IPv4_VPN` | 1 | 128 |
| `l3vpn-ipv6` | `RF_IPv6_VPN` | 2 | 128 |

The NLRI on the wire is the classical `LabeledVPNIPAddrPrefix`. xk6-bgp
operates in RFC 9252 § 4 no-transposition mode: the MPLS Label field is
fixed at `0` and the SRv6 SID is signalled in full via the BGP
Prefix-SID attribute (SRv6 L3 Service TLV).

## Route descriptors

| Field | Required | Description |
|---|---|---|
| `rd` | yes | Route Distinguisher (any form gobgp parses: `asn:n`, `asn.asn:n`, `ipv4:n`) |
| `prefix` | yes | Customer prefix (IPv4 for `l3vpn-ipv4`, IPv6 for `l3vpn-ipv6`) |

## Required advertise options

L3VPN distribution needs both an import-side Route-Target ext-community
(RFC 4364 § 4.3.1) and the SRv6 service config. Every NLRI in one
UPDATE shares the same SID — the typical "one SID per VRF" PE pattern.

### `extCommunities`

`string[]` of EXTENDED_COMMUNITIES entries
([RFC 4360](https://www.rfc-editor.org/rfc/rfc4360.txt)). Each string
may carry an optional type prefix (`rt:` Route-Target, `soo:`
Site-of-Origin); a bare value defaults to Route-Target.

### `srv6L3Service`

| Field | Required | Default | Description |
|---|---|---|---|
| `sid` | yes | — | IPv6 SID address |
| `behavior` | yes | — | One of `END_DT4` / `END_DT6` / `END_DT46` / `END_DX4` / `END_DX6` ([RFC 8986](https://www.rfc-editor.org/rfc/rfc8986.txt) endpoint behaviors) |
| `structure.locatorBlockLength` | no | `40` | SID Structure Sub-Sub-TLV (RFC 9252 § 3.2.1) |
| `structure.locatorNodeLength` | no | `24` | |
| `structure.functionLength` | no | `16` | |
| `structure.argumentLength` | no | `0` | |
| `structure.transpositionLength` | no | `0` | Must stay `0` — xk6-bgp does not transpose SID bits into the label field |
| `structure.transpositionOffset` | no | `0` | |

## Example

See [`examples/srv6_l3vpn.js`](../examples/srv6_l3vpn.js) for a
runnable script.

```javascript
peer.advertise({
  family:         'l3vpn-ipv4',
  nextHop:        '10.0.0.1',
  localAs:        65001,
  extCommunities: ['rt:65000:100'],
  srv6L3Service: {
    sid:      'fc00:0:1::',
    behavior: 'END_DT4',
    structure: {
      locatorBlockLength: 40,
      locatorNodeLength:  24,
      functionLength:     16,
      argumentLength:     0,
    },
  },
  routes: [
    { rd: '65000:1', prefix: '10.99.0.0/24' },
  ],
});
```
