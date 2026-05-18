# MUP SAFI

3GPP-5G Mobile User-Plane SAFI per
[draft-mpmz-bess-mup-safi-03](https://datatracker.ietf.org/doc/draft-mpmz-bess-mup-safi/).

| Family string | gobgp constant | AFI | SAFI |
|---|---|---|---|
| `ipv4-mup` | `RF_MUP_IPv4` | 1 | 85 |
| `ipv6-mup` | `RF_MUP_IPv6` | 2 | 85 |

## Route descriptors

`routes` entries are objects with a `type` discriminator. The same
shape is shared between `advertise` / `withdraw` / `waitForPrefixes`.

| `type` | Required fields | Optional fields | Reference |
|---|---|---|---|
| `'isd'`  | `rd`, `prefix` | — | draft § 3.1.1 |
| `'dsd'`  | `rd`, `address` | — | draft § 3.1.2 |
| `'t1st'` | `rd`, `prefix`, `teid`, `qfi`, `endpoint` | `source` | draft § 3.1.3 |
| `'t2st'` | `rd`, `endpoint`, `endpointAddressLength`, `teid` | — | draft § 3.1.4 |

- `rd` accepts any RD form gobgp parses (`asn:n`, `asn.asn:n`, `ipv4:n`).
- `teid` is given as an IPv4-shaped dotted-quad to carry the 32-bit
  TEID (e.g. `'0.0.0.100'` for TEID 100).
- `endpointAddressLength` is the combined Endpoint Address + TEID bit
  length per the draft: 32..64 for IPv4 endpoints, 128..160 for IPv6.

## Example

See [`examples/mup.js`](../examples/mup.js) for a runnable script
covering all four route types.

```javascript
peer.advertise({
  family:  'ipv4-mup',
  nextHop: '10.0.0.1',
  localAs: 65001,
  routes: [
    { type: 'isd',  rd: '65000:1', prefix: '10.10.10.0/24' },
    { type: 'dsd',  rd: '65000:1', address: '10.10.10.1' },
    { type: 't1st', rd: '65000:1', prefix: '192.0.2.0/24',
      teid: '0.0.0.100', qfi: 9, endpoint: '10.10.10.1' },
    { type: 't2st', rd: '65000:1', endpoint: '10.10.10.1',
      endpointAddressLength: 64, teid: '0.0.0.100' },
  ],
});
```
