# xk6-bgp

[![CI](https://github.com/higebu/xk6-bgp/actions/workflows/ci.yml/badge.svg)](https://github.com/higebu/xk6-bgp/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/higebu/xk6-bgp.svg)](https://pkg.go.dev/github.com/higebu/xk6-bgp)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**k6 extension for BGP benchmarking**

**xk6-bgp** drives real BGP sessions against a target BGP daemon
(FRR, GoBGP, RustyBGP, …). Establish sessions, advertise and withdraw
prefixes, and measure how fast the daemon delivers UPDATEs
end-to-end — all from a k6 script.

## Example

A minimal UPDATE delivery scenario: one Peer advertises prefixes,
another Peer (which the DUT reflects to) waits for them and emits
`bgp_prefix_received_duration`.

```javascript
import bgp from 'k6/x/bgp';

export const options = { vus: 1, iterations: 1 };

export default function () {
  const sender = new bgp.Peer({
    localAs:  65001,
    peerAs:   65000,
    routerId: '10.0.0.1',
    target:   __ENV.TARGET,
    families: ['ipv4-unicast'],
    tags:     { peer: 'sender' },
  });
  const receiver = new bgp.Peer({
    localAs:  65002,
    peerAs:   65000,
    routerId: '10.0.0.2',
    target:   __ENV.TARGET,
    families: ['ipv4-unicast'],
    tags:     { peer: 'receiver' },
  });

  receiver.open();
  sender.open();

  const routes = [];
  for (let i = 0; i < 1000; i++) routes.push(`10.99.${i >> 8}.${i & 0xff}/32`);

  const adv = sender.advertise({
    family:  'ipv4-unicast',
    nextHop: '10.0.0.1',
    localAs: 65001,
    routes,
  });

  try {
    const res = receiver.waitForPrefixes({
      prefixes:     routes,
      timeout:      '10s',
      sentAtMonoNs: adv.sentAtMonoNs,
    });
    console.log(`received: matched=${res.matched}`);
  } catch (e) {
    console.error(`waitForPrefixes: ${e}`);
  }

  receiver.close();
  sender.close();
}
```

```sh
./k6 run -e TARGET=10.0.0.99:179 examples/ipv4_unicast.js
```

## Examples

The [examples](./examples/) directory contains scripts demonstrating
various scenarios:

- [`smoke.js`](./examples/smoke.js) — minimal one-peer advertise/withdraw smoke test
- [`ipv4_unicast.js`](./examples/ipv4_unicast.js) — IPv4-unicast UPDATE delivery between two Peers
- [`ipv6_unicast.js`](./examples/ipv6_unicast.js) — IPv6-unicast variant
- [`mup.js`](./examples/mup.js) — `ipv4-mup` advertise of all four MUP route types
- [`throughput.js`](./examples/throughput.js) — single-peer advertise throughput sweep over `COUNT` prefixes
- [`multi_peer.js`](./examples/multi_peer.js) — many-peer benchmark
- [`session_up.js`](./examples/session_up.js) — `OPEN → Established` scaling under many concurrent peers

For local smoke without a real BGP daemon, see
[`cmd/fakebgpd`](./cmd/fakebgpd) — a minimal reflector bundled for
end-to-end tests.

## Session lifecycle

Each `Peer` represents one BGP session over TCP/179. A typical flow:

- `peer.open()` — TCP-connect, send OPEN, exchange capabilities, reach
  `Established`. Returns `{ sessionUpUs }` with the `OpenSent →
  Established` duration in microseconds, the same value pushed to the
  `bgp_session_up` metric.
- `peer.advertise({...})` / `peer.withdraw({...})` — send MP_REACH /
  MP_UNREACH UPDATEs (auto-chunked to fit `BGP_MAX_MESSAGE_LENGTH`, or
  the RFC 8654 ceiling when both sides negotiated Extended Messages).
- `peer.waitForPrefixes({...})` — block until the expected prefixes
  arrive on this Peer or the timeout fires (throws on timeout).
- `peer.close()` — send Cease NOTIFICATION and tear the session down.

A `Peer` is single-use. Calling `open()` again after `close()` throws
`"Peer is single-use; construct a new bgp.Peer to reconnect"`.
Construct a new `bgp.Peer` instance per iteration when you need a
fresh session.

## Capabilities

Negotiated by default in OPEN:

- MP-BGP for the declared `families`
- Extended Messages ([RFC 8654](https://www.rfc-editor.org/rfc/rfc8654.txt))
- Route Refresh ([RFC 2918](https://www.rfc-editor.org/rfc/rfc2918.txt))
- Graceful Restart with N-bit ([RFC 4724](https://www.rfc-editor.org/rfc/rfc4724.txt) + [RFC 8538](https://www.rfc-editor.org/rfc/rfc8538.txt))
- 4-octet AS ([RFC 6793](https://www.rfc-editor.org/rfc/rfc6793.txt))

## API

The JS API is synchronous: each Peer method blocks the calling VU
until the underlying I/O completes. BGP benchmark scripts run
sequentially per VU (open → advertise → wait → close), so this matches
the natural shape of every example here. k6 runs each VU on its own
goroutine, so blocking in one VU does not block others.

### `new bgp.Peer(config)`

| Field | Type | Default | Description |
|---|---|---|---|
| `localAs` | number | — | Local AS number (required) |
| `peerAs` | number | — | Remote AS number (required; `0` accepts any AS) |
| `routerId` | string | — | Router-ID in dotted-quad form (required) |
| `target` | string | — | `host:port` of the BGP speaker (required) |
| `families` | string[] | — | AFI/SAFI list, e.g. `['ipv4-unicast', 'ipv6-unicast']` (required) |
| `localAddress` | string | unset | Source IP for the outbound TCP connection; used by `throughput.js` / `multi_peer.js` to drive many sessions from distinct loopback aliases |
| `timers` | object | defaults | `{ keepalive, holdtime, connectRetry, openTimeout }` as k6 duration strings |
| `capabilities` | object | defaults on | Per-capability overrides: `{ extendedMessage, routeRefresh, enhancedRouteRefresh, gracefulRestart }` |
| `tags` | object | unset | Key-value pairs added to every metric this Peer emits. `tags.peer` becomes the `peer` label |

### Methods

| Method | Returns | Description |
|---|---|---|
| `peer.open()` | `{ sessionUpUs }` | TCP-connect and run the OPEN/KEEPALIVE handshake; resolves on `Established` |
| `peer.advertise(opts)` | `{ count, sentAtWallNs, sentAtMonoNs }` | Send MP_REACH UPDATEs |
| `peer.withdraw(opts)` | `{ count, sentAtWallNs, sentAtMonoNs }` | Send MP_UNREACH UPDATEs |
| `peer.waitForPrefixes(opts)` | `{ matched, missing, firstSeenWallNs, firstSeenMonoNs, lastSeenWallNs, lastSeenMonoNs }` | Block until all `opts.prefixes` are observed; throws on timeout |
| `peer.close()` | — | Send Cease NOTIFICATION and close the session |

### Properties

| Property | Type | Description |
|---|---|---|
| `peer.state` | string | Current FSM state: `Idle`, `Active`, `OpenSent`, `OpenConfirm`, or `Established` |

### `advertise` / `withdraw` options

| Field | Type | Description |
|---|---|---|
| `family` | string | AFI/SAFI declared in `peer.families` (required) |
| `nextHop` | string | IPv4 or IPv6 next-hop (required for `advertise`) |
| `localAs` | number | AS_PATH origin AS (required for `advertise`) |
| `routes` | string[] \| object[] | For `ipv4-unicast` / `ipv6-unicast`: prefixes (e.g. `['10.0.0.0/24']`) or `{ prefix }` objects. For `ipv4-mup` / `ipv6-mup`: route descriptors keyed by `type` (see [MUP routes](#mup-routes)) (required) |
| `origin` | number | ORIGIN attribute: `0` IGP, `1` EGP, `2` INCOMPLETE (`advertise` only, default `0`) |
| `med` | number | MULTI_EXIT_DISC (`advertise` only) |
| `localPref` | number | LOCAL_PREF for iBGP (`advertise` only) |
| `useMpReach` | boolean | Force IPv4-unicast through `MP_REACH_NLRI` instead of the UPDATE NLRI field |
| `useExtendedMessages` | boolean | Chunk UPDATEs up to the RFC 8654 65535-byte limit. The peer **must** have advertised capability 6 — `advertise`/`withdraw` returns an error otherwise (see [Capabilities](#capabilities)) |
| `updateRate` | number | Cap the per-Peer UPDATE send rate at this many messages per second (`0` = unlimited) |

### `waitForPrefixes` options

| Field | Type | Description |
|---|---|---|
| `prefixes` | (string \| object)[] | Expected route set: prefix strings for IP unicast or MUP descriptor objects (same shape as `advertise.routes`) (required) |
| `timeout` | string \| number | k6 duration string or seconds; throws if not met before this |
| `sentAtMonoNs` | number | Filter observations that predate this mono-ns timestamp, and anchor the `bgp_prefix_received_duration` sample (typically `advertise.sentAtMonoNs`) |

### MUP routes

For the MUP SAFI (`ipv4-mup` / `ipv6-mup`, draft-mpmz-bess-mup-safi-03)
the `routes` entries are objects with a `type` discriminator. The
descriptors are shared between `advertise` / `withdraw` / `waitForPrefixes`.

| `type` | Required fields | Optional fields | Reference |
|---|---|---|---|
| `'isd'`  | `rd`, `prefix` | — | section 3.1.1 |
| `'dsd'`  | `rd`, `address` | — | section 3.1.2 |
| `'t1st'` | `rd`, `prefix`, `teid`, `qfi`, `endpoint` | `source` | section 3.1.3 |
| `'t2st'` | `rd`, `endpoint`, `endpointAddressLength`, `teid` | — | section 3.1.4 |

`rd` accepts any RD form gobgp parses (`asn:n`, `asn.asn:n`, `ipv4:n`).
`teid` is given as an IPv4-shaped dotted-quad to carry the 32-bit TEID
(e.g. `'0.0.0.100'` for TEID 100). `endpointAddressLength` is the
combined Endpoint Address + TEID bit length per the draft: 32..64 for
IPv4 endpoints, 128..160 for IPv6.

### Cross-VU coordination

`bgp.barrier(name, count)` is a process-wide barrier shared across
VUs. Call `.arrive()` before timing-sensitive sections (e.g. wait for
all VUs to reach `Established` before any of them advertises) so that
the benchmark measures the steady-state throughput rather than ramp-up
artifacts. Barriers are single-use — pick a fresh `name` per
rendezvous if a script needs to barrier multiple times.

## Metrics

| Name | Type | Unit | Description |
|---|---|---|---|
| `bgp_session_up` | Trend | µs | `OpenSent → Established` per Peer |
| `bgp_prefix_received_duration` | Trend | µs | `sentAtMonoNs` → receive timestamp of the last expected prefix |
| `bgp_prefix_sent` | Counter | routes | Cumulative NLRIs sent |
| `bgp_prefix_received` | Counter | routes | Cumulative NLRIs received |

The two Trend metrics carry microsecond samples. They don't end in
`_us` (k6 convention is to document the unit in the metric table
rather than embed it in the name). BGP delivery latencies are
typically sub-millisecond, so storing them as ms would round many
samples to `0`.

Default tags: `plane=control`, `peer=<tags.peer from JS, if set>`. You
can attach additional tags via the `tags` option on the Peer
constructor.

Under k6's Prometheus remote-write output, names are prefixed with
`k6_` and Counters get a `_total` suffix appended, so the four
metrics above show up as `k6_bgp_session_up_*`,
`k6_bgp_prefix_received_duration_*`, `k6_bgp_prefix_sent_total`,
`k6_bgp_prefix_received_total` in Prometheus.

## Build

The [xk6](https://github.com/grafana/xk6) build tool builds a k6
binary that includes the xk6-bgp extension:

```sh
go install go.k6.io/xk6/cmd/xk6@latest
xk6 build --with github.com/higebu/xk6-bgp@v0.1.0
```

The minimum Go toolchain is the one k6 itself requires (currently
**Go 1.25**, dictated by `go.k6.io/k6` v1.7). xk6 will tell you if
your local toolchain is too old.

To track the development branch instead of a release, replace
`@v0.1.0` with `@latest` (master HEAD) or a specific commit hash.
`master` may be broken at any time. The version reported by
`bgp.version` is read from the module's embedded build info; override
it at build time via `GOFLAGS`:

```sh
GOFLAGS='-ldflags=-X github.com/higebu/xk6-bgp.Version=v0.1.0-local' \
  xk6 build --with github.com/higebu/xk6-bgp@latest
```

## Contribute

Issues and pull requests are welcome. Commit messages follow
[Conventional Commits](https://www.conventionalcommits.org/) — see
[CLAUDE.md](./CLAUDE.md). The `commitlint` GitHub Action enforces
the format on PR commits. Run the local lint with:

```sh
golangci-lint run ./...
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
