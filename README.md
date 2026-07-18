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
- [`ipv4_addpath.js`](./examples/ipv4_addpath.js) — RFC 7911 ADD-PATH delivery of multiple paths per prefix
- [`mup.js`](./examples/mup.js) — `ipv4-mup` advertise of all four MUP route types
- [`srv6_l3vpn.js`](./examples/srv6_l3vpn.js) — `l3vpn-ipv4` advertise with RT + SRv6 L3 Service TLV (End.DT4 SID)
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

Opt-in via `capabilities`:

- ADD-PATH ([RFC 7911](https://www.rfc-editor.org/rfc/rfc7911.txt)) —
  `addPath: { '<family>': 'receive' | 'send' | 'both' }` per family.
  Each direction takes effect only when the peer advertised the
  matching opposite direction. With receive negotiated, observed-set
  keys become `"<prefix>:<pathId>"` for that family (see
  `waitForPrefixes`); with send negotiated, routes may carry a
  `pathId` (routes without one go out as Path Identifier `0`), and a
  `pathId` on a session that did not negotiate send is an error.

When a peer does not advertise the 4-octet AS capability, xk6-bgp
follows [RFC 6793 § 4.2.2](https://www.rfc-editor.org/rfc/rfc6793.txt):
AS_PATH is sent with 2-octet AS numbers (a non-mappable local AS
becomes `AS_TRANS` with the real value in AS4_PATH), and received
2-octet AS_PATHs are decoded accordingly.

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
| `capabilities` | object | see note | Per-capability overrides: `{ extendedMessage, routeRefresh, enhancedRouteRefresh, gracefulRestart, addPath }`. `extendedMessage`, `routeRefresh`, and `gracefulRestart` default on; `enhancedRouteRefresh` and `addPath` default off. `addPath` maps family strings to `'receive'` / `'send'` / `'both'` (see [Capabilities](#capabilities)) |
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
| `routes` | string[] \| object[] | Prefix strings (`['10.0.0.0/24']`) or family-specific descriptor objects — see [Supported AFI/SAFI](#supported-afisafi) (required). Any object form additionally accepts `pathId` (RFC 7911 Path Identifier; requires ADD-PATH send negotiated for the family) |
| `origin` | number | ORIGIN attribute: `0` IGP, `1` EGP, `2` INCOMPLETE (`advertise` only, default `0`) |
| `med` | number | MULTI_EXIT_DISC (`advertise` only) |
| `localPref` | number | LOCAL_PREF for iBGP (`advertise` only) |
| `extCommunities` | string[] | EXTENDED_COMMUNITIES entries ([RFC 4360](https://www.rfc-editor.org/rfc/rfc4360.txt)). Each string may carry an optional type prefix (`rt:` / `soo:` / `encap:` / `routermac:`); a bare value defaults to Route-Target. `encap:vxlan` etc. emit the Encapsulation EC ([RFC 9012](https://www.rfc-editor.org/rfc/rfc9012.txt)); `routermac:<MAC>` emits the EVPN Router's MAC EC ([RFC 9135 § 9](https://www.rfc-editor.org/rfc/rfc9135.txt)) |
| `srv6L3Service` | object | SRv6 L3 Service TLV ([RFC 9252](https://www.rfc-editor.org/rfc/rfc9252.txt)); see [`docs/srv6_l3vpn.md`](./docs/srv6_l3vpn.md) |
| `pmsiTunnel` | object | PMSI Tunnel attribute ([RFC 6514](https://www.rfc-editor.org/rfc/rfc6514.txt)). Shape: `{ tunnel: 'ingress-repl' \| <num>, label, endpoint, isLeafInfoRequired? }`. For EVPN Type 3 with VXLAN, set `tunnel: 'ingress-repl'`, `label: <VNI>`, `endpoint: <egress PE IP>` per [RFC 8365 § 5.1.3](https://www.rfc-editor.org/rfc/rfc8365.txt) |
| `useMpReach` | boolean | Force IPv4-unicast through `MP_REACH_NLRI` instead of the UPDATE NLRI field |
| `useExtendedMessages` | boolean | Chunk UPDATEs up to the RFC 8654 65535-byte limit. The peer **must** have advertised capability 6 — `advertise`/`withdraw` returns an error otherwise (see [Capabilities](#capabilities)) |
| `updateRate` | number | Cap the per-Peer UPDATE send rate at this many messages per second (`0` = unlimited) |

### `waitForPrefixes` options

| Field | Type | Description |
|---|---|---|
| `prefixes` | (string \| object)[] | Expected route set: prefix strings or family-specific descriptor objects (same shape as `advertise.routes` — see [Supported AFI/SAFI](#supported-afisafi)) (required). With ADD-PATH receive negotiated for the family, keys carry the Path Identifier: append `:<pathId>` to a prefix string (`'10.0.0.0/24:1'`) or set `pathId` on a descriptor object |
| `timeout` | string \| number | k6 duration string or seconds; throws if not met before this |
| `sentAtMonoNs` | number | Filter observations that predate this mono-ns timestamp, and anchor the `bgp_prefix_received_duration` sample (typically `advertise.sentAtMonoNs`) |

### Cross-VU coordination

`bgp.barrier(name, count)` is a process-wide barrier shared across
VUs. Call `.arrive()` before timing-sensitive sections (e.g. wait for
all VUs to reach `Established` before any of them advertises) so that
the benchmark measures the steady-state throughput rather than ramp-up
artifacts. Barriers are single-use — pick a fresh `name` per
rendezvous if a script needs to barrier multiple times.

`.arrive(timeout)` takes an optional timeout (k6 duration string or
seconds number) and throws when it elapses. Always pass one in scripts
where a VU can fail before its `arrive()` (a failed `open()`,
typically) — without a timeout the remaining VUs block until the
scenario's `maxDuration`. A timed-out arrival still counts toward
`count`, so one aborted VU does not wedge the rest a second time.

## Supported AFI/SAFI

| Family string | SAFI | Route descriptor | Reference | Doc | Example |
|---|---|---|---|---|---|
| `ipv4-unicast` | 1 | prefix string or `{ prefix }` | [RFC 4271](https://www.rfc-editor.org/rfc/rfc4271.txt) | — | [`examples/ipv4_unicast.js`](./examples/ipv4_unicast.js) |
| `ipv6-unicast` | 1 | prefix string or `{ prefix }` | [RFC 4760](https://www.rfc-editor.org/rfc/rfc4760.txt) | — | [`examples/ipv6_unicast.js`](./examples/ipv6_unicast.js) |
| `ipv4-mup` / `ipv6-mup` | 85 | `{ type, rd, ... }` | [draft-mpmz-bess-mup-safi](https://datatracker.ietf.org/doc/draft-mpmz-bess-mup-safi/) | [`docs/mup.md`](./docs/mup.md) | [`examples/mup.js`](./examples/mup.js) |
| `l3vpn-ipv4` / `l3vpn-ipv6` | 128 | `{ rd, prefix }` (+ `srv6L3Service` on advertise) | [RFC 4364](https://www.rfc-editor.org/rfc/rfc4364.txt), [RFC 9252](https://www.rfc-editor.org/rfc/rfc9252.txt) | [`docs/srv6_l3vpn.md`](./docs/srv6_l3vpn.md) | [`examples/srv6_l3vpn.js`](./examples/srv6_l3vpn.js) |
| `l2vpn-evpn` | 70 | `{ type: 'mac-ip' \| 'imet' \| 'ip-prefix', rd, ... }` | [RFC 7432](https://www.rfc-editor.org/rfc/rfc7432.txt), [RFC 9136](https://www.rfc-editor.org/rfc/rfc9136.txt) | [`docs/evpn.md`](./docs/evpn.md) | [`examples/evpn.js`](./examples/evpn.js) |

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
