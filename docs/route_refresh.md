# Route Refresh

Route Refresh ([RFC 2918](https://www.rfc-editor.org/rfc/rfc2918.txt))
lets a BGP speaker ask its peer to re-send the Adj-RIB-Out for one
AFI/SAFI. On a real daemon that request triggers a full table walk and
re-advertisement — a table-scale workload (policy re-evaluation,
refresh storms from many peers) worth benchmarking on its own.
`peer.routeRefresh()` sends the request; `bgp_route_refresh_duration`
measures how long the target takes to complete the replay.

## Capabilities

| Capability | Code | RFC | Default | Role |
|---|---|---|---|---|
| Route Refresh | 2 | [RFC 2918](https://www.rfc-editor.org/rfc/rfc2918.txt) | on | Permits sending ROUTE-REFRESH to a peer that advertised it |
| Enhanced Route Refresh | 70 | [RFC 7313](https://www.rfc-editor.org/rfc/rfc7313.txt) | off (`enhancedRouteRefresh`) | Peer demarcates the replay with BoRR/EoRR |

`peer.routeRefresh()` errors unless the peer advertised the Route
Refresh capability in its OPEN (RFC 2918 § 4). BoRR/EoRR demarcations
are recognized only when both sides advertised Enhanced Route Refresh
(RFC 7313 § 4); without it the subtype field stays Reserved per RFC
2918 and inbound refresh messages count as plain requests (RFC 7313
§ 5).

## Measuring with RFC 7313 (EoRR mode)

With `enhancedRouteRefresh: true` negotiated, the target brackets the
replay between Beginning-of-Route-Refresh (BoRR) and
End-of-Route-Refresh (EoRR) demarcations. EoRR marks the RFC-exact
completion of the refresh:

```js
const rr = peer.routeRefresh({ family: 'ipv4-unicast' });
const eorr = peer.waitForRouteRefreshEnd({
  family:       'ipv4-unicast',
  timeout:      '10s',
  sentAtMonoNs: rr.sentAtMonoNs,
});
```

`bgp_route_refresh_duration` (Trend, µs) is the refresh write → EoRR
read interval, timestamped at the TCP syscall boundaries on both ends.
Passing `sentAtMonoNs` both anchors the metric and filters an EoRR left
over from an earlier refresh cycle on the same session.

## Measuring without RFC 7313 (prefix fallback)

When the target only supports RFC 2918, there is no EoRR to wait for —
`waitForRouteRefreshEnd` throws. Compose the refresh with the existing
prefix mechanism instead:

```js
const rr = peer.routeRefresh({ family: 'ipv4-unicast' });
const res = peer.waitForPrefixes({
  prefixes:     expected,
  timeout:      '10s',
  sentAtMonoNs: rr.sentAtMonoNs,
});
const us = Math.round((res.lastSeenMonoNs - rr.sentAtMonoNs) / 1000);
```

This measures until the last expected prefix of the replay arrives and
reports through `bgp_prefix_received_duration` rather than
`bgp_route_refresh_duration`. Note the observed set's firstSeen-sticky
cutoff: a prefix the session already observed before `sentAtMonoNs`
only re-matches after the target re-advertises it following a withdraw,
so this fallback fits a fresh session per iteration (open → advertise →
refresh → close), not a long-lived one.

## Observing DUT-solicited refreshes

The receive side counts inbound refresh traffic in `peer.stats()`:

| Counter | Meaning |
|---|---|
| `routeRefreshReceived` | ROUTE-REFRESH requests (subtype 0, or any subtype when RFC 7313 was not negotiated) |
| `borrReceived` | RFC 7313 BoRR demarcations |
| `eorrReceived` | RFC 7313 EoRR demarcations |

xk6-bgp deliberately does not replay its own advertisements when the
peer requests a refresh — the test script stays in control of what is
sent. The counters exist so scripts can detect the solicitation and
re-advertise explicitly if the scenario calls for it.

## fakebgpd

`cmd/fakebgpd` answers a ROUTE-REFRESH by replaying every cached UPDATE
the other sessions sent, bracketed by BoRR/EoRR when the client
negotiated RFC 7313 — enough for
[`examples/route_refresh.js`](../examples/route_refresh.js) to run
without a real daemon.
