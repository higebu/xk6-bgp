# fakebgpd

`fakebgpd` is a minimal BGP speaker bundled with xk6-bgp for end-to-end
smoke tests. It is **not** a routing daemon: it accepts BGP sessions,
completes the OPEN / KEEPALIVE handshake, optionally reflects every
UPDATE it receives to all other connected sessions, answers
ROUTE-REFRESH requests by replaying the other sessions' cached UPDATEs
(bracketed by RFC 7313 BoRR/EoRR when the client negotiated Enhanced
Route Refresh), and exits when either side tears the TCP connection
down.

The delivery examples (`examples/ipv4_unicast.js`, `examples/ipv6_unicast.js`)
use `fakebgpd -reflect` so the sender Peer and the receiver Peer can
talk through a single process without a real BGP daemon.

## Build

```sh
go build -o fakebgpd ./cmd/fakebgpd
```

## Run

```sh
./fakebgpd -listen 127.0.0.1:11790 -families ipv4-unicast -reflect
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `-listen` | `127.0.0.1:1790` | TCP `host:port` to bind. Use `'[::1]:11790'` for IPv6. |
| `-as` | `65000` | Local AS number advertised in the OPEN. |
| `-router-id` | `10.0.0.2` | Router-ID (must be a dotted-quad). |
| `-families` | `ipv4-unicast` | Comma-separated AFI/SAFI list, e.g. `ipv4-unicast,ipv6-unicast`. |
| `-reflect` | `false` | Re-broadcast each received UPDATE to every other connected session. Required when both sender and receiver Peers connect to the same fakebgpd. |
| `-addpath` | `false` | Advertise the RFC 7911 ADD-PATH capability (send/receive) for all families and decode Path Identifiers from clients that negotiated send. Reflection stays a raw byte re-send, so every connected Peer must use the same `addPath` capabilities (see `examples/ipv4_addpath.js`). |

## Example: minimal delivery smoke

Run fakebgpd, then drive both Peers from xk6-bgp:

```sh
go build -o fakebgpd ./cmd/fakebgpd
./fakebgpd -listen 127.0.0.1:11790 -families ipv4-unicast -reflect &
./k6 run -e TARGET=127.0.0.1:11790 examples/ipv4_unicast.js
```

The receiver Peer should observe `matched=<COUNT>` for every prefix
the sender advertised, with `bgp_prefix_received_duration` showing the
round-trip through fakebgpd.

## Scope

- No Loc-RIB, no best-path, no policy. Reflection is a literal byte-for-
  byte re-send of the original UPDATE to every other session, and
  refresh replay re-sends the cached UPDATEs the same way (no per-family
  filtering).
- Capabilities advertised: MP-BGP (per `-families`), Route Refresh,
  Enhanced Route Refresh, Extended Messages, 4-octet AS, and (with
  `-addpath`) ADD-PATH.
- Hold time is hard-coded to 90 s, keepalive period to 30 s.
- Intended for local smoke and CI; not for any kind of performance
  measurement of the BGP code path itself.
