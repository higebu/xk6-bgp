# xk6-bgp

A [k6](https://k6.io/) extension built with
[xk6](https://github.com/grafana/xk6) that drives BGP sessions to
benchmark a target BGP daemon. Wire-level encoding and decoding reuse
[gobgp v4](https://github.com/osrg/gobgp)'s `pkg/packet/bgp`; the BGP
FSM and TCP I/O loop are xk6-bgp's own.

## Ground rules

- Respond to the user in Japanese
- Insert a half-width space between full-width and half-width characters
  in Japanese text
- No emojis
- RFC compliance is the top priority
- Do not write unnecessary comments
- Comments are written in English
- Log messages are written in English
- Error messages are written in English

## Review

- Reviews must be strict
- Findings must be specific and concise
- Findings must be ordered by priority, most important first
- Verify that changes and documentation stay consistent

## Commits

- Do not commit on your own
- Confirm the commit message with the user
- Commit messages are written in English
- Commit messages use the imperative mood
- One concern per commit
- Force-push only with `--force-with-lease`
- This repository is not upstream-bound; prefer readable history over
  paper-ready patches

## Examples

- `examples/*.js` are reference samples; they must be robust and
  performant
- Do not hard-code absolute paths
- Make the target BGP daemon configurable via environment variables

## Tests

- Unit tests are `<file>_test.go`, colocated with the implementation
- Do not use `t.Skip` for tests that always skip
- Receive-side tests use known UPDATE byte sequences as input and
  verify the expected NLRI set
- Send-side tests must at minimum round-trip xk6-bgp's OPEN/UPDATE
  output through gobgp `ParseBGPMessage`

## Go

- Prefer robustness over raw performance
- Keep dependencies minimal
- Avoid allocations on the hot path (reuse buffers, batch prefixes
  into a single UPDATE)
- Keep the goroutine count per Peer minimal
- When implementing draft-derived features, cite the source document
  name, section number, and the possibility of future changes in a
  code comment
- No CGo, no external native dependencies; plain `xk6 build` must
  produce a working binary

## Dependencies

- BGP wire encode/decode goes through gobgp v4 `pkg/packet/bgp` only
  (`ParseBGPMessage`, `NLRIFromSlice`, NLRI constructors, capability
  encoders)
- Do not use gobgp's `pkg/server.BgpServer` (we don't want ADJ-RIB-In,
  Loc-RIB, policy, or bestpath)
- JS binding goes through `go.k6.io/k6/js/modules` and
  `github.com/grafana/sobek`
- Metrics go through `go.k6.io/k6/metrics`

## Peer model

- `bgp.Peer` is the only public type
- One Peer = one BGP session (TCP/179)
- No RIB, no Loc-RIB, no policy
- The same Peer type handles both sending (`advertise()` /
  `withdraw()`) and receiving (`waitForPrefixes()`)
- Any AFI/SAFI that gobgp `pkg/packet/bgp` encodes is in scope; do not
  hard-code per-family logic into the public API surface

## Performance discipline

- Do not push metrics per-prefix; batch through
  `metrics.PushIfNotDone`
- Take timestamps at the TCP read/write syscall boundary
  (`internal/timing/clock.go` captures wall + mono together)

## Build and validation

```sh
go install go.k6.io/xk6/cmd/xk6@latest
xk6 build --with github.com/higebu/xk6-bgp=.
go build ./... && go vet ./... && go test ./...
./k6 run examples/<scenario>.js
```

Pass all of the following before treating a change as done:

- `go build ./...` is clean
- `go vet ./...` is clean
- `go test ./...` passes
- `xk6 build` produces `./k6`
- At least one `examples/*.js` runs end-to-end and emits the expected
  metrics

## RFC alignment

- The primary metric `bgp_prefix_received_duration` measures the time
  from the sender's UPDATE write to the receiver's UPDATE read of the
  last expected prefix (the DUT delivers routes between them)
- Negotiated by default: Extended Messages (RFC 8654), Route Refresh
  (RFC 2918), Graceful Restart with N-bit (RFC 4724 + RFC 8538),
  4-octet AS (RFC 6793)
- Data-plane / FIB convergence is out of scope
- RFCs and drafts that need to be referenced go under `refs/`. BGP
  wire format is delegated to gobgp, so RFC references are expected
  to be needed only occasionally during implementation
