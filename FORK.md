# This fork

tzekid/goose-http's `work` branch is based on kaitk/goose-http's `v0.5.16`
(`e0722c46`), rebased on 2026-11-01, with changes meant to go upstream as small pull
requests. Each change below is a few commits that touch only its files, so that it
can be cherry-picked onto a fresh upstream
`main` and sent alone. None has been sent upstream yet. This file is the fork's own, and
goes in no pull request. The fork's `main` mirrors upstream's `main`, fast-forwarded to
it, so that a pull request's branch starts there (2026-11-01).

Two sibling forks hold what this one needs from kaitk's other packages:
[tzekid/goose-compress](https://github.com/tzekid/goose-compress)'s `work`, with a
decoder, and [tzekid/plod](https://github.com/tzekid/plod)'s `work`, with a service
example.

## The changes, in the order to send them

The commits after the first in each row are the review's fixes (2026-11-01, below);
they go in the same pull request as the change they fix.

| # | Change | Commits | Depends on |
|---|---|---|---|
| 1 | `Session.total_ms`: one limit on a request as a whole, however steadily bytes come | `bc3f75e0` | — |
| 2 | `Session.redirects`: redirects followed, with RFC 9110's method rules, credentials dropped across origins, and no https-to-http | `b2e0202d`, `c9f29809`, `2a3760c2` | 1 |
| 3 | `connect`'s `deny` and `Session.deny`: classes of address refused at the dial, IPv4 inside IPv6 judged as IPv4 | `57919226`, `448e0e72`, `06eed0c9` | — |
| 4 | `http.websocket_client`: a blocking WebSocket client | `2c5cb4d6`, `3599c2a2`, `cd798032` | 1 |
| 5 | `begin`, `response`, `read`, `end`: a response's body in pieces, the buffered calls rebuilt on them | `2e0e5e95`, `3736b2ed`, `bc9c4763`, `5575e8f4` | 1 |
| 6 | `stream`, `write`, `end_body`, `expect_continue`: a request's body in pieces, and 100 Continue | `975c0aaa`, `eb3e2044`, `4d28026c`, `a8d14ff3` | 5 |
| 7 | `shim/resolve.c`: a name's lookup bounded by connect's limit, on a thread of its own | `91c0dbdf`, `27ee6f97` | — |
| 8 | Happy Eyeballs: `race`, and `net_poll_any` in each shim | `da431921`, `54cb9451` | 7 |
| 9 | `Session.proxy`: an HTTP proxy, with CONNECT for TLS and WebSockets | `408bd9a9`, `34751dc2` | 5 |
| 10 | `Session.max_idle`: connections kept for other origins | `816e9efb`, `9172aeff`, `9602ea7f` | 5, 6, 9 |
| 11 | `http.client_decoding`: gzip and deflate responses decoded | `af146437`, `dcae7706`, `55d566f9`, `d138209a` | 5, and goose-compress's decoder released |
| 12 | A request target that is a query alone gets its `/` (RFC 9112 §3.2.1), an upstream bug | `c62872ab` | — |

- `4d28026c` refuses a CR or LF in `stream`'s media type, and also in `http::body`'s and
  in the method, which upstream lets through into the request's head. Sent before 6, its
  `body` and method half stands alone.
- `9602ea7f` takes `expect_ms` -1 as documented, which is 6's, beside `idle_ms` -1 and
  `via` in the reuse key, which are 10's; hence 10's dependence on 6 and 9.

Fork-only commits, which go in no pull request:

- `7a90da9a`, then `971b6c76`, pin goose-compress to the fork's commit with the decoder,
  then to the one with its fixes, `81aedc4`, so that 11 builds here; upstream, that
  becomes a move to the goose-compress release that has it.
- This file, and the README's status rows, which describe all of the above at once.

The macOS `IPV6_DONTFRAG` build fix is already in upstream `v0.5.13`, so the rebase
drops the fork's duplicate. Upstream now has MIT and Apache-2.0 licenses. The rebase
keeps both `shim/shared.c` and `shim/resolve.c` in each platform's build sidecar.

Upstream's pull request
[#4](https://github.com/kaitk/goose-http/pull/4), opened 2026-11-01 by another
contributor, adds a blocking WebSocket client too, as `http.wsclient`, with one test.
Change 4 overlaps it, with more of RFC 6455 checked, and both add
`test/expected/ws_client.out`. Settle with the maintainer which goes in before sending
4.

Follow-up test and setup fixes, each independent of the client features above:

- `a3132533` accepts macOS's full-backlog resets in the outbound tests, including a
  reset seen during the first send or as `EINVAL` from `getpeername`. The blocking
  test still bounds the wait and requires the socket to close.
- `4388a2f3` builds the server before parallel tests, using the same C compiler
  command for both, so a cold shared CMake cache is ready before the tests use it.
- `eb53dcbb` documents TinyCC's SELinux build option for the pinned Goose release.

## Review (2026-11-01)

An adversarial review of the changes above, with a probe program run for each
suspicion, found these, each fixed with a test that fails without the fix:

- A response returned for another request: over TLS, bytes after a response stayed
  decrypted in TLS, where the reuse check can't see them, and became the next
  request's response (5); and an `end` called again after the next request began on the
  kept connection freed it for a third, which then read the second's response (5).
- Injection and memory: a CR or LF in a media type or the method went into the
  request's head (6, and upstream); a chunk-size line or trailer section that never
  ended, and pings or pongs between WebSocket messages, grew without bound (5, 4).
- A regression from upstream: a HEAD's or a 304's `Content-Length` past `max_body`
  failed the request, though neither has a body (5).
- Bodies and settings: an empty compressed body, as a HEAD's, a 204's, or a 304's,
  failed to decode (11); a valid deflate body read in pieces could fail at its end
  (11, with the decoder's fixes); `redirects`, `idle_ms`, `expect_ms`, and `ws.limit`
  at -1 didn't mean what the other settings' -1 does, or the docs said (2, 10, 6, 4);
  an HTTP/1.0 response without keep-alive left its connection kept (5); a changed
  `via` didn't change the connection (10); a proxy's credentials that weren't
  percent-encoded were dropped silently (9); `ws_close` cut a reason inside a character
  and sent any code (4); and SIIT's `::ffff:0:0/96` counted as public (3).
- Process: changes 7, 8, and 10 contradicted `docs/decisions.md` without updating it,
  as `AGENTS.md` asks; `27ee6f97`, `54cb9451`, and `9172aeff` record them.

goose-compress's fork has its own: `81aedc4` fixes the decoder at a call's output
limit, after a header cut short, and on fixed blocks, whose codes it rebuilt for each
block, so 1 MB of empty ones took 2.6 s; `13398dd` fixes upstream's `zstd_fse.goose`,
whose `as i64` of a fraction aborted every `--debug` build of a program that imports
the package, for a pull request of its own. A differential fuzzer against zlib, about
377,000 runs, found nothing else in the decoder.

Checked and found right, among others: redirects' credential and downgrade rules,
`resolve_url` against RFC 3986 §5.4's examples, `deny` at every redirect and through
`via`, `race`'s order and delay, `shim/resolve.c`'s copies, bound, and reference
counts, and the WebSocket client's framing, UTF-8, and handshake checks.

## How each was checked

The original changes were checked on 2026-10-25 as follows. Each change has its tests
in `test/`, as the repository's convention has them, which
`test/run_tests.py` runs at `-O0` and `-O2`:

- macOS 27.0.1 (arm64): every test passes but two that fail on `main` too:
  `outbound_blocking` and `outbound_loop` expect a full listen backlog to drop the next
  SYN, which this macOS doesn't.
- Linux 7.1 (arm64, Fedora's kernel in a Podman VM), Ubuntu 26.04, gcc 15.2, liburing
  2.14, Goose v2026.3 built from its tag: all 73 tests pass at both levels, the two
  above included, with native io_uring (the container run with `--security-opt
  seccomp=unconfined --security-opt label=disable`, since SELinux's container policy
  refuses io_uring), and on the emulated ring without it, where SELinux refused it.
  goose-compress's 27 tests and Plod's `examples/notes` pass there too.
- Windows: `shim/resolve.c` and `shim/net_win.c` compile with `zig cc -target
  x86_64-windows-gnu -std=c11 -Wall -Wextra` without a warning. Nothing ran on Windows.
- A fresh container's first run of tests in parallel can fail to build some: several
  builds compile a package into the empty cache at once. One test built first avoids
  it.

Probes measured what a test can't set up, once, and were deleted:

- A lookup of a missing `.local` name took 5,008 ms with `net_resolve`; `connect` with
  a 300 ms limit failed with `resolve`'s `ETIMEDOUT` at 301 ms; 40 hung lookups at
  once got 31 `ETIMEDOUT`s and 9 `EAGAIN`s: the 32 threads' bound, with one held.
- `192.0.2.1` alone took all of 2,000 ms; raced before `127.0.0.1`, the second
  connected after 252 ms.
- goose-compress's decoder, on a 2.5 MB word list compressed by `gzip -9` and by
  Python's zlib at levels 1, 6, and 9, gave the same bytes at 210 to 250 MB/s at
  `-O2`, where Python's zlib took 570 MB/s.

No benchmark ran: only the blocking client's and connect's paths changed, and none of
the loops' or the server's request path. The pull requests that touch `socket.goose`
(3, 7, 8) should still get the maintainer's run of `bench/count.sh`.

## Checks after the rebase and test fixes (2026-11-01)

The rebase uses Goose `v2026.3`, still the latest official release.

- Linux arm64, Ubuntu 26.04, gcc 15.2, kernel 7.2.7: `scripts/test.sh` passes from an
  empty compiled dependency cache. All 85 tests pass at `-O0` and `-O2`, as does the
  JIT check. Goose was built from the release's unchanged source with
  `CONFIG_SELINUX=1`, and the full suite ran with SELinux enforcing. The HTTP, TLS,
  drain, shared-send, worker-mail, and echo checks pass on native io_uring, epoll, and the emulated ring
  where each applies, including the 10,000-client HTTP and echo runs. Every example
  passes. h2spec is skipped because its release has no Linux arm64 binary.
- macOS 27.2 arm64: all 85 regression cases pass across the full run and targeted
  reruns of the corrected outbound fixtures at both levels. The blocking fixture
  also passes 64 concurrent stress runs under CPU load. The package loads through
  the JIT.
- macOS: the drain, upgraded-timeout, stale-reply, shared-send, and worker-mail
  end-to-end checks pass. h2spec passes all 146 cases over h2c and all 146 over TLS
  on each loop, and every example passes. The full HTTP and echo scripts still
  fail their high-connection runs on this host. An independent Python TCP listener
  also fails as connections accumulate, so host diagnostics remain pending; neither
  full script has a passing macOS run in this validation.
- Windows: the resolver and socket shims compile with
  `zig cc -target x86_64-windows-gnu -std=c11 -Wall -Wextra` without warnings.
  Windows runtime checks remain pending.

## Checks after the review (2026-11-01)

- macOS 27.2 arm64: all 88 tests pass at `-O0` and `-O2`, the review's three new ones
  (`client_framing`, `client_tail`, `ws_client_limits`) among them, and the server's
  and examples' root files typecheck. goose-compress's 28 tests pass, and a `--debug`
  build of a program that imports it runs each encoder and the decoder. Linux and
  Windows weren't run again: the fixes touch the client's and `connect`'s Goose, and no
  shim.
