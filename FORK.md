# This fork

tzekid/goose-http's `work` branch is based on kaitk/goose-http's `v0.5.16`
(`e0722c46`), rebased on 2026-11-01, with changes meant to go upstream as small pull
requests. Each change below is a few commits that touch only its files, so that it
can be cherry-picked onto a fresh upstream
`main` and sent alone. None has been sent upstream yet. This file is the fork's own, and
goes in no pull request.

Two sibling forks hold what this one needs from kaitk's other packages:
[tzekid/goose-compress](https://github.com/tzekid/goose-compress)'s `work`, with a
decoder, and [tzekid/plod](https://github.com/tzekid/plod)'s `work`, with a service
example.

## The changes, in the order to send them

| # | Change | Commits | Depends on |
|---|---|---|---|
| 1 | `Session.total_ms`: one limit on a request as a whole, however steadily bytes come | `bc3f75e0` | — |
| 2 | `Session.redirects`: redirects followed, with RFC 9110's method rules, credentials dropped across origins, and no https-to-http | `b2e0202d`, `c9f29809` | 1 |
| 3 | `connect`'s `deny` and `Session.deny`: classes of address refused at the dial, IPv4 inside IPv6 judged as IPv4 | `57919226`, `448e0e72` | — |
| 4 | `http.websocket_client`: a blocking WebSocket client | `2c5cb4d6`, `3599c2a2` | 1 |
| 5 | `begin`, `response`, `read`, `end`: a response's body in pieces, the buffered calls rebuilt on them | `2e0e5e95`, `3736b2ed` | 1 |
| 6 | `stream`, `write`, `end_body`, `expect_continue`: a request's body in pieces, and 100 Continue | `975c0aaa`, `eb3e2044` | 5 |
| 7 | `shim/resolve.c`: a name's lookup bounded by connect's limit, on a thread of its own | `91c0dbdf` | — |
| 8 | Happy Eyeballs: `race`, and `net_poll_any` in each shim | `da431921` | 7 |
| 9 | `Session.proxy`: an HTTP proxy, with CONNECT for TLS and WebSockets | `408bd9a9` | 5 |
| 10 | `Session.max_idle`: connections kept for other origins | `816e9efb` | 5 |
| 11 | `http.client_decoding`: gzip and deflate responses decoded | `af146437` | 5, and goose-compress's decoder released |

Fork-only commits, which go in no pull request:

- `7a90da9a` pins goose-compress to the fork's commit with the decoder, so that 11
  builds here; upstream, that becomes a move to the goose-compress release that has it.
- This file, and the README's status rows, which describe all of the above at once.

The macOS `IPV6_DONTFRAG` build fix is already in upstream `v0.5.13`, so the rebase
drops the fork's duplicate. Upstream now has MIT and Apache-2.0 licenses. The rebase
keeps both `shim/shared.c` and `shim/resolve.c` in each platform's build sidecar.

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

## Rebase checks (2026-11-01)

The rebase uses Goose `v2026.3`, still the latest official release.

- Linux arm64, Ubuntu 26.04: all 85 tests pass at `-O0` and `-O2` as compiled
  programs.
- macOS 27.2 arm64: 83 of 85 tests pass at both levels. `outbound_blocking` and
  `outbound_loop` still fail their full-backlog timeout expectations; both also fail
  on untouched upstream `e0722c46` at both levels. The package loads through the JIT.
- macOS: the drain, upgraded-timeout, stale-reply, shared-send, and worker-mail
  end-to-end checks pass. h2spec passes all 146 cases over h2c and all 146 over TLS
  on each loop, and every example passes. One earlier h2spec run timed out over TLS;
  both loop runs passed on retry. The full HTTP server script stops at its 10,000
  client test with a connection timeout or reset, also reproduced on untouched
  upstream. The echo script stops at a concurrent-client connection reset.
  Neither full script has a passing macOS run in this validation.
- Windows: the resolver and socket shims compile with
  `zig cc -target x86_64-windows-gnu -std=c11 -Wall -Wextra` without warnings.
  Windows runtime checks remain pending.
