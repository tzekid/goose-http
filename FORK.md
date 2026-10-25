# This fork

tzekid/goose-http's `work` branch is kaitk/goose-http's `main`, which `main` here mirrors,
with changes meant to go upstream as small pull requests. Each change below is a few
commits that touch only its files, so that it can be cherry-picked onto a fresh upstream
`main` and sent alone. None has been sent upstream yet. This file is the fork's own, and
goes in no pull request.

Two sibling forks hold what this one needs from kaitk's other packages:
[tzekid/goose-compress](https://github.com/tzekid/goose-compress)'s `work`, with a
decoder, and [tzekid/plod](https://github.com/tzekid/plod)'s `work`, with a service
example.

## The changes, in the order to send them

| # | Change | Commits | Depends on |
|---|---|---|---|
| 1 | v0.5.12 doesn't build on macOS: `shim/kqueue.c` uses `IPV6_DONTFRAG`, which Apple's headers declare only for RFC 3542's API. Plod's examples can't build on a Mac until it's fixed | `a86cfd6e` | — |
| 2 | `Session.total_ms`: one limit on a request as a whole, however steadily bytes come | `b3a8da0a` | — |
| 3 | `Session.redirects`: redirects followed, with RFC 9110's method rules, credentials dropped across origins, and no https-to-http | `b6aa0999`, `06925cf3` | 2 |
| 4 | `connect`'s `deny` and `Session.deny`: classes of address refused at the dial, IPv4 inside IPv6 judged as IPv4 | `a00b2818`, `7d5dd01a` | — |
| 5 | `http.websocket_client`: a blocking WebSocket client | `836eef85`, `81210f5e` | 2 |
| 6 | `begin`, `response`, `read`, `end`: a response's body in pieces, the buffered calls rebuilt on them | `5dd96706`, `39cf31d7` | 2 |
| 7 | `stream`, `write`, `end_body`, `expect_continue`: a request's body in pieces, and 100 Continue | `35560338`, `5aa232f1` | 6 |
| 8 | `shim/resolve.c`: a name's lookup bounded by connect's limit, on a thread of its own | `4c7ea475` | — |
| 9 | Happy Eyeballs: `race`, and `net_poll_any` in each shim | `6838b7b8` | 8 |
| 10 | `Session.proxy`: an HTTP proxy, with CONNECT for TLS and WebSockets | `a8b9f75f` | 6 |
| 11 | `Session.max_idle`: connections kept for other origins | `848f06b7` | 6 |
| 12 | `http.client_decoding`: gzip and deflate responses decoded | `ace62583` | 6, and goose-compress's decoder released |

Fork-only commits, which go in no pull request:

- `f431de6c` pins goose-compress to the fork's commit with the decoder, so that 12
  builds here; upstream, that becomes a move to the goose-compress release that has it.
- This file, and the README's status rows, which describe all of the above at once.

Before the first pull request: none of kaitk's repositories has a license file, which
contributions need settled.

## How each was checked

Each change has its tests in `test/`, as the repository's convention has them, which
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
(4, 8, 9) should still get the maintainer's run of `bench/count.sh`.
