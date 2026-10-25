// http.websocket_client against the package's own WebSocket server, plain
// and over TLS on Unix sockets in TMPDIR, and against a peer in the program
// that writes the frames a server may send but this one doesn't: a text
// message, a large binary one, a subprotocol, a refusal, and a close from
// each side; then fragments with a ping between them, a masked frame, text
// that isn't UTF-8, a wrong Sec-WebSocket-Accept, and an extension never
// offered. The peer reports what the client sent it, its pongs and Close
// codes, in a last message.
import std;
import os;
import http from "../../";
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import http.tls;
import http.websocket;
import http.websocket_client;

struct St { ws: http::WebSocket = http::WebSocket { limit: 1 << 20, .. } }

fn handle(ev: http::Event, st: St&, out: http::Reply) {
    if ev.kind == http::REQUEST {
        let path = http::path_of(ev.req.target);
        if path == "/nows" {
            http::respond(out, 403, "text/plain", "no");
        } else {
            http::ws_upgrade(ev.req, st.ws, out, if path == "/chat" { "chat" } else { "" });
        }
    } else {
        http::ws_read(ev, st.ws, out) { op, data, o =>
            if data == "close-me" { http::ws_close(o, st.ws, 4000, "bye"); }
            else { http::ws_send(o, op, data); }
        };
    }
}

thread_fn plain_worker(cfg: http::Config) {
    let e = http::serve_epoll(cfg, St { .. }) { ev, st, out => handle(ev, st, out); };
    if e.code != 0 { http::report(e); }
}

thread_fn tls_worker(cfg: http::Config, ctx: tls::Context) {
    var server = http::tls_server(ctx);
    let e = http::serve_epoll(cfg, St { .. }, server) { ev, st, out => handle(ev, st, out); };
    http::release(server);
    if e.code != 0 { http::report(e); }
}

fn unix_address(name: const u8[:]) -> u8[>..] {
    var dir: u8[>..] = [];
    var a: u8[>..] = [];
    if env("TMPDIR", dir) && dir.len > 0 { format(a, "unix:", dir, "/", name); }
    else { format(a, "unix:", name); }
    return a;
}

fn listening(address: const u8[:], port: i64) {
    for i in 500 {
        var s, e = http::connect(address, port, 1000);
        if e.code == 0 {
            http::hangup(s);
            return;
        }
        sleep_ms(10);
    }
    abort(str("nothing listens at ", address));
}

// The peer's side: blocking sends and reads on an accepted socket.
fn send_all(fd: i32, data: const u8[:]) {
    var at = 0;
    while at < data.len {
        let n = http::net_send(fd, data[at..]);
        if n <= 0 { return; }
        at += n;
    }
}

// An unmasked frame, as a server sends it, or masked where masked.
fn frame(out: u8[>..]&, fin: bool, op: u8, payload: const u8[:], masked: bool = false) {
    out.push((if fin { 0x80 } else { 0 }) | op);
    out.push((if masked { 0x80 } else { 0 }) | payload.len as! u8);
    let key: u8[4] = [1, 2, 3, 4];
    if masked { out.append(key); }
    for b, i in payload { out.push(if masked { b ^ key[i & 3] } else { b }); }
}

// Reads the client's next frame from fd into payload, unmasked, and returns
// its opcode, or -1 if it isn't masked or the connection ends first.
fn read_frame(fd: i32, held: u8[>..]&, payload: u8[>..]&) -> i64 {
    var buf: u8[4096] = [0; 4096];
    loop {
        if held.len >= 6 && (held[1] & 0x7F) < 126 && held.len >= 6 + (held[1] & 0x7F) as i64 {
            guard held[1] & 0x80 != 0 else { return -1; }
            let n = (held[1] & 0x7F) as i64;
            payload.clear();
            for i in n { payload.push(held[6 + i] ^ held[2 + (i & 3)]); }
            let op = (held[0] & 0x0F) as i64;
            var rest: u8[>..] = [];
            rest.append(held[6 + n..]);
            held.clear();
            held.append(rest);
            return op;
        }
        let n = http::net_recv(fd, buf);
        if n <= 0 { return -1; }
        held.append(buf[..n]);
    }
}

// Answers one handshake after another on lfd, each by its path, and keeps
// what the client sent back in seen; /report sends seen and ends.
thread_fn peer(lfd: i32) {
    var seen: u8[>..] = [];
    loop {
        let fd = http::net_accept(lfd, 0);
        assert(fd >= 0);
        var head: u8[>..] = [];
        var buf: u8[4096] = [0; 4096];
        while find(head, "\r\n\r\n") < 0 {
            let n = http::net_recv(fd, buf);
            assert(n > 0);
            head.append(buf[..n]);
        }
        let path = head[4..find(head, " HTTP/")];
        let k = find(head, "Sec-WebSocket-Key: ") + 19;
        let key = head[k..k + 24];
        var accept: u8[>..] = [];
        if path == "/badaccept" { accept.append("AAAAAAAAAAAAAAAAAAAAAAAAAAA="); } else { accept.append(http::ws_accept(key)); }
        var out: u8[>..] = [];
        format(out, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n",
               "Sec-WebSocket-Accept: ", accept, "\r\n");
        if path == "/ext" { out.append("Sec-WebSocket-Extensions: permessage-deflate\r\n"); }
        out.append("\r\n");
        var held: u8[>..] = [];
        var payload: u8[>..] = [];
        if path == "/frag" {
            frame(out, false, http::WS_TEXT, "hel");
            frame(out, true, 9, "x");
            frame(out, true, 0, "lo");
            send_all(fd, out);
            let op = read_frame(fd, held, payload);
            format(seen, "frag: op ", op, " ", payload, "; ");
            out.clear();
            frame(out, true, 8, [0x03, 0xe8]);
            send_all(fd, out);
            let c = read_frame(fd, held, payload);
            format(seen, "close op ", c, " code ", (payload[0] as i64) << 8 | payload[1], "\n");
        } else if path == "/masked" || path == "/utf8" {
            if path == "/masked" { frame(out, true, http::WS_TEXT, "hidden", true); }
            else { frame(out, true, http::WS_TEXT, [0x68, 0xff]); }
            send_all(fd, out);
            let c = read_frame(fd, held, payload);
            format(seen, path, ": close op ", c, " code ", (payload[0] as i64) << 8 | payload[1], "\n");
        } else if path == "/report" {
            frame(out, true, http::WS_TEXT, seen);
            frame(out, true, 8, [0x03, 0xe8]);
            send_all(fd, out);
            read_frame(fd, held, payload);
            http::net_close(fd);
            return;
        } else {
            send_all(fd, out);
        }
        http::net_close(fd);
    }
}

fn show(name: const u8[:], ws: const http::WsClient&, e: http::Error) {
    if e.code == 0 { print(name, ": open, protocol \"", ws.protocol, "\""); }
    else { print(name, ": failed: ", e.call, ", status ", ws.status); }
}

fn next(ws: http::WsClient&, message: u8[>..]&) {
    let op, e = http::ws_receive(ws, message);
    if e.code != 0 { print("  failed: ", e.call, " ", e.code == http::ETIMEDOUT); return; }
    if op == http::WS_CLOSE { print("  close ", ws.close_code, " \"", message, "\""); return; }
    if op == http::WS_BINARY { print("  binary ", message.len, " ", message[message.len - 1]); return; }
    print("  text \"", message, "\"");
}

fn main() {
    var chain: u8[>..] = [];
    var key: u8[>..] = [];
    let failed = tls::run() {
        let k = tls::key_generate(tls::P256);
        chain = tls::self_signed(k, ["localhost"], 1);
        key = tls::key_pem(k);
        tls::free(k);
    };
    assert(failed.len == 0);
    let ctx, ok = tls::server(chain, key, ["http/1.1"]);
    assert(ok);
    let plain = unix_address("p.sock");
    let secure = unix_address("t.sock");
    let w = [
        thread_spawn(plain_worker, http::Config { address: plain, workers: 1, .. }),
        thread_spawn(tls_worker, http::Config { address: secure, workers: 1, tls: true, .. }, ctx),
    ];
    listening(plain, 0);
    listening(secure, 0);
    var message: u8[>..] = [];

    for secured in [false, true] {
        print(if secured { "== wss" } else { "== ws" });
        var session, trusted = http::session_trusting(chain, 5000);
        assert(trusted);
        if secured { session.via.append(secure); } else { session.via.append(plain); }
        let scheme = if secured { "wss" } else { "ws" };
        var ws, e = http::ws_connect(session, str(scheme, "://localhost/echo"));
        show("echo", ws, e);
        print("  the session holds no connection: ", session.s.fd < 0);
        http::ws_send(ws, http::WS_TEXT, "héllo");
        next(ws, message);
        var big: u8[>..] = [];
        for i in 200000 { big.push((i % 251) as! u8); }
        http::ws_send(ws, http::WS_BINARY, big);
        next(ws, message);
        print("  the same bytes: ", message == big);
        http::ws_send(ws, http::WS_TEXT, "close-me");
        next(ws, message);
        print("  send after: ", http::ws_send(ws, http::WS_TEXT, "x").code == http::EPIPE);

        var chat, ce = http::ws_connect(session, str(scheme, "://localhost/chat")) { req =>
            http::header(req, "Sec-WebSocket-Protocol", "superchat, chat");
        };
        show("chat", chat, ce);
        print("  closed by the client: ", http::ws_close(chat, 1000, "done").code, " ", chat.close_code);

        var no, ne = http::ws_connect(session, str(scheme, "://localhost/nows"));
        show("refused", no, ne);
        var bad, be = http::ws_connect(session, str(scheme, "://localhost/echo")) { req =>
            http::header(req, "Sec-WebSocket-Key", "x");
        };
        show("a key of the program's", bad, be);
        http::free(session);
    }

    print("== a peer of the test's");
    let a, ok2 = http::address("127.0.0.1");
    assert(ok2);
    let lfd = http::net_listen(a.ip, 0, 16, 0);
    assert(lfd >= 0);
    let port = http::net_port(lfd);
    let p = thread_spawn(peer, lfd);
    var session = http::session(2000);
    for path in ["/frag", "/masked", "/utf8", "/badaccept", "/ext", "/report"] {
        var ws, e = http::ws_connect(session, str("ws://127.0.0.1:", port, path));
        show(path, ws, e);
        var got: u8[>..] = [];
        if e.code == 0 {
            next(ws, got);
            if path == "/frag" || path == "/report" { next(ws, got); }
            print("  closed: ", ws.done);
        }
    }
    http::free(session);
    thread_wait(p);
    http::net_close(lfd);

    http::stop();
    for t in w { thread_wait(t); }
    tls::free(ctx);
}
