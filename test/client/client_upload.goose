// stream, write, and end_body (client.goose): bodies the program writes in
// pieces, to a peer in the program that reads them by the request's path: 3
// MB with a Content-Length, to a reader that takes its time; chunks; Expect:
// 100-continue answered with a refusal before the body, with 100 Continue,
// and not at all; a body short of its Content-Length and one past it; a
// streamed body given to request; and Session.total_ms against a reader too
// slow for it.
import std;
import http from "../../";
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import http.client;

let SIZE = 3 << 20;

fn send_text(fd: i32, text: const u8[:]) {
    var at = 0;
    while at < text.len {
        let n = http::net_send(fd, text[at..]);
        if n <= 0 { return; }
        at += n;
    }
}

fn answer(fd: i32, status: const u8[:], body: const u8[:]) {
    var out: u8[>..] = [];
    format(out, "HTTP/1.1 ", status, "\r\nConnection: close\r\nContent-Length: ", body.len, "\r\n\r\n", body);
    send_text(fd, out);
}

// Reads from fd until held holds n bytes; false if the connection ends first.
fn fill(fd: i32, held: u8[>..]&, n: i64, pause: bool) -> bool {
    var buf: u8[>..] = [];
    buf.resize(65536, 0);
    while held.len < n {
        let k = http::net_recv(fd, buf);
        if k <= 0 { return false; }
        held.append(buf[..k]);
        if pause { sleep_ms(1); }
    }
    return true;
}

// The bytes of a chunked body, read from held and fd with the server's own
// reader of request bodies.
fn dechunk(fd: i32, held: u8[>..]&) -> u8[>..] {
    var body: u8[>..] = [];
    var r = http::BodyReader.ChunkSize;
    var buf: u8[>..] = [];
    buf.resize(4096, 0);
    loop {
        let d0, d1, verdict = http::read_body(held, r);
        assert(verdict != 400);
        if verdict == 200 {
            let ended = match r { None => true, _ => false };
            if !ended { body.append(held[d0..d1]); }
            var rest: u8[>..] = [];
            rest.append(held[d1..]);
            held.clear();
            held.append(rest);
            if ended { return body; }
            continue;
        }
        let k = http::net_recv(fd, buf);
        assert(k > 0);
        held.append(buf[..k]);
    }
}

thread_fn peer(lfd: i32) {
    loop {
        let fd = http::net_accept(lfd, 0);
        assert(fd >= 0);
        var held: u8[>..] = [];
        var buf: u8[>..] = [];
        buf.resize(4096, 0);
        while find(held, "\r\n\r\n") < 0 {
            let n = http::net_recv(fd, buf);
            if n <= 0 { break; }
            held.append(buf[..n]);
        }
        let end = find(held, "\r\n\r\n");
        if end < 0 {
            http::net_close(fd);
            continue;
        }
        var head: u8[>..] = [];
        head.append(held[..end + 4]);
        var rest: u8[>..] = [];
        rest.append(held[end + 4..]);
        held.clear();
        held.append(rest);
        let path = head[find(head, " ") + 1..find(head, " HTTP/")];
        let at = find(head, "Content-Length: ");
        var length = -1;
        if at >= 0 {
            let line = head[at + 16..];
            let n, ok = parse_int(line[..find(line, "\r\n")]);
            length = n;
        }
        if path == "/quit" {
            http::net_close(fd);
            return;
        } else if path == "/reject" {
            answer(fd, "413 Content Too Large", "too big");
        } else if path == "/chunks" {
            let body = dechunk(fd, held);
            answer(fd, "200 OK", body);
        } else if path == "/slow" {
            var slow: u8[>..] = [];
            slow.resize(16384, 0);
            loop {
                let n = http::net_recv(fd, slow);
                if n <= 0 { break; }
                sleep_ms(100);
            }
        } else {
            if path == "/continue" { send_text(fd, "HTTP/1.1 100 Continue\r\n\r\n"); }
            if fill(fd, held, length, path == "/count") {
                var sum = 0;
                for b in held[..length] { sum = (sum + b) % 65521; }
                var text: u8[>..] = [];
                format(text, "got ", length, ", sum ", sum);
                answer(fd, if path == "/continue" { "201 Created" } else { "200 OK" }, text);
            }
        }
        http::net_close(fd);
    }
}

fn byte_at(i: i64) -> u8 { (i * 13 % 251) as! u8 }

fn finish(s: http::Session&, x: http::ClientExchange&, name: const u8[:]) {
    var e = http::response(s, x);
    var body: u8[>..] = [];
    var buf: u8[256] = [0; 256];
    while e.code == 0 {
        let n, re = http::read(s, x, buf);
        e = re;
        if n == 0 { break; }
        body.append(buf[..n]);
    }
    if e.code != 0 { print(name, ": failed: ", e.call); } else { print(name, ": ", x.status, " ", body); }
    http::end(s, x);
}

fn main() {
    let a, ok = http::address("127.0.0.1");
    assert(ok);
    let lfd = http::net_listen(a.ip, 0, 16, 0);
    assert(lfd >= 0);
    var base: u8[>..] = [];
    format(base, "http://127.0.0.1:", http::net_port(lfd));
    let t = thread_spawn(peer, lfd);
    var s = http::session(5000);

    var sum = 0;
    for i in SIZE { sum = (sum + byte_at(i)) % 65521; }
    print("expected: got ", SIZE, ", sum ", sum);
    var x, e = http::begin(s, "PUT", str(base, "/count")) { req => http::stream(req, "", SIZE); };
    var piece: u8[>..] = [];
    var at = 0;
    while at < SIZE && e.code == 0 {
        piece.clear();
        for i in min(65536, SIZE - at) { piece.push(byte_at(at + i)); }
        e = http::write(s, x, piece);
        at += piece.len;
    }
    if e.code == 0 { e = http::end_body(s, x); }
    finish(s, x, "3 MB, Content-Length");

    x, e = http::begin(s, "POST", str(base, "/chunks")) { req => http::stream(req, "text/plain", -1); };
    for p in ["abc", "", "defgh", "ij"] { http::write(s, x, p); }
    http::end_body(s, x);
    finish(s, x, "chunks");

    x, e = http::begin(s, "PUT", str(base, "/reject")) { req =>
        http::stream(req, "", 1 << 20);
        http::expect_continue(req);
    };
    let w = http::write(s, x, "x");
    print("refused before the body: begin ", e.code, ", write ", w.call, " ", w.code == http::EPIPE, ", ended ",
          http::end_body(s, x).code);
    finish(s, x, "  answer");
    print("  kept: ", s.s.fd >= 0);

    let r1, e1 = http::post(s, str(base, "/continue")) { req =>
        http::body(req, "text/plain", "hello");
        http::expect_continue(req);
    };
    print("100 Continue: ", e1.code, ", ", r1.status, " ", r1.body);

    s.expect_ms = 200;
    let began = http::net_clock_ms();
    let r2, e2 = http::put(s, str(base, "/silent")) { req =>
        http::body(req, "text/plain", "hello");
        http::expect_continue(req);
    };
    let waited = http::net_clock_ms() - began;
    print("no 100: ", e2.code, ", ", r2.status, " ", r2.body, ", waited for it ", waited >= 150 && waited < 4000);

    x, e = http::begin(s, "PUT", str(base, "/count")) { req => http::stream(req, "", 10); };
    http::write(s, x, "12345");
    let short = http::end_body(s, x);
    print("short: ", short.call, ", kept ", s.s.fd >= 0);
    x, e = http::begin(s, "PUT", str(base, "/count")) { req => http::stream(req, "", 3); };
    let over = http::write(s, x, "12345");
    print("past Content-Length: ", over.call, ", kept ", s.s.fd >= 0);
    let r3, e3 = http::put(s, str(base, "/count")) { req => http::stream(req, "", 3); };
    print("streamed, to request: ", e3.call);

    s.total_ms = 300;
    s.ms = 5000;
    let started = http::net_clock_ms();
    x, e = http::begin(s, "PUT", str(base, "/slow")) { req => http::stream(req, "", 64 << 20); };
    piece.clear();
    piece.resize(1 << 20, 7);
    var sent = 0;
    while e.code == 0 && sent < 64 {
        e = http::write(s, x, piece);
        sent++;
    }
    let took = http::net_clock_ms() - started;
    print("a slow reader past total_ms: ", e.call, " ", e.code == http::ETIMEDOUT, ", within a second ",
          took < 1000, ", kept ", s.s.fd >= 0);
    s.total_ms = -1;

    let q, qe = http::get(s, str(base, "/quit"));
    http::free(s);
    thread_wait(t);
    http::net_close(lfd);
}
