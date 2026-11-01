// What a response's framing does to the client, against a peer in the
// program that answers by path: a HEAD's and a 304's Content-Length past
// Session.max_body, which describe no body; a chunk-size line and a trailer
// section that never end, which fail once they pass a head's limit rather
// than fill memory; and HTTP/1.0 responses, whose connection is kept only
// with keep-alive.
import std;
import http from "../../";
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import http.client;

fn send_text(fd: i32, text: const u8[:]) -> bool {
    var s = http::Socket { fd: fd };
    let e = http::send_all(s, text, 5000);
    return e.code == 0;
}

// Sends 20 MB of 'a', or until the client hangs up.
fn flood(fd: i32) {
    var chunk: u8[>..] = [];
    chunk.resize(65536, 'a');
    for i in 320 { if !send_text(fd, chunk) { return; } }
}

// Answers target on connection serial: false to close the connection.
fn answer(fd: i32, serial: i64, target: const u8[:]) -> bool {
    if target == "/head-big" {
        return send_text(fd, "HTTP/1.1 200 OK\r\nContent-Length: 100000000\r\n\r\n");
    }
    if target == "/304-big" {
        return send_text(fd, "HTTP/1.1 304 Not Modified\r\nETag: \"x\"\r\nContent-Length: 100000000\r\n\r\n");
    }
    if target == "/ext" {
        send_text(fd, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;x=");
        flood(fd);
        return false;
    }
    if target == "/trailer" {
        send_text(fd, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Pad: ");
        flood(fd);
        return false;
    }
    var body: u8[>..] = [];
    format(body, "connection ", serial);
    var out: u8[>..] = [];
    if target == "/1.0" {
        // Closed a while after the answer, as a server that doesn't keep
        // HTTP/1.0 connections does, so a reuse in between would fail.
        format(out, "HTTP/1.0 200 OK\r\nContent-Length: ", body.len, "\r\n\r\n", body);
        send_text(fd, out);
        sleep_ms(200);
        return false;
    }
    let keep = if target == "/1.0-keep" { "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\n" } else { "HTTP/1.1 200 OK\r\n" };
    format(out, keep, "Content-Length: ", body.len, "\r\n\r\n", body);
    return send_text(fd, out);
}

thread_fn peer(lfd: i32) {
    var serial = 0;
    var buf: u8[>..] = [];
    buf.resize(4096, 0);
    loop {
        let fd = http::net_accept(lfd, 0);
        assert(fd >= 0);
        serial++;
        var held: u8[>..] = [];
        loop {
            var end = find(held, "\r\n\r\n");
            while end < 0 {
                let n = http::net_recv(fd, buf);
                if n == -http::EAGAIN {
                    sleep_ms(1);
                    continue;
                }
                if n <= 0 { break; }
                held.append(buf[..n]);
                end = find(held, "\r\n\r\n");
            }
            if end < 0 { break; }
            let line = held[..find(held, "\r\n")];
            let rest = line[find(line, " ") + 1..];
            var target: u8[>..] = [];
            target.append(rest[..find(rest, " ")]);
            if target == "/quit" {
                http::net_close(fd);
                return;
            }
            var left: u8[>..] = [];
            left.append(held[end + 4..]);
            held.clear();
            held.append(left);
            if !answer(fd, serial, target) { break; }
        }
        http::net_close(fd);
    }
}

fn main() {
    let a, ok = http::address("127.0.0.1");
    assert(ok);
    let lfd = http::net_listen(a.ip, 0, 16, 0);
    assert(lfd >= 0);
    var url: u8[>..] = [];
    format(url, "http://127.0.0.1:", http::net_port(lfd));
    let t = thread_spawn(peer, lfd);
    var s = http::session(5000);

    let head, he = http::request(s, "HEAD", str(url, "/head-big")) { req => };
    print("a HEAD whose Content-Length is past max_body: '", he.call, "' ", head.status);
    let cached, ce = http::get(s, str(url, "/304-big")) { req => http::header(req, "If-None-Match", "\"x\""); };
    print("a 304 whose Content-Length is past max_body: '", ce.call, "' ", cached.status);

    var buf: u8[256] = [0; 256];
    for path in ["/ext", "/trailer"] {
        var x, e = http::begin(s, "GET", str(url, path));
        var got = 0;
        loop {
            let n, re = http::read(s, x, buf);
            e = re;
            if n == 0 || re.code != 0 { break; }
            got += n;
        }
        print(path, " that never ends: ", got, " bytes, '", e.call, "', held at most a head ",
              x.held.len <= http::MAX_RESPONSE_HEAD + 16384);
        http::end(s, x);
    }

    let old, oe = http::get(s, str(url, "/1.0"));
    print("HTTP/1.0: '", oe.call, "' ", old.body, ", kept ", s.s.fd >= 0);
    let after, ae = http::get(s, str(url, "/who"));
    print("  the next: '", ae.call, "' ", after.body);
    let kept, ke = http::get(s, str(url, "/1.0-keep"));
    print("HTTP/1.0 with keep-alive: '", ke.call, "' ", kept.body, ", kept ", s.s.fd >= 0);

    let q, qe = http::get(s, str(url, "/quit"));
    http::free(s);
    thread_wait(t);
    http::net_close(lfd);
}
