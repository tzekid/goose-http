// begin, response, read, and end (client.goose): a response's body read in
// pieces from a peer in the program, by its path: 5 MB through a 4 KB buf,
// with how much the exchange ever held; a chunked body with extensions and
// trailers, sent a byte at a time; a body that ends with the connection; a
// body left half read, whose connection the next request doesn't reuse; one
// cut short; two 1xx before a response; a body past Session.max_body; and
// 2 MB over TLS from the package's own server.
import std;
import os;
import http from "../../";
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import http.tls;
import http.client;

let BIG = 5 << 20;

fn send_text(fd: i32, text: const u8[:]) -> bool {
    var at = 0;
    while at < text.len {
        let n = http::net_send(fd, text[at..]);
        if n <= 0 { return false; }
        at += n;
    }
    return true;
}

fn byte_at(i: i64) -> u8 { (i * 7 % 251) as! u8 }

// Answers each request on each connection, one connection at a time, by its
// path; a body that names the connection says which one carried it.
thread_fn peer(lfd: i32) {
    var buf: u8[>..] = [];
    buf.resize(4096, 0);
    var serial = 0;
    loop {
        let fd = http::net_accept(lfd, 0);
        assert(fd >= 0);
        serial++;
        var open = true;
        while open {
            let n = http::net_recv(fd, buf);
            if n <= 0 { break; }
            let req = buf[..n];
            let path = req[4..find(req, " HTTP/")];
            var out: u8[>..] = [];
            if path == "/quit" {
                http::net_close(fd);
                return;
            } else if path == "/big" {
                format(out, "HTTP/1.1 200 OK\r\nContent-Length: ", BIG, "\r\n\r\n");
                send_text(fd, out);
                var chunk: u8[>..] = [];
                var at = 0;
                while at < BIG {
                    chunk.clear();
                    for i in min(65536, BIG - at) { chunk.push(byte_at(at + i)); }
                    if !send_text(fd, chunk) { break; }
                    at += chunk.len;
                }
            } else if path == "/chunked" {
                out.append("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
                out.append("5;name=value\r\nhello\r\n1\r\n \r\nc\r\nworld, again\r\n0\r\nX-Sum: 17\r\nX-More: yes\r\n\r\n");
                for i in out.len {
                    if !send_text(fd, out[i..i + 1]) { break; }
                    sleep_ms(1);
                }
            } else if path == "/close" {
                send_text(fd, "HTTP/1.1 200 OK\r\n\r\nuntil the end");
                open = false;
            } else if path == "/half" {
                format(out, "HTTP/1.1 200 OK\r\nContent-Length: ", 1 << 20, "\r\n\r\n");
                send_text(fd, out);
                var zeros: u8[>..] = [];
                zeros.resize(1 << 20, 0);
                send_text(fd, zeros);
            } else if path == "/short" {
                send_text(fd, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nonly fifty bytes, and then the server closes......");
                open = false;
            } else if path == "/interim" {
                send_text(fd, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n");
                send_text(fd, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfinal");
            } else {
                format(out, "connection ", serial);
                var head: u8[>..] = [];
                format(head, "HTTP/1.1 200 OK\r\nContent-Length: ", out.len, "\r\n\r\n", out);
                send_text(fd, head);
            }
        }
        http::net_close(fd);
    }
}

thread_fn tls_worker(cfg: http::Config, ctx: tls::Context) {
    var server = http::tls_server(ctx);
    let e = http::serve_epoll(cfg, server) { req, body, out =>
        var big: u8[>..] = [];
        for i in 2 << 20 { big.push(byte_at(i)); }
        http::respond(out, 200, "application/octet-stream", big);
    };
    http::release(server);
    if e.code != 0 { http::report(e); }
}

// Reads x's body through a buf of size bytes: how many it read, whether they
// were the bytes byte_at gives, the most one read gave, and the most x held.
fn drain(s: http::Session&, x: http::ClientExchange&, size: i64) -> i64, bool, i64, i64, http::Error {
    var buf: u8[>..] = [];
    buf.resize(size, 0);
    var total = 0;
    var same = true;
    var most = 0;
    var held = 0;
    loop {
        let n, e = http::read(s, x, buf);
        guard e.code == 0 else { return total, same, most, held, e; }
        if n == 0 { break; }
        for i in n { if buf[i] != byte_at(total + i) { same = false; } }
        total += n;
        most = max(most, n);
        held = max(held, x.held.len);
    }
    return total, same, most, held, http::no_error();
}

fn text_of(s: http::Session&, x: http::ClientExchange&) -> u8[>..], http::Error {
    var t: u8[>..] = [];
    var buf: u8[7] = [0; 7];
    loop {
        let n, e = http::read(s, x, buf);
        guard e.code == 0 else { return t, e; }
        if n == 0 { return t, e; }
        t.append(buf[..n]);
    }
}

fn get(s: http::Session&, url: const u8[:], path: const u8[:]) -> http::ClientExchange, http::Error {
    var x, e = http::begin(s, "GET", str(url, path));
    if e.code == 0 { e = http::response(s, x); }
    return x, e;
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

    var x, e = get(s, url, "/big");
    let total, same, most, held, re = drain(s, x, 4096);
    print("5 MB: ", re.code, ", ", total == BIG, ", the same bytes ", same, ", at most ", most,
          " a read, held at most 16 KB ", held <= 16384);
    http::end(s, x);
    print("  kept: ", s.s.fd >= 0);

    x, e = get(s, url, "/chunked");
    let body, ce = text_of(s, x);
    print("chunked: ", ce.code, ", \"", body, "\", trailers \"", x.trailers, "\"");
    http::end(s, x);
    print("  kept: ", s.s.fd >= 0);

    x, e = get(s, url, "/interim");
    let fin, ie = text_of(s, x);
    print("after two 1xx: ", x.status, " \"", fin, "\"");
    http::end(s, x);

    x, e = get(s, url, "/close");
    let rest, le = text_of(s, x);
    print("to the close: ", le.code, " \"", rest, "\"");
    http::end(s, x);
    print("  kept: ", s.s.fd >= 0);

    x, e = get(s, url, "/half");
    var some: u8[10000] = [0; 10000];
    let n, he = http::read(s, x, some);
    http::end(s, x);
    print("half read: ", n, ", kept ", s.s.fd >= 0);
    x, e = get(s, url, "/who");
    let who, we = text_of(s, x);
    http::end(s, x);
    print("  the next: ", who);

    x, e = get(s, url, "/short");
    let cut, se = text_of(s, x);
    print("cut short: ", se.call, ", kept ", s.s.fd >= 0);

    s.max_body = 1000;
    x, e = get(s, url, "/big");
    print("past max_body: ", e.call, " ", x.failed);
    s.max_body = 16 << 20;

    // A request begun again before the first ended takes a connection of its
    // own, and the first fails without touching it.
    var first, fe = http::begin(s, "GET", str(url, "/who"));
    let second, se2 = http::get(s, str(url, "/who"));
    var leftover: u8[64] = [0; 64];
    let ln, le = http::read(s, first, leftover);
    http::end(s, first);
    let third, te = http::get(s, str(url, "/who"));
    print("begun again before the end: the second on ", second.body, ", the first ", le.call,
          ", the third on ", third.body);

    var chain: u8[>..] = [];
    var key: u8[>..] = [];
    let failed = tls::run() {
        let k = tls::key_generate(tls::P256);
        chain = tls::self_signed(k, ["localhost"], 1);
        key = tls::key_pem(k);
        tls::free(k);
    };
    assert(failed.len == 0);
    let ctx, cok = tls::server(chain, key, ["http/1.1"]);
    assert(cok);
    var dir: u8[>..] = [];
    var secure: u8[>..] = [];
    if env("TMPDIR", dir) && dir.len > 0 { format(secure, "unix:", dir, "/t.sock"); } else { secure.append("unix:t.sock"); }
    let w = thread_spawn(tls_worker, http::Config { address: secure, workers: 1, tls: true, .. }, ctx);
    var ts, trusted = http::session_trusting(chain, 5000);
    assert(trusted);
    ts.via.append(secure);
    for i in 500 {
        x, e = http::begin(ts, "GET", "https://localhost/");
        if e.code == 0 { break; }
        sleep_ms(10);
    }
    let t2, s2, m2, h2, e2 = drain(ts, x, 3000);
    print("2 MB over TLS: ", e2.code, ", ", t2 == 2 << 20, ", the same bytes ", s2, ", at most ", m2, " a read");
    http::end(ts, x);
    http::free(ts);
    http::stop();
    thread_wait(w);
    tls::free(ctx);

    let q, qe = get(s, url, "/quit");
    http::free(s);
    thread_wait(t);
    http::net_close(lfd);
}
