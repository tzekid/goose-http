// http.client_decoding against the package's own server, which compresses by
// Accept-Encoding (http.compression), and a peer in the program that sends
// what that server doesn't: a whole gzip body, and a streamed one flushed
// piece by piece, read 1,000 bytes at a time; then from the peer, a zlib body
// (HTTP's deflate), an identity body, a gzip body whose CRC is wrong, one cut
// short, br, a chain of two codings, and 10 MB of zeros against a 1 MB limit.
import std;
import os;
import http from "../../";
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import compress from "github.com/tzekid/goose-compress@0d31e4f6360f9ac6e2a3464bb2457f527d6e27cc";
import http.compression;
import http.client;
import http.client_decoding;

struct St {
    coded: http::Compressed = http::Compressed { .. },
    next: i64 = 0,
    last: i64 = 0,
}

fn report() -> u8[>..] {
    var body: u8[>..] = [];
    body.push('[');
    for i in 200 {
        if i > 0 { body.push(','); }
        format(body, "{\"id\":", i + 1, ",\"status\":\"ok\"}");
    }
    body.push(']');
    return body;
}

fn handle(ev: http::Event, st: St&, out: http::Reply) {
    if ev.kind == http::REQUEST {
        if http::path_of(ev.req.target) == "/report" {
            http::respond_compressed(out, ev.req, 200, "application/json", report());
        } else {
            http::begin_compressed(out, ev.req, 200, "text/plain", st.coded);
            st.next = 1;
            st.last = 20000;
        }
    } else if ev.kind == http::MORE {
        var piece: u8[>..] = [];
        while st.next <= st.last && piece.len < 16384 {
            format(piece, st.next, "\n");
            st.next++;
        }
        http::send_compressed(out, st.coded, piece);
        if st.next > st.last { http::end_compressed(out, st.coded); }
    } else if ev.kind == http::CLOSED {
        http::release_compressed(st.coded);
    }
}

thread_fn worker(cfg: http::Config) {
    let e = http::serve_epoll(cfg, St { .. }) { ev, st, out => handle(ev, st, out); };
    if e.code != 0 { http::report(e); }
}

fn send_text(fd: i32, text: const u8[:]) {
    var s = http::Socket { fd: fd };
    http::send_all(s, text, 5000);
}

// Answers each request by its path with a body coded as the path says.
thread_fn peer(lfd: i32) {
    var buf: u8[>..] = [];
    buf.resize(4096, 0);
    loop {
        let fd = http::net_accept(lfd, 0);
        assert(fd >= 0);
        let n = http::net_recv(fd, buf);
        if n <= 0 {
            http::net_close(fd);
            continue;
        }
        let req = buf[..n];
        let path = req[4..find(req, " HTTP/")];
        if path == "/quit" {
            http::net_close(fd);
            return;
        }
        var plain: u8[>..] = [];
        plain.append("coded by the peer, ");
        for i in 50 { plain.append("again and again, "); }
        var body: u8[>..] = [];
        var coding = "gzip";
        if path == "/deflate" {
            compress::compress(plain, body, compress::ZLIB, 6);
            coding = "deflate";
        } else if path == "/identity" {
            body.append(plain);
            coding = "identity";
        } else if path == "/bomb" {
            var zeros: u8[>..] = [];
            zeros.resize(10 << 20, 0);
            compress::compress(zeros, body, compress::GZIP, 6);
        } else {
            compress::compress(plain, body, compress::GZIP, 6);
            if path == "/crc" { body[body.len - 6] = body[body.len - 6] ^ 0x40; }
            if path == "/short" { body.resize(body.len - 12); }
            if path == "/br" { coding = "br"; }
            if path == "/chain" { coding = "gzip, gzip"; }
        }
        var out: u8[>..] = [];
        format(out, "HTTP/1.1 200 OK\r\nContent-Encoding: ", coding, "\r\nContent-Length: ", body.len,
               "\r\nConnection: close\r\n\r\n");
        out.append(body);
        send_text(fd, out);
        http::net_close(fd);
    }
}

fn expected_count() -> u8[>..] {
    var t: u8[>..] = [];
    for i in 20000 { format(t, i + 1, "\n"); }
    return t;
}

fn main() {
    var dir: u8[>..] = [];
    var address: u8[>..] = [];
    if env("TMPDIR", dir) && dir.len > 0 { format(address, "unix:", dir, "/d.sock"); } else { address.append("unix:d.sock"); }
    let w = thread_spawn(worker, http::Config { address: address, workers: 1, .. });
    var s = http::session(5000);
    s.via.append(address);
    for i in 500 {
        var probe, pe = http::connect(address, 0, 1000);
        http::hangup(probe);
        if pe.code == 0 { break; }
        sleep_ms(10);
    }

    var r, e = http::get(s, "http://localhost/report") { req => http::accept_compressed(req); };
    let field, has = http::header(r, "Content-Encoding");
    let coding = str(field);
    let sent = r.body.len;
    if e.code == 0 { e = http::decode_body(r); }
    print("a whole body: ", e.code, ", ", coding, ", ", sent, " bytes sent, the same JSON ", r.body == report());

    var x, xe = http::begin(s, "GET", "http://localhost/count") { req => http::accept_compressed(req); };
    var b = http::BodyDecoder { .. };
    var all: u8[>..] = [];
    var most = 0;
    while xe.code == 0 {
        var piece: u8[>..] = [];
        let n, re = http::read_decoded(s, x, b, piece, 1000);
        xe = re;
        if n == 0 { break; }
        most = max(most, n);
        all.append(piece);
    }
    let streamed, shas = http::field_in(x.fields, "Content-Encoding");
    http::end(s, x);
    print("a streamed body: ", xe.code, ", ", streamed, ", the same lines ", all == expected_count(),
          ", at most ", most, " bytes a read");
    http::free(s);
    http::stop();
    thread_wait(w);

    let a, ok = http::address("127.0.0.1");
    let lfd = http::net_listen(a.ip, 0, 16, 0);
    let t = thread_spawn(peer, lfd);
    var base: u8[>..] = [];
    format(base, "http://127.0.0.1:", http::net_port(lfd));
    var p = http::session(5000);
    for path in ["/deflate", "/identity", "/crc", "/short", "/br", "/chain"] {
        var pr, pe = http::get(p, str(base, path)) { req => http::accept_compressed(req); };
        if pe.code == 0 { pe = http::decode_body(pr); }
        if pe.code == 0 { print(path, ": ", pr.body.len, " bytes, ", starts_with(pr.body, "coded by the peer")); }
        else { print(path, ": failed: ", pe.call); }
    }
    var bomb, be = http::get(p, str(base, "/bomb")) { req => http::accept_compressed(req); };
    let bomb_sent = bomb.body.len;
    if be.code == 0 { be = http::decode_body(bomb, 1 << 20); }
    print("10 MB of zeros, sent in under 20 KB ", bomb_sent < 20000, ", against a 1 MB limit: ", be.call);
    var bx, bxe = http::begin(p, "GET", str(base, "/bomb")) { req => http::accept_compressed(req); };
    var bd = http::BodyDecoder { limit: 1 << 20, .. };
    var made = 0;
    while bxe.code == 0 {
        var piece: u8[>..] = [];
        let n, re = http::read_decoded(p, bx, bd, piece, 65536);
        bxe = re;
        if n == 0 { break; }
        made += n;
    }
    print("  read in pieces: ", bxe.call, ", having made no more than the limit ", made <= 1 << 20);
    http::end(p, bx);
    let q, qe = http::get(p, str(base, "/quit"));
    http::free(p);
    thread_wait(t);
    http::net_close(lfd);
}
