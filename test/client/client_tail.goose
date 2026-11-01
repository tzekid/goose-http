// Bytes a server sends after a response's body, in the same write as the
// body's end, over plain TCP and over TLS, where TLS decrypts them past what
// the body's read asked for. The head goes first and the body later, so the
// client reads the body after the head. The next request on the session
// doesn't read those bytes as its response, but goes on a new connection.
import std;
import http from "../../";
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import http.client;

let TAIL = "helloHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nevil";

fn send_text(fd: i32, text: const u8[:]) -> bool {
    var s = http::Socket { fd: fd };
    let e = http::send_all(s, text, 5000);
    return e.code == 0;
}

fn flush(fd: i32, c: tls::Conn) -> bool {
    var wire: u8[16384] = [0; 16384];
    loop {
        let n = tls::drain(c, wire);
        if n <= 0 { return true; }
        if !send_text(fd, wire[..n]) { return false; }
    }
}

// Reads from fd, through c when secure, until held has a request's head.
fn next_head(fd: i32, c: tls::Conn, secure: bool, held: u8[>..]&) -> i64 {
    var wire: u8[16384] = [0; 16384];
    var plain: u8[16384] = [0; 16384];
    loop {
        let end = find(held, "\r\n\r\n");
        if end >= 0 { return end; }
        if secure {
            let r = tls::read(c, plain);
            if r > 0 {
                held.append(plain[..r]);
                continue;
            }
            if r != tls::WANT_INPUT { return -1; }
        }
        var s = http::Socket { fd: fd };
        let n = http::recv(s, wire, 5000);
        if n <= 0 { return -1; }
        if secure {
            tls::feed(c, wire[..n]);
        } else {
            held.append(wire[..n]);
        }
    }
}

fn put(fd: i32, c: tls::Conn, secure: bool, text: const u8[:]) -> bool {
    if !secure { return send_text(fd, text); }
    tls::write(c, text);
    return flush(fd, c);
}

thread_fn peer(lfd: i32, secure: bool, ctx: tls::Context) {
    var serial = 0;
    loop {
        let fd = http::net_accept(lfd, 0);
        assert(fd >= 0);
        serial++;
        var c = tls::Conn { .. };
        var good = true;
        if secure {
            c = tls::accept(ctx);
            var wire: u8[16384] = [0; 16384];
            loop {
                let r = tls::handshake(c);
                if !flush(fd, c) { good = false; break; }
                if r == 0 { break; }
                if r != tls::WANT_INPUT { good = false; break; }
                var s = http::Socket { fd: fd };
                let n = http::recv(s, wire, 5000);
                if n <= 0 { good = false; break; }
                tls::feed(c, wire[..n]);
            }
        }
        var held: u8[>..] = [];
        while good {
            let end = next_head(fd, c, secure, held);
            if end < 0 { break; }
            let line = held[..find(held, "\r\n")];
            let rest = line[find(line, " ") + 1..];
            var target: u8[>..] = [];
            target.append(rest[..find(rest, " ")]);
            var left: u8[>..] = [];
            left.append(held[end + 4..]);
            held.clear();
            held.append(left);
            if target == "/quit" {
                if secure { tls::free(c); }
                http::net_close(fd);
                return;
            }
            if target == "/one" {
                good = put(fd, c, secure, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
                sleep_ms(200);
                good = good && put(fd, c, secure, TAIL);
            } else {
                good = put(fd, c, secure, str("HTTP/1.1 200 OK\r\nContent-Length: ", 9 + str(serial).len,
                                              "\r\n\r\ngood conn", serial));
            }
        }
        if secure { tls::free(c); }
        http::net_close(fd);
    }
}

fn listener() -> i32 {
    let a, ok = http::address("127.0.0.1");
    assert(ok);
    let lfd = http::net_listen(a.ip, 0, 16, 0);
    assert(lfd >= 0);
    return lfd;
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
    let plain_fd = listener();
    let secure_fd = listener();
    let tp = thread_spawn(peer, plain_fd, false, ctx);
    let ts = thread_spawn(peer, secure_fd, true, ctx);

    var s, trusted = http::session_trusting(chain, 3000);
    assert(trusted);
    for secure in [false, true] {
        let scheme = if secure { "https" } else { "http" };
        let host = if secure { "localhost" } else { "127.0.0.1" };
        let port = http::net_port(if secure { secure_fd } else { plain_fd });
        let r1, e1 = http::get(s, str(scheme, "://", host, ":", port, "/one"));
        print(scheme, " /one: '", e1.call, "' ", r1.status, " '", r1.body, "', connection kept ", s.s.fd >= 0);
        let r2, e2 = http::get(s, str(scheme, "://", host, ":", port, "/two"));
        print(scheme, " /two: '", e2.call, "' ", r2.status, " '", r2.body, "'");
        http::hangup(s);
        let q, qe = http::get(s, str(scheme, "://", host, ":", port, "/quit"));
    }
    http::free(s);
    thread_wait(tp);
    thread_wait(ts);
    http::net_close(plain_fd);
    http::net_close(secure_fd);
    tls::free(ctx);
}
