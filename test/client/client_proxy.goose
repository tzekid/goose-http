// Session.proxy against a forward proxy in the program, which answers an
// http:// request itself with what it was sent, and tunnels CONNECT to the
// package's TLS server: two requests on one connection to the proxy, the
// whole URL in each request line and the proxy's credentials beside them; a
// redirect to another origin, which drops the origin's credentials but not
// the proxy's; an https:// request through a tunnel, with TLS checking the
// URL's host; wrong credentials (407); deny with a proxy; and a proxy that
// isn't http://.
import std;
import http from "../../";
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import http.tls;
import http.client;

fn send_text(fd: i32, text: const u8[:]) {
    var s = http::Socket { fd: fd };
    http::send_all(s, text, 5000);
}

// The value of field name in head, or "".
fn field(head: const u8[:], name: const u8[:]) -> const u8[:] {
    let at = find(head, str("\r\n", name, ": "));
    guard at >= 0 else { return ""; }
    let rest = head[at + name.len + 4..];
    return rest[..find(rest, "\r\n")];
}

// Copies bytes each way between a and b until one closes.
fn splice(a: i32, b: i32) {
    var buf: u8[>..] = [];
    buf.resize(16384, 0);
    let fds: i64[2] = [a as i64, b as i64];
    loop {
        let r = http::net_poll_any(fds, http::READABLE, 10000);
        if r <= 0 { return; }
        let from = fds[r - 1] as i32;
        let to = fds[2 - r] as i32;
        let n = http::net_recv(from, buf);
        if n == -http::EAGAIN { continue; }
        if n <= 0 { return; }
        send_text(to, buf[..n]);
    }
}

thread_fn proxy(lfd: i32, origin_port: i64) {
    var serial = 0;
    loop {
        let fd = http::net_accept(lfd, 0);
        assert(fd >= 0);
        serial++;
        var served = 0;
        var held: u8[>..] = [];
        var buf: u8[>..] = [];
        buf.resize(4096, 0);
        loop {
            while find(held, "\r\n\r\n") < 0 {
                let n = http::net_recv(fd, buf);
                if n <= 0 { break; }
                held.append(buf[..n]);
            }
            let end = find(held, "\r\n\r\n");
            if end < 0 { break; }
            var head: u8[>..] = [];
            head.append(held[..end + 2]);
            var rest: u8[>..] = [];
            rest.append(held[end + 4..]);
            held.clear();
            held.append(rest);
            let line = head[..find(head, "\r\n")];
            if line == "GET /quit HTTP/1.1" {
                http::net_close(fd);
                return;
            }
            let auth = field(head, "Proxy-Authorization");
            if starts_with(line, "CONNECT ") {
                if auth != "Basic dXNlcjpwQHNz" {
                    send_text(fd, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n");
                    break;
                }
                var origin, e = http::connect("127.0.0.1", origin_port, 5000);
                assert(e.code == 0);
                send_text(fd, "HTTP/1.1 200 Connection Established\r\n\r\n");
                splice(fd, origin.fd);
                http::hangup(origin);
                break;
            }
            served++;
            var body: u8[>..] = [];
            format(body, "connection ", serial, ", request ", served, ": ", line, "; proxy auth ", auth,
                   "; host ", field(head, "Host"), "; origin auth ", field(head, "Authorization"));
            var out: u8[>..] = [];
            if find(line, "/moved") >= 0 {
                format(out, "HTTP/1.1 302 Found\r\nLocation: http://other.example/landing\r\nContent-Length: 0\r\n\r\n");
            } else {
                format(out, "HTTP/1.1 200 OK\r\nContent-Length: ", body.len, "\r\n\r\n", body);
            }
            send_text(fd, out);
        }
        http::net_close(fd);
    }
}

thread_fn tls_worker(cfg: http::Config, ctx: tls::Context) {
    var server = http::tls_server(ctx);
    let e = http::serve_epoll(cfg, server) { req, body, out =>
        let host, has = http::field_of(req, "Host");
        let colon = find(host, ":");
        http::respond(out, 200, "text/plain", str("secure ", req.target, "; host ", if colon >= 0 { host[..colon] } else { host }));
    };
    http::release(server);
    if e.code != 0 { http::report(e); }
}

fn free_port() -> i64 {
    let a, ok = http::address("127.0.0.1");
    let fd = http::net_listen(a.ip, 0, 1, 0);
    let port = http::net_port(fd);
    http::net_close(fd);
    return port;
}

fn show(name: const u8[:], r: const http::ClientResponse&, e: http::Error) {
    if e.code != 0 { print(name, ": failed: ", e.call, " ", e.code); return; }
    print(name, ": ", r.status, " ", r.body);
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
    let origin_port = free_port();
    let w = thread_spawn(tls_worker, http::Config { address: "127.0.0.1", port: origin_port as i32, workers: 1, tls: true, .. }, ctx);

    let a, aok = http::address("127.0.0.1");
    let lfd = http::net_listen(a.ip, 0, 16, 0);
    assert(lfd >= 0);
    let proxy_port = http::net_port(lfd);
    let t = thread_spawn(proxy, lfd, origin_port);
    for i in 500 {
        var probe, pe = http::connect("127.0.0.1", origin_port, 1000);
        http::hangup(probe);
        if pe.code == 0 { break; }
        sleep_ms(10);
    }

    var s, trusted = http::session_trusting(chain, 5000);
    assert(trusted);
    format(s.proxy, "http://user:p%40ss@127.0.0.1:", proxy_port);
    let r1, e1 = http::get(s, "http://origin.example/page?q=1");
    show("http", r1, e1);
    let r2, e2 = http::get(s, "http://origin.example/again") { req => http::bearer(req, "k-1"); };
    show("http again", r2, e2);
    s.redirects = 2;
    let r3, e3 = http::get(s, "http://origin.example/moved") { req => http::bearer(req, "k-1"); };
    show("redirected", r3, e3);

    var url: u8[>..] = [];
    format(url, "https://localhost:", origin_port, "/hello");
    let r4, e4 = http::get(s, url);
    show("https, tunneled", r4, e4);
    // The proxy serves one connection at a time: let the tunnel go.
    http::hangup(s);

    var wrong, ok2 = http::session_trusting(chain, 5000);
    format(wrong.proxy, "http://user:nope@127.0.0.1:", proxy_port);
    let r5, e5 = http::get(wrong, url);
    print("wrong credentials: ", e5.call, " ", e5.code == http::EACCES);
    wrong.proxy.clear();
    format(wrong.proxy, "http://127.0.0.1:", proxy_port);
    wrong.deny = http::DENY_PRIVATE;
    let r6, e6 = http::get(wrong, "http://origin.example/");
    print("deny with a proxy: ", e6.call);
    wrong.deny = 0;
    wrong.proxy.clear();
    wrong.proxy.append("socks5://127.0.0.1:1080");
    let r7, e7 = http::get(wrong, "http://origin.example/");
    print("not an http:// proxy: ", e7.call);
    http::free(wrong);

    s.proxy.clear();
    var quit: u8[>..] = [];
    format(quit, "http://127.0.0.1:", proxy_port, "/quit");
    s.ms = 1000;
    let q, qe = http::get(s, quit);
    http::free(s);
    thread_wait(t);
    http::net_close(lfd);
    http::stop();
    thread_wait(w);
    tls::free(ctx);
}
