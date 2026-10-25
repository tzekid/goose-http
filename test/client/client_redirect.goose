// Session.redirects against two servers in the program, on Unix sockets in
// TMPDIR, plain and TLS, which Session.via reaches whatever a URL's host: each
// redirect status, with its method and body after it; a Location relative
// to the request's path, with dot segments, and one that is a query; the
// fields that carry credentials at a redirect to another origin and to the
// same one; a loop, a downgrade from https, a Location of another scheme, a
// redirect without one, and a session that follows none.
import std;
import os;
import http from "../../";
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import http.tls;
import http.client;

// The redirect /r/<name> answers with, while its target has no query.
fn route(name: const u8[:]) -> i32, const u8[:] {
    if name == "301" { return 301, "/echo"; }
    if name == "302" { return 302, "../echo?from=302"; }
    if name == "303" { return 303, "/echo"; }
    if name == "307" { return 307, "/echo"; }
    if name == "308" { return 308, "/echo"; }
    if name == "query" { return 302, "?q=1"; }
    if name == "dots" { return 302, "./a/../../echo/./x/.."; }
    if name == "other" { return 307, "http://other.example/echo"; }
    if name == "same" { return 307, "//localhost/echo"; }
    if name == "loop" { return 302, "/r/loop"; }
    if name == "down" { return 302, "http://localhost/echo"; }
    if name == "ftp" { return 302, "ftp://localhost/echo"; }
    return 302, "";
}

fn handle(req: const http::Request&, body: const u8[:], out: http::Reply) {
    let path = http::path_of(req.target);
    if starts_with(path, "/r/") && find(req.target, "?") < 0 {
        let status, location = route(path[3..]);
        http::start(out, status);
        if location.len > 0 { http::field(out, "Location", location); }
        http::finish(out, http::NO_TYPE, "");
        return;
    }
    let host, h = http::field_of(req, "Host");
    let auth, a = http::field_of(req, "Authorization");
    let cookie, c = http::field_of(req, "Cookie");
    let key, k = http::field_of(req, "X-Key");
    let media, m = http::field_of(req, "Content-Type");
    http::respond(out, 200, "text/plain", str(req.method, " ", req.target, " host=", host, " auth=", auth,
                                              " cookie=", cookie, " key=", key, " type=", media, " body=", body));
}

thread_fn plain_worker(cfg: http::Config) {
    let e = http::serve(cfg) { req, body, out => handle(req, body, out); };
    if e.code != 0 { http::report(e); }
}

thread_fn tls_worker(cfg: http::Config, ctx: tls::Context) {
    var server = http::tls_server(ctx);
    let e = http::serve_epoll(cfg, server) { req, body, out => handle(req, body, out); };
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

fn listening(address: const u8[:]) {
    for i in 500 {
        var s, e = http::connect(address, 0, 1000);
        if e.code == 0 {
            http::hangup(s);
            return;
        }
        sleep_ms(10);
    }
    abort(str("nothing listens at ", address));
}

fn show(name: const u8[:], response: const http::ClientResponse&, err: http::Error) {
    if err.code != 0 {
        print(name, ": failed: ", err.call, ", status ", response.status);
        return;
    }
    let location, has = http::header(response, "Location");
    print(name, ": ", response.status, if has { str(" to ", location) } else { str(": ", response.body) });
}

fn send(session: http::Session&, method: const u8[:], url: const u8[:]) {
    let r, e = http::request(session, method, url) { req =>
        http::bearer(req, "k-1");
        http::header(req, "Cookie", "id=7");
        http::header(req, "X-Key", "v");
        if method != "GET" { http::body(req, "text/plain", "data"); }
    };
    show(str(method, " ", url), r, e);
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
    // Short names: macOS's TMPDIR is long, and a socket's path takes 104 bytes.
    let plain = unix_address("p.sock");
    let secure = unix_address("t.sock");
    let w = [
        thread_spawn(plain_worker, http::Config { address: plain, workers: 1, .. }),
        thread_spawn(tls_worker, http::Config { address: secure, workers: 1, tls: true, .. }, ctx),
    ];
    listening(plain);
    listening(secure);

    print("== none followed");
    var session = http::session(5000);
    session.via.append(plain);
    send(session, "GET", "http://localhost/r/301");

    print("== followed");
    session.redirects = 3;
    send(session, "POST", "http://localhost/r/301");
    send(session, "POST", "http://localhost/r/302");
    send(session, "PUT", "http://localhost/r/303");
    send(session, "HEAD", "http://localhost/r/303");
    send(session, "POST", "http://localhost/r/307");
    send(session, "PUT", "http://localhost/r/308");
    send(session, "GET", "http://localhost/r/query");
    send(session, "GET", "http://localhost/r/dots");
    send(session, "GET", "http://localhost/r/other");
    send(session, "GET", "http://localhost/r/same");
    send(session, "GET", "http://localhost/r/none");

    print("== refused");
    send(session, "GET", "http://localhost/r/loop");
    send(session, "GET", "http://localhost/r/ftp");

    print("== https");
    var secured, trusted = http::session_trusting(chain, 5000);
    assert(trusted);
    secured.via.append(secure);
    secured.redirects = 3;
    send(secured, "GET", "https://localhost/r/307");
    send(secured, "GET", "https://localhost/r/down");

    http::free(secured);
    http::free(session);
    http::stop();
    for t in w { thread_wait(t); }
    tls::free(ctx);
}
