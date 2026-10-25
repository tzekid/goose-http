// The classes of address connect's deny refuses (socket.goose), and
// Session.deny: address_class over addresses of each class, written each way
// that holds an IPv4 address in IPv6; connect to a listener on loopback, as
// a literal, as a name, and as a Unix socket, refused and allowed; and a
// session refused at a redirect to a private address, which no connect is
// tried for.
import std;
import os;
import http from "../../";
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import http.client;

let ADDRESSES = [
    "8.8.8.8", "2606:4700::1111", "172.32.0.1", "100.128.0.1",
    "127.0.0.1", "127.255.255.254", "0.0.0.0", "::1", "::",
    "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1", "fc00::1", "fd12:3456::1",
    "169.254.169.254", "fe80::1",
    "224.0.0.1", "255.255.255.255", "240.0.0.1", "192.0.2.1", "198.18.0.1", "198.51.100.7", "203.0.113.9",
    "ff02::1", "2001:db8::1", "2001::1", "fec0::1", "100::1", "::a00:1",
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::a00:1", "2002:7f00:1::",
    "2002:0808:0808::",
];

thread_fn server(cfg: http::Config) {
    let e = http::serve(cfg) { req, body, out =>
        if http::path_of(req.target) == "/private" {
            http::start(out, 302);
            http::field(out, "Location", "http://10.0.0.1/");
            http::finish(out, http::NO_TYPE, "");
        } else {
            http::respond(out, 200, "text/plain", "ok");
        }
    };
    if e.code != 0 { http::report(e); }
}

fn tried(name: const u8[:], s: http::Socket&, e: http::Error) {
    if e.code == 0 { print(name, ": connected"); } else { print(name, ": ", e.call, " ", e.code == http::EACCES); }
    http::hangup(s);
}

fn main() {
    print("== classes");
    for text in ADDRESSES {
        let a, ok = http::address(text);
        assert(ok);
        print(text, " ", http::address_class(a.ip));
    }

    let a, ok = http::address("127.0.0.1");
    assert(ok);
    let lfd = http::net_listen(a.ip, 0, 64, 0);
    assert(lfd >= 0);
    let port = http::net_port(lfd);
    http::net_close(lfd);
    var dir: u8[>..] = [];
    var unix: u8[>..] = [];
    if env("TMPDIR", dir) && dir.len > 0 { format(unix, "unix:", dir, "/d.sock"); } else { format(unix, "unix:d.sock"); }
    let w = [
        thread_spawn(server, http::Config { address: "127.0.0.1", port: port as i32, workers: 1, .. }),
        thread_spawn(server, http::Config { address: unix, workers: 1, .. }),
    ];
    for i in 500 {
        var s, e = http::connect("127.0.0.1", port, 1000);
        http::hangup(s);
        var u, f = http::connect(unix, 0, 1000);
        http::hangup(u);
        if e.code == 0 && f.code == 0 { break; }
        sleep_ms(10);
    }

    print("== connect");
    var s, e = http::connect("127.0.0.1", port, 1000, http::DENY_NON_PUBLIC);
    tried("127.0.0.1, non-public", s, e);
    s, e = http::connect("127.0.0.1", port, 1000, http::DENY_PRIVATE | http::DENY_LINK_LOCAL);
    tried("127.0.0.1, private and link-local", s, e);
    s, e = http::connect("[::ffff:127.0.0.1]", port, 1000, http::DENY_LOOPBACK);
    tried("::ffff:127.0.0.1, loopback", s, e);
    s, e = http::connect("LOCALHOST", port, 1000, http::DENY_LOOPBACK);
    tried("the name LOCALHOST, loopback", s, e);
    s, e = http::connect(unix, 0, 1000, http::DENY_LOOPBACK);
    tried("a Unix socket, loopback", s, e);
    s, e = http::connect(unix, 0, 1000, http::DENY_PRIVATE);
    tried("a Unix socket, private", s, e);

    print("== session");
    var session = http::session(1000);
    var url: u8[>..] = [];
    format(url, "http://127.0.0.1:", port, "/");
    let r1, e1 = http::get(session, url);
    print("no deny: ", r1.status, " ", r1.body);
    session.deny = http::DENY_NON_PUBLIC;
    let r2, e2 = http::get(session, url);
    print("deny, the open connection not reused: ", e2.call, " ", e2.code == http::EACCES);
    session.deny = http::DENY_PRIVATE;
    session.redirects = 2;
    var private: u8[>..] = [];
    format(private, "http://127.0.0.1:", port, "/private");
    let r3, e3 = http::get(session, private);
    print("a redirect to 10.0.0.1: ", e3.call, " ", e3.code == http::EACCES);
    session.via.append(unix);
    session.deny = http::DENY_LOOPBACK;
    let r4, e4 = http::get(session, "http://example.com/");
    print("via a Unix socket: ", e4.call, " ", e4.code == http::EACCES);
    http::free(session);

    http::stop();
    for t in w { thread_wait(t); }
}
