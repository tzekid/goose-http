// Session.max_idle and idle_ms against three peers in the program, each of
// which names the connection a request came on: two origins in turn with
// none kept, and with two; a kept connection past idle_ms; three origins
// with one kept; a connection in an exchange begin started, which isn't
// kept; and a deny that changed, after which a kept connection isn't reused.
import std;
import http from "../../";
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import http.client;

fn send_text(fd: i32, text: const u8[:]) {
    var s = http::Socket { fd: fd };
    http::send_all(s, text, 5000);
}

// Serves every connection to lfd at once, as kept connections stay open,
// answering each request with name and the connection's number.
thread_fn peer(lfd: i32, name: u8) {
    var fds: i64[>..] = [lfd];
    var serials: i64[>..] = [0];
    var serial = 0;
    var buf: u8[>..] = [];
    buf.resize(4096, 0);
    loop {
        let r = http::net_poll_any(fds, http::READABLE, -1);
        if r <= 0 { continue; }
        let i = r - 1;
        if i == 0 {
            let fd = http::net_accept(lfd, 0);
            assert(fd >= 0);
            serial++;
            fds.push(fd);
            serials.push(serial);
            continue;
        }
        let fd = fds[i] as i32;
        let n = http::net_recv(fd, buf);
        if n <= 0 || find(buf[..n], "/quit") >= 0 {
            http::net_close(fd);
            fds[i] = fds[fds.len - 1];
            serials[i] = serials[serials.len - 1];
            fds.resize(fds.len - 1);
            serials.resize(serials.len - 1);
            if n > 0 {
                for j in fds.len - 1 { http::net_close(fds[j + 1] as i32); }
                return;
            }
            continue;
        }
        var body: u8[>..] = [];
        body.push(name);
        format(body, serials[i]);
        var out: u8[>..] = [];
        format(out, "HTTP/1.1 200 OK\r\nContent-Length: ", body.len, "\r\n\r\n", body);
        send_text(fd, out);
    }
}

fn get(s: http::Session&, urls: const u8[..64][3]&, which: i64) -> u8[>..] {
    let r, e = http::get(s, urls[which]);
    var t: u8[>..] = [];
    if e.code != 0 { format(t, "failed ", e.call); } else { t.append(r.body); }
    return t;
}

fn run(s: http::Session&, urls: const u8[..64][3]&, order: const i64[:]) {
    var line: u8[>..] = [];
    for w in order {
        if line.len > 0 { line.append(" "); }
        line.append(get(s, urls, w));
    }
    print("  ", line);
}

fn main() {
    let a, ok = http::address("127.0.0.1");
    assert(ok);
    var lfds: i32[3] = [0; 3];
    var urls: u8[..64][3] = [[], [], []];
    var threads: i64[>..] = [];
    for i in 3 {
        lfds[i] = http::net_listen(a.ip, 0, 16, 0);
        assert(lfds[i] >= 0);
        format(urls[i], "http://127.0.0.1:", http::net_port(lfds[i]), "/");
        threads.push(thread_spawn(peer, lfds[i], ('A' + i) as u8));
    }

    print("none kept, A B A B:");
    var s = http::session(5000);
    run(s, urls, [0, 1, 0, 1]);
    http::free(s);

    print("two kept, A B A B:");
    s = http::session(5000);
    s.max_idle = 2;
    run(s, urls, [0, 1, 0, 1]);
    print("past idle_ms, A B, a pause, A:");
    s.idle_ms = 100;
    run(s, urls, [0, 1]);
    sleep_ms(250);
    run(s, urls, [0]);
    http::free(s);

    print("one kept, A B C A B:");
    s = http::session(5000);
    s.max_idle = 1;
    run(s, urls, [0, 1, 2, 0, 1]);
    http::free(s);

    print("an exchange not ended, A, then B A:");
    s = http::session(5000);
    s.max_idle = 2;
    var x, e = http::begin(s, "GET", urls[0]);
    e = http::response(s, x);
    run(s, urls, [1, 0]);
    http::free(s);

    print("deny changed, A B, then A:");
    s = http::session(5000);
    s.max_idle = 2;
    run(s, urls, [0, 1]);
    s.deny = http::DENY_PRIVATE;
    run(s, urls, [0]);
    http::free(s);

    for i in 3 {
        var q = http::session(1000);
        let r, qe = http::get(q, str(urls[i], "quit"));
        http::free(q);
    }
    for t in threads { thread_wait(t); }
    for fd in lfds { http::net_close(fd); }
}
