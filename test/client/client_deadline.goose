// Session.total_ms against a peer that trickles each response's body, a byte
// every 40 ms, so no single wait runs out: without total_ms the response
// comes whole; with it, the request fails at its limit, and its connection
// is closed rather than reused by the next request.
import std;
import http from "../../";
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import http.client;

let BODY = 20;

fn send_text(fd: i32, text: const u8[:]) -> bool {
    var at = 0;
    while at < text.len {
        let n = http::net_send(fd, text[at..]);
        if n <= 0 { return false; }
        at += n;
    }
    return true;
}

// Answers each request on each connection, one connection at a time, with a
// body that names the connection, sent a byte at a time. A request for
// /quit ends it.
thread_fn peer(lfd: i32) {
    var buf: u8[>..] = [];
    buf.resize(4096, 0);
    var serial = 0;
    loop {
        let fd = http::net_accept(lfd, 0);
        assert(fd >= 0);
        serial++;
        loop {
            let n = http::net_recv(fd, buf);
            if n <= 0 { break; }
            if find(buf[..n], "/quit") >= 0 {
                http::net_close(fd);
                return;
            }
            var body: u8[>..] = [];
            format(body, "connection ", serial);
            while body.len < BODY { body.push('.'); }
            var head: u8[>..] = [];
            format(head, "HTTP/1.1 200 OK\r\nContent-Length: ", BODY, "\r\n\r\n");
            var sent = send_text(fd, head);
            for i in BODY {
                if !sent { break; }
                sleep_ms(40);
                sent = send_text(fd, body[i..i + 1]);
            }
            if !sent { break; }
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
    format(url, "http://127.0.0.1:", http::net_port(lfd), "/slow");
    let t = thread_spawn(peer, lfd);

    var session = http::session(300);
    let r1, e1 = http::get(session, url);
    print("each wait limited: ", e1.code, ", ", r1.status, ", ", r1.body);

    session.total_ms = 300;
    let began = http::net_clock_ms();
    let r2, e2 = http::get(session, url);
    let took = http::net_clock_ms() - began;
    print("in all limited: ", e2.call, " ", e2.code == http::ETIMEDOUT, ", status ", r2.status,
          ", before the body's end ", took < BODY * 40, ", closed ", session.s.fd < 0);

    session.total_ms = -1;
    let r3, e3 = http::get(session, url);
    print("the next request: ", e3.code, ", ", r3.status, ", ", r3.body);

    var quit: u8[>..] = [];
    format(quit, "http://127.0.0.1:", http::net_port(lfd), "/quit");
    session.ms = 1000;
    let r4, e4 = http::get(session, quit);
    http::free(session);
    thread_wait(t);
    http::net_close(lfd);
}
