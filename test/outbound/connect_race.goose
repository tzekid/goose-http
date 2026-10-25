// race (socket.goose), the Happy Eyeballs connect behind connect's names:
// an address of a documentation network first, whose connect hangs or fails,
// and one that answers second, which wins long before the first's limit;
// 300 races between two addresses that both answer, each returning one
// socket and closing the other, which would run out of descriptors if a
// loser stayed open; and 300 races where no address answers.
import std;
import http from "../../";

// Accepts until a connection sends q, closing each.
thread_fn server(lfd: i32) {
    var buf: u8[1] = [0];
    loop {
        let fd = http::net_accept(lfd, 0);
        assert(fd >= 0);
        let n = http::net_recv(fd, buf);
        http::net_close(fd);
        if n == 1 && buf[0] == 'q' { return; }
    }
}

fn addresses(texts: const u8[:][:]) -> u8[>..] {
    var out: u8[>..] = [];
    for t in texts {
        let a, ok = http::address(t);
        assert(ok);
        out.append(a.ip);
    }
    return out;
}

fn main() {
    let any, ok = http::address("::");
    assert(ok);
    let lfd = http::net_listen(any.ip, 0, 128, 0);
    assert(lfd >= 0);
    let port = http::net_port(lfd);
    let t = thread_spawn(server, lfd);

    let slow = addresses(["192.0.2.1", "127.0.0.1"]);
    let began = http::net_clock_ms();
    var s, e = http::race(slow, port, http::deadline(5000));
    print("a documentation address first: ", e.code, ", within 1.5 s ", http::net_clock_ms() - began < 1500);
    http::hangup(s);

    let both = addresses(["::1", "127.0.0.1"]);
    var won = 0;
    for i in 300 {
        var w, we = http::race(both, port, http::deadline(5000));
        if we.code == 0 { won++; }
        http::hangup(w);
    }
    print("300 races that both answer: ", won, " won");

    let gone = http::net_listen(any.ip, 0, 1, 0);
    let gone_port = http::net_port(gone);
    http::net_close(gone);
    var refused = 0;
    for i in 300 {
        var f, fe = http::race(both, gone_port, http::deadline(5000));
        if fe.code == http::ECONNREFUSED && f.fd < 0 { refused++; }
    }
    print("300 races that none answers: ", refused, " refused");

    var q, qe = http::connect("127.0.0.1", port, 5000);
    assert(qe.code == 0);
    http::send_all(q, "q", 5000);
    thread_wait(t);
    http::hangup(q);
    http::net_close(lfd);
}
