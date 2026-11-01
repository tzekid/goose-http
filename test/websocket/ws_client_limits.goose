// http.websocket_client's limits, against a peer in the program: WsClient.limit
// -1, which takes any message; 4 MB of pongs before a message, which a
// ws_receive with a limit of 1,024 reads through, holding a frame and a read
// at a time; ws_close's reason, cut at 123 bytes where a character starts; a
// Close code that's never sent; and an op that ws_send doesn't send.
import std;
import os;
import http from "../../";
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import http.websocket;
import http.websocket_client;

fn send_all(fd: i32, data: const u8[:]) {
    var s = http::Socket { fd: fd };
    http::send_all(s, data, 10000);
}

fn frame(out: u8[>..]&, op: u8, payload: const u8[:]) {
    out.push(0x80 | op);
    out.push(payload.len as! u8);
    out.append(payload);
}

// Reads the client's next frame, unmasked, into payload; returns its opcode
// or -1.
fn read_frame(fd: i32, held: u8[>..]&, payload: u8[>..]&) -> i64 {
    var buf: u8[4096] = [0; 4096];
    loop {
        if held.len >= 6 && (held[1] & 0x7F) < 126 && held.len >= 6 + (held[1] & 0x7F) as i64 {
            let n = (held[1] & 0x7F) as i64;
            payload.clear();
            for i in n { payload.push(held[6 + i] ^ held[2 + (i & 3)]); }
            let op = (held[0] & 0x0F) as i64;
            var rest: u8[>..] = [];
            rest.append(held[6 + n..]);
            held.clear();
            held.append(rest);
            return op;
        }
        var s = http::Socket { fd: fd };
        let n = http::recv(s, buf, 5000);
        if n <= 0 { return -1; }
        held.append(buf[..n]);
    }
}

thread_fn peer(lfd: i32, flood_mb: i64) {
    loop {
        let fd = http::net_accept(lfd, 0);
        assert(fd >= 0);
        var head: u8[>..] = [];
        var buf: u8[4096] = [0; 4096];
        while find(head, "\r\n\r\n") < 0 {
            var s = http::Socket { fd: fd };
            let n = http::recv(s, buf, 5000);
            assert(n > 0);
            head.append(buf[..n]);
        }
        let path = head[4..find(head, " HTTP/")];
        if path == "/quit" {
            http::net_close(fd);
            return;
        }
        let k = find(head, "Sec-WebSocket-Key: ") + 19;
        var out: u8[>..] = [];
        format(out, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n",
               "Sec-WebSocket-Accept: ", http::ws_accept(head[k..k + 24]), "\r\n\r\n");
        send_all(fd, out);
        out.clear();
        if path == "/flood" {
            var pongs: u8[>..] = [];
            for i in 32768 { pongs.push(0x8A); pongs.push(0); }
            for i in flood_mb * 16 { send_all(fd, pongs); }
        }
        if path != "/reason" {
            frame(out, http::WS_TEXT, "hi");
            send_all(fd, out);
        }
        var held: u8[>..] = [];
        var payload: u8[>..] = [];
        loop {
            let op = read_frame(fd, held, payload);
            if op < 0 { break; }
            if op == 8 {
                if path == "/reason" {
                    var state: u32 = 0;
                    let valid = payload.len >= 2 && http::ws_utf8(payload[2..], state) && state == 0;
                    print("peer: the client's Close reason has ", payload.len - 2, " bytes, valid UTF-8 ", valid);
                }
                var close: u8[>..] = [];
                frame(close, 8, payload[..min(payload.len, 2)]);
                send_all(fd, close);
                break;
            }
        }
        http::net_close(fd);
    }
}

fn main() {
    let flood_mb = 4;
    let a, ok = http::address("127.0.0.1");
    assert(ok);
    let lfd = http::net_listen(a.ip, 0, 16, 0);
    assert(lfd >= 0);
    let port = http::net_port(lfd);
    let t = thread_spawn(peer, lfd, flood_mb);
    var s = http::session(10000);
    var message: u8[>..] = [];

    var ws, e = http::ws_connect(s, str("ws://127.0.0.1:", port, "/hi"));
    ws.limit = -1;
    let op, re = http::ws_receive(ws, message);
    print("ws_receive of 'hi' with limit -1: op ", op, ", '", re.call, "', message '", message, "'");
    let se = http::ws_send(ws, http::WS_PING, "");
    print("ws_send of a ping: '", se.call, "'");
    let be = http::ws_close(ws, 1005);
    print("ws_close with 1005: '", be.call, "'");
    http::ws_close(ws);

    var flooded, fe = http::ws_connect(s, str("ws://127.0.0.1:", port, "/flood"));
    flooded.limit = 1024;
    let fop, fre = http::ws_receive(flooded, message);
    print(flood_mb, " MB of pongs, limit 1024: op ", fop, ", '", fre.call, "', message '", message, "'");
    http::ws_close(flooded);

    var ws2, e2 = http::ws_connect(s, str("ws://127.0.0.1:", port, "/reason"));
    var reason: u8[>..] = [];
    for i in 122 { reason.push('a'); }
    reason.append("é");
    let ce = http::ws_close(ws2, 1000, reason);
    print("ws_close with a ", reason.len, "-byte reason: '", ce.call, "'");

    var q, qe = http::ws_connect(s, str("ws://127.0.0.1:", port, "/quit"));
    http::free(s);
    thread_wait(t);
    http::net_close(lfd);
}
