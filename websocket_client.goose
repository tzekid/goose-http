// A WebSocket client (RFC 6455) for a thread that runs no loop, such as a
// lane's or a command-line program's: each call blocks, with the session's
// limit on each wait. Only a program that imports this module needs
// goose-tls and goose-hash, which its root file declares at the tags
// client.goose and websocket.goose name:
//
//   import http from "github.com/kaitk/goose-http@<tag>";
//   import tls from "github.com/kaitk/goose-tls@v0.0.6";
//   import hash from "github.com/kaitk/goose-hash@v0.0.4";
//   import http.websocket_client;
//
//   var session = http::session();
//   var ws, err = http::ws_connect(session, "wss://example.com/feed") { req =>
//       http::bearer(req, token);
//   };
//   guard err.code == 0 else { ... }   // ws.status: the server's answer
//   http::ws_send(ws, http::WS_TEXT, "subscribe");
//   var message: u8[>..] = [];
//   let op, e = http::ws_receive(ws, message);   // WS_TEXT, WS_BINARY, or WS_CLOSE
//   http::ws_close(ws);
//   http::free(session);
//
// Every frame the client sends is masked with a key from the OS's secure
// random source, as §5.3 asks, and every frame it reads must be unmasked. No
// extension is offered, so a server that names one fails the handshake.
namespace http;

import std;
import base64;
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import message;
import socket;
import client;
import websocket;

// A WebSocket that ws_connect opened, on the connection it took from the
// session.
struct WsClient {
    // The connection, and conn.ms, the limit on each wait from the session.
    conn: Session = Session { .. },
    // The status the server answered the handshake with: 101 once open.
    status: i64 = 0,
    // The subprotocol the server chose, of those the handshake offered.
    protocol: u8[..128],
    // The longest message ws_receive takes, whether in one frame or several;
    // a longer one fails the connection with 1009.
    limit: i64 = 1 << 20,
    // The opcode of a message whose fragments are coming, or 0, and what its
    // UTF-8 so far leaves to check.
    op: u8 = 0,
    utf8: u32 = 0,
    // The code of the server's Close, 1005 for one without a code; 0 until
    // it comes.
    close_code: i32 = 0,
    // A Close was sent, and only the server's matters now; then the
    // connection is closed.
    closing: bool = false,
    done: bool = false,
    // Between calls of ws_receive: the message so far, its first joined
    // bytes, and then the bytes read past the last whole frame.
    joined: i64 = 0,
    held: u8[>..],
}

// Opens a WebSocket to url, ws:// or wss://, after F has added to the
// handshake's request, as a request's block does (client.goose): a GET with
// Upgrade: websocket and a new Sec-WebSocket-Key. To offer subprotocols, F
// adds Sec-WebSocket-Protocol; the one the server chose is ws.protocol. The
// session's ms, total_ms up to the server's answer, deny, via, and TLS trust
// apply; a redirect is an answer that isn't 101. Once the server has
// answered 101 with the right Sec-WebSocket-Accept, the connection is the
// WebSocket's, and the session holds none.
//
// A failure is an Error as a request's, and call "websocket" for an answer
// that doesn't open one, whose status is ws.status. The connection is
// closed then.
fn ws_connect<F>(s: Session&, url: const u8[:]) -> WsClient, Error {
    var ws = WsClient { .. };
    var lines: u8[>..] = [];
    var payload: u8[>..] = [];
    var req = ClientRequest { lines: lines, payload: payload };
    F(&req);
    guard req.refused.len == 0 && req.media.len == 0 && !ws_owns_field(req.lines) else {
        return ws, client_error(if req.media.len > 0 { "body" } else { "header" });
    }
    var http_url: u8[>..] = [];
    if starts_with(url, "ws://") { format(http_url, "http://", url[5..]); }
    else if starts_with(url, "wss://") { format(http_url, "https://", url[6..]); }
    let u, ok = parse_url(http_url);
    guard ok else { return ws, client_error("url"); }

    var nonce: u8[16] = [0; 16];
    hash::random_bytes(nonce);
    var key: u8[>..] = [];
    base64::encode(key, nonce);
    var wire: u8[>..] = [];
    format(wire, "GET ", u.target, " HTTP/1.1\r\nHost: ", u.authority, "\r\nUser-Agent: goose-http\r\n",
           "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ", key,
           "\r\nSec-WebSocket-Version: 13\r\n", req.lines, "\r\n");

    let until = deadline(s.total_ms);
    // Through a proxy, a WebSocket goes in a tunnel, whatever its scheme.
    var e = open(s, u, until, true);
    guard e.code == 0 else { return ws, e; }
    e = put(s, wire, until);
    guard e.code == 0 else {
        hangup(s);
        return ws, e;
    }
    var raw: u8[>..] = [];
    var buf: u8[16384] = [0; 16384];
    var eol = 0;
    var end = 0;
    while end == 0 {
        let n, got = take(s, buf, until);
        guard got.code == 0 && n > 0 else {
            hangup(s);
            return ws, if got.code != 0 { got } else { client_error("response") };
        }
        raw.append(buf[..n]);
        eol = line_end(raw, 0);
        if eol > 0 { end = trailer_end(raw, eol); }
        guard eol >= 0 && end >= 0 && (end > 0 || raw.len <= MAX_RESPONSE_HEAD) else {
            hangup(s);
            return ws, client_error("response");
        }
        guard end > 0 || !expired(until) else {
            hangup(s);
            return ws, Error { call: "recv", code: ETIMEDOUT };
        }
    }
    let status = raw[..eol - 2];
    guard starts_with(status, "HTTP/1.1 ") && status.len >= 12 && is_digit(status[9]) else {
        hangup(s);
        return ws, client_error("response");
    }
    let code, numeric = parse_int(status[9..12]);
    guard numeric else {
        hangup(s);
        return ws, client_error("response");
    }
    ws.status = code;
    let fields = raw[eol..end - 2];
    let upgrade, _ = field_in(fields, "Upgrade");
    let connection, _ = field_in(fields, "Connection");
    let accept, _ = field_in(fields, "Sec-WebSocket-Accept");
    let chosen, named = field_in(fields, "Sec-WebSocket-Protocol");
    let offered, _ = field_in(req.lines, "Sec-WebSocket-Protocol");
    let extensions, extended = field_in(fields, "Sec-WebSocket-Extensions");
    guard code == 101 && has_token(upgrade, "websocket") && has_token(connection, "upgrade")
        && accept == ws_accept(key) && !extended && (!named || has_token(offered, chosen) && chosen.len <= 128)
    else {
        hangup(s);
        return ws, client_error("websocket");
    }
    if named { ws.protocol.append(chosen); }
    ws.held.append(raw[end..]);
    // The connection moves to ws; the session keeps its TLS context, which
    // must outlive ws.
    ws.conn = Session { ms: s.ms, s: s.s, c: s.c, .. };
    s.s = Socket { .. };
    s.c = tls::Conn { .. };
    s.peer.clear();
    return ws, no_error();
}

fn ws_connect(s: Session&, url: const u8[:]) -> WsClient, Error { return ws_connect(s, url) { req => }; }

// Whether lines, a request's fields, set one the handshake writes itself.
fn ws_owns_field(lines: const u8[:]) -> bool {
    var pos = 0;
    while pos < lines.len {
        let name, value, next = field_at(lines, pos);
        if same_name(name, "Upgrade") || same_name(name, "Sec-WebSocket-Key")
            || same_name(name, "Sec-WebSocket-Version") || same_name(name, "Sec-WebSocket-Extensions") {
            return true;
        }
        pos = next;
    }
    return false;
}

// Whether list, comma-separated, holds token, ignoring ASCII case.
fn has_token(list: const u8[:], token: const u8[:]) -> bool {
    var found = false;
    each_split(list, ',') { if same_name(trim(it), token) { found = true; } };
    return found && token.len > 0;
}

// Sends a message, op WS_TEXT or WS_BINARY, in one masked frame, within
// ws.conn.ms. Text must be UTF-8. EPIPE once the connection is closed; a
// failed send closes it.
fn ws_send(ws: WsClient&, op: u8, data: const u8[:]) -> Error {
    guard !ws.closing else { return Error { call: "send", code: EPIPE }; }
    return ws_put(ws, op, data);
}

// One masked frame, whole (§5.2).
fn ws_put(ws: WsClient&, op: u8, data: const u8[:]) -> Error {
    guard !ws.done else { return Error { call: "send", code: EPIPE }; }
    var frame: u8[>..] = [];
    frame.push(0x80 | op);
    let n = data.len;
    if n < 126 {
        frame.push(0x80 | n as! u8);
    } else if n < 65536 {
        frame.push(0x80 | 126);
        frame.push((n >> 8) as! u8);
        frame.push(n as! u8);
    } else {
        frame.push(0x80 | 127);
        for i in 8 { frame.push((n >> (56 - 8 * i)) as! u8); }
    }
    var mask: u8[4] = [0; 4];
    hash::random_bytes(mask);
    frame.append(mask);
    let at = frame.len;
    frame.append(data);
    for i in n { frame[at + i] = frame[at + i] ^ mask[i & 3]; }
    let e = put(ws.conn, frame);
    if e.code != 0 { ws_drop(ws); }
    return e;
}

// Waits for the next message, and puts it in out: returns its opcode,
// WS_TEXT or WS_BINARY; or WS_CLOSE once the server has closed, with its
// reason in out and its code in ws.close_code, after which the connection is
// closed. A ping gets its pong on the way. Each wait is limited by
// ws.conn.ms: an ETIMEDOUT leaves the WebSocket as it was, to be called
// again. A frame the protocol forbids fails the connection with 1002, text
// that isn't UTF-8 with 1007, and a message past ws.limit with 1009, each
// sent in a Close first, and returns call "websocket"; a connection that ends
// without a Close, ECONNRESET.
fn ws_receive(ws: WsClient&, out: u8[>..]&) -> u8, Error {
    out.clear();
    guard !ws.done else { return 0, Error { call: "recv", code: ECONNRESET }; }
    // What ws held is the call's while it runs: the message so far goes to
    // out, and the frames are read from the rest, and from what comes after.
    out.append(ws.held[..ws.joined]);
    var pending: u8[>..] = [];
    pending.append(ws.held[ws.joined..]);
    ws.held.clear();
    ws.joined = 0;
    var at = 0;
    var buf: u8[16384] = [0; 16384];
    loop {
        let op, used = ws_frames(ws, pending[at..], out);
        at += used;
        if op != 0 {
            if !ws.done { ws.held.append(pending[at..]); }
            return op, no_error();
        }
        guard !ws.done else {
            out.clear();
            return 0, client_error("websocket");
        }
        let n, e = take(ws.conn, buf);
        guard e.code == 0 && n > 0 else {
            if e.code == ETIMEDOUT {
                ws.held.append(out);
                ws.held.append(pending[at..]);
                ws.joined = out.len;
                out.clear();
                return 0, e;
            }
            ws_drop(ws);
            out.clear();
            return 0, if e.code != 0 { e } else { Error { call: "recv", code: ECONNRESET } };
        }
        pending.append(buf[..n]);
    }
}

// Reads the whole frames at the start of src, as ws_receive describes, until
// a message or a Close is whole in out: returns its opcode, or 0 for none
// yet, and how many bytes the frames took.
fn ws_frames(ws: WsClient&, src: const u8[:], out: u8[>..]&) -> u8, i64 {
    var at = 0;
    while !ws.done && src.len - at >= 2 {
        let s = src[at..];
        let fin = s[0] & 0x80 != 0;
        let op = s[0] & 0x0F;
        var n = (s[1] & 0x7F) as i64;
        var h = 2;
        if n == 126 {
            guard s.len >= 4 else { break; }
            n = (s[2] as i64) << 8 | s[3];
            h = 4;
        } else if n == 127 {
            guard s.len >= 10 else { break; }
            guard s[2] & 0x80 == 0 else {
                ws_fail(ws, WS_PROTOCOL_ERROR);
                break;
            }
            n = 0;
            for i in 8 { n = n << 8 | s[2 + i]; }
            h = 10;
        }
        // A server's frames are never masked (§5.1), and are checked from the
        // head alone, so a frame too long is refused before it arrives.
        let control = op >= 8;
        let fault = s[0] & 0x70 != 0 || s[1] & 0x80 != 0 ||
                    (if control { op > WS_PONG || !fin || n > 125 }
                     else { op > WS_BINARY || (op == WS_CONTINUATION) == (ws.op == 0) });
        guard !fault else {
            ws_fail(ws, WS_PROTOCOL_ERROR);
            break;
        }
        guard control || n <= ws.limit - out.len else {
            ws_fail(ws, WS_TOO_BIG);
            break;
        }
        guard s.len - h >= n else { break; }
        let payload = s[h..h + n];
        at += h + n;
        if ws.closing && op != WS_CLOSE { continue; }
        if op == WS_PING {
            ws_put(ws, WS_PONG, payload);
        } else if op == WS_CLOSE {
            var state: u32 = 0;
            if payload.len == 1 || payload.len >= 2 && !ws_code_ok((payload[0] as i32) << 8 | payload[1]) {
                ws_fail(ws, WS_PROTOCOL_ERROR);
                break;
            }
            guard payload.len < 2 || ws_utf8(payload[2..], state) && state == 0 else {
                ws_fail(ws, WS_INVALID_DATA);
                break;
            }
            ws.close_code = if payload.len >= 2 { (payload[0] as i32) << 8 | payload[1] } else { 1005 };
            if !ws.closing { ws_put(ws, WS_CLOSE, payload[..min(payload.len, 2)]); }
            out.clear();
            if payload.len > 2 { out.append(payload[2..]); }
            ws_drop(ws);
            return WS_CLOSE, at;
        } else if op != WS_PONG {
            if op != WS_CONTINUATION {
                ws.op = op;
                ws.utf8 = 0;
            }
            guard ws.op != WS_TEXT || ws_utf8(payload, ws.utf8) && (!fin || ws.utf8 == 0) else {
                ws_fail(ws, WS_INVALID_DATA);
                break;
            }
            out.append(payload);
            if fin {
                let done = ws.op;
                ws.op = 0;
                return done, at;
            }
        }
    }
    return 0, at;
}

// Starts the close (§7.1.2): sends a Close with code and reason, at most 123
// bytes of UTF-8, then reads until the server's Close, within ws.conn.ms for
// each wait, and closes the connection.
fn ws_close(ws: WsClient&, code: i32 = WS_NORMAL, reason: const u8[:] = "") -> Error {
    guard !ws.done else { return no_error(); }
    if !ws.closing {
        var body: u8[..125] = [];
        body.push((code >> 8) as! u8);
        body.push(code as! u8);
        body.append(reason[..min(reason.len, 123)]);
        let e = ws_put(ws, WS_CLOSE, body);
        guard e.code == 0 else { return e; }
        ws.closing = true;
    }
    var rest: u8[>..] = [];
    loop {
        let op, e = ws_receive(ws, rest);
        guard e.code == 0 else {
            ws_drop(ws);
            return e;
        }
        if op == WS_CLOSE { return no_error(); }
    }
}

// Fails the connection (§7.1.7): a Close with code, unless one was sent, then
// the connection closes.
fn ws_fail(ws: WsClient&, code: i32) {
    if !ws.closing {
        var body: u8[2] = [(code >> 8) as! u8, code as! u8];
        ws_put(ws, WS_CLOSE, body);
    }
    ws_drop(ws);
}

// Closes the connection at once, without a Close.
fn ws_drop(ws: WsClient&) {
    hangup(ws.conn);
    ws.done = true;
    ws.closing = true;
    ws.op = 0;
    ws.joined = 0;
    ws.held.clear();
}
