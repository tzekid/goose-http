// An HTTP/1.1 client for a thread that runs no loop, such as a lane's or a
// command-line program's: each call blocks until its response has come, over
// the blocking socket (socket.goose), and over goose-tls's client TLS for an
// https URL. Only a program that imports this module needs goose-tls, which
// its root file declares at the reference this file names:
//
//   import http from "github.com/kaitk/goose-http@<tag>";
//   import tls from "github.com/kaitk/goose-tls@v0.0.6";
//   import http.client;
//
//   var session = http::session();
//   let response, err = http::post(session, "https://api.example.com/v1/login") { req =>
//       http::bearer(req, api_key);
//       http::header(req, "X-Device-Id", device_id);
//       http::json(req, credentials);
//   };
//   http::free(session);
//
// The calls are compositions of parts a program can call on its own:
// parse_url, write_request, and read_response work on bytes, and exchange
// carries one request over a session's connection.
namespace http;

import std;
import base64;
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import sys;
import message;
import socket;

// A client's settings and its open connection, which the next request to the
// same scheme, host, and port reuses.
struct Session {
    // The limit in milliseconds on each wait: a host name's lookup and the
    // connect together, a send, a read (-1: none).
    ms: i64 = 30000,
    // The limit in milliseconds on a request as a whole, from its lookup to
    // its response's last byte, however steadily bytes arrive (-1: none).
    total_ms: i64 = -1,
    // How long a request that asked for 100 Continue (expect_continue)
    // waits for it before it sends its body anyway (-1: until an answer).
    expect_ms: i64 = 1000,
    // The most redirects a request follows (0: none, a redirect is the
    // response), as follow describes.
    redirects: i64 = 0,
    // The classes of address the session doesn't connect to, as connect's
    // DENY_ bits (0: none), for a program that requests URLs from outside:
    // DENY_NON_PUBLIC keeps them to public addresses. Every redirect's
    // address is checked too. With via, via's address is the one checked.
    deny: i64 = 0,
    // The most body a response may have, in bytes as sent (-1: none, for a
    // body read in pieces).
    max_body: i64 = 16 << 20,
    // An address to connect to in place of the URL's host and port, such as
    // "unix:/run/app.sock"; TLS still checks the URL's host.
    via: u8[..256],
    // An HTTP proxy every request goes through, http://host:port, with
    // user:password@ before the host for one that asks for them (Basic);
    // empty for none. An http:// request goes to it whole, and an https://
    // one, or a WebSocket, through a tunnel it opens with CONNECT, over
    // which TLS checks the URL's host. With via, via's address is the
    // proxy's. deny can't be checked through a proxy, so a session with both
    // fails its requests with call "proxy".
    proxy: u8[..256],
    // How many connections to other origins the session keeps open beside
    // its own, up to IDLE_MAX, so that a program calling several origins in
    // turn reconnects to none (0: none, as one origin needs), and how long
    // one is kept unused.
    max_idle: i64 = 0,
    idle_ms: i64 = 30000,
    ctx: tls::Context,
    s: Socket = Socket { fd: -1 },
    c: tls::Conn,
    // The connection's scheme, host, and port, as https://host:port, and the
    // deny and proxy it was opened with, after them.
    peer: u8[..600],
    // Whether the connection is in an exchange that begin started and end
    // hasn't ended, so that it isn't kept for another request.
    busy: bool = false,
    // The connections kept for other origins, the oldest first.
    idle: IdleConnection[..IDLE_MAX],
}

let IDLE_MAX = 8;

// A connection a session keeps for its origin's next request, as Session
// holds its own, and since when.
struct IdleConnection { s: Socket = Socket { fd: -1 }, c: tls::Conn, peer: u8[..600], since: i64 = 0 }

// A session whose TLS trusts OpenSSL's store of certificate authorities. An
// https request fails with call "tls" when OpenSSL couldn't make its context.
fn session(ms: i64 = 30000) -> Session {
    let ctx, ok = tls::client(["http/1.1"]);
    return Session { ms: ms, ctx: if ok { ctx } else { tls::Context { .. } }, .. };
}

// A session whose TLS trusts only the certificates in ca, PEM text, and
// whether its context was made.
fn session_trusting(ca: const u8[:], ms: i64 = 30000) -> Session, bool {
    let ctx, ok = tls::client_trusting(ca, ["http/1.1"]);
    return Session { ms: ms, ctx: if ok { ctx } else { tls::Context { .. } }, .. }, ok;
}

// Closes the session's connection and frees its TLS context.
fn free(s: Session&) {
    hangup(s);
    while s.idle.len > 0 { close_idle(s, s.idle.len - 1); }
    if tls::ok(s.ctx) { tls::free(s.ctx); }
    s.ctx = tls::Context { .. };
}

// What a request's block adds to it: header field lines, and a body with its
// media type. lines and payload are the request call's own buffers.
struct ClientRequest {
    lines: u8[>..]&,
    payload: u8[>..]&,
    media: const u8[:] = "",
    // What the block did that fails the request: "header" for a field it
    // refused, "body" for a second body.
    refused: const u8[:] = "",
    // A body the program writes after begin, as stream says: its length, or
    // -1 for chunks; -2 for none.
    length: i64 = -2,
    // Whether the request waits for 100 Continue before its body.
    expect: bool = false,
}

// The response: its status, its header field lines, each ending in CRLF,
// and its body. Status 0 for a request that failed.
struct ClientResponse {
    status: i64 = 0,
    fields: u8[..8192],
    body: u8[>..],
}

// The value of r's header field name, compared ignoring ASCII case, and
// whether r has it; the first, if it repeats.
fn header(r: const ClientResponse&, name: const u8[:]) -> const u8[:], bool {
    return field_in(r.fields, name);
}

// Adds the field name: value. A name that isn't a token, a value with a CR,
// an LF, or another control byte, and the fields the session writes itself
// fail the request with call "header".
fn header(req: ClientRequest&, name: const u8[:], value: const u8[:]) {
    let own = same_name(name, "Host") || same_name(name, "Content-Length")
        || same_name(name, "Transfer-Encoding") || same_name(name, "Connection") || same_name(name, "Expect");
    guard !own && is_field(name, trim_ows(value)) else {
        if req.refused.len == 0 { req.refused = "header"; }
        return;
    }
    format(req.lines, name, ": ", trim_ows(value), "\r\n");
}

// Adds Authorization: Bearer token.
fn bearer(req: ClientRequest&, token: const u8[:]) { header(req, "Authorization", str("Bearer ", token)); }

// Makes v the body as JSON, written by v's format overload, with
// Content-Type: application/json. A request has one body: a second fails it
// with call "body".
fn json(req: ClientRequest&, v) {
    guard first_body(req) else { return; }
    format(req.payload, v);
    req.media = "application/json";
}

// Makes bytes the body, with Content-Type: media.
fn body(req: ClientRequest&, media: const u8[:], bytes: const u8[:]) {
    guard first_body(req) else { return; }
    req.payload.append(bytes);
    req.media = media;
}

// Makes the body one the program writes after begin, with write and then
// end_body, so it needn't be held whole: length bytes, said in
// Content-Length, or for length -1, chunks. Only begin takes such a
// request; request and its forms fail it with call "body".
fn stream(req: ClientRequest&, media: const u8[:], length: i64) {
    guard first_body(req) else { return; }
    guard length >= -1 else {
        if req.refused.len == 0 { req.refused = "body"; }
        return;
    }
    req.media = if media.len > 0 { media } else { "application/octet-stream" };
    req.length = length;
}

// Sends Expect: 100-continue, and holds the body until the server answers
// 100 Continue, or for Session.expect_ms, so that a server that refuses the
// request, as with 401 or 413, does so before the body is sent.
fn expect_continue(req: ClientRequest&) { req.expect = true; }

fn first_body(req: ClientRequest&) -> bool {
    guard req.media.len > 0 else { return true; }
    if req.refused.len == 0 { req.refused = "body"; }
    return false;
}

// The request method makes to url, which is http:// or https://, after F has
// added to it, and its response; an Error whose call says which step failed
// and whose code is the socket's, or EINVAL for a URL, a field, a body, TLS,
// or a response that couldn't be used, as call "url", "header", "body",
// "tls", and "response" say. After "tls", tls::error_text() says why.
fn request<F>(s: Session&, method: const u8[:], url: const u8[:]) -> ClientResponse, Error {
    var lines: u8[>..] = [];
    var payload: u8[>..] = [];
    var req = ClientRequest { lines: lines, payload: payload };
    F(&req);
    return follow(s, method, url, req);
}

// Sends the request with exchange, and follows the redirects in its
// responses, up to Session.redirects of them: a 301, 302, 303, 307, or 308
// with a Location. A 303, and a 301 or 302 to a POST, go on as a GET without
// the body; the others repeat the method and the body. A redirect to another
// scheme, host, or port drops the fields Authorization, Cookie, and
// Proxy-Authorization from the request, and the rest of it goes on. A
// redirect past the limit, from https to http, or to a Location that isn't
// an http:// or https:// URL fails with call "redirect". Session.total_ms
// counts every request of the chain.
fn follow(s: Session&, method: const u8[:], url: const u8[:], req: const ClientRequest&) -> ClientResponse, Error {
    let until = deadline(s.total_ms);
    var r, e = exchange_by(s, method, url, req, until);
    var m = method;
    var at: u8[>..] = [];
    at.append(url);
    var credentials = true;
    var body = true;
    for hop in s.redirects + 1 {
        guard e.code == 0 && is_redirect(r.status) else { return r, e; }
        let location, has = header(r, "Location");
        guard has && s.redirects > 0 else { return r, e; }
        guard hop < s.redirects else { break; }
        var next: u8[>..] = [];
        let from, _ = parse_url(at);
        guard resolve_url(from, location, next) else { break; }
        let to, ok = parse_url(next);
        guard ok && (to.secure || !from.secure) else { break; }
        credentials = credentials && same_origin(from, to);
        if r.status == 303 && m != "HEAD" || (r.status == 301 || r.status == 302) && m == "POST" {
            m = "GET";
            body = false;
        }
        at = copy(next);
        r, e = exchange_hop(s, m, at, req, until, credentials, body);
    }
    return ClientResponse { .. }, client_error("redirect");
}

fn is_redirect(status: i64) -> bool { status == 301 || status == 302 || status == 303 || status == 307 || status == 308 }

// Whether a and b have the same scheme, host, and port: the same origin.
fn same_origin(a: Url, b: Url) -> bool { a.secure == b.secure && a.port == b.port && same_name(a.host, b.host) }

// exchange_by for a request a redirect repeats: req's fields, without those
// that carry credentials unless credentials, and its body, unless body is
// false.
fn exchange_hop(s: Session&, method: const u8[:], url: const u8[:], req: const ClientRequest&, until: i64,
                credentials: bool, body: bool) -> ClientResponse, Error {
    var lines: u8[>..] = [];
    var pos = 0;
    while pos < req.lines.len {
        let name, value, next = field_at(req.lines, pos);
        if credentials || !same_name(name, "Authorization") && !same_name(name, "Cookie")
            && !same_name(name, "Proxy-Authorization") {
            lines.append(req.lines[pos..next]);
        }
        pos = next;
    }
    var payload: u8[>..] = [];
    if body { payload.append(req.payload); }
    let hop = ClientRequest { lines: lines, payload: payload, media: if body { req.media } else { "" } };
    return exchange_by(s, method, url, hop, until);
}

// Writes to out the URL that location, a redirect's Location, names from
// base (RFC 3986 §5.2), and returns whether it names one: a URL with its
// scheme, one without it ("//host/path"), an absolute path, a query, or a
// path relative to base's. parse_url then checks what out holds.
fn resolve_url(base: Url, location: const u8[:], out: u8[>..]&) -> bool {
    guard location.len > 0 else { return false; }
    let colon = find(location, ":");
    let delim = find_any(location, REFERENCE_DELIM);
    if colon > 0 && (delim < 0 || colon < delim) {
        // A scheme is in any case (RFC 3986 §3.1); parse_url takes it in
        // lower case.
        for c in location[..colon] { out.push(if c >= 'A' && c <= 'Z' { c + 32 } else { c }); }
        out.append(location[colon..]);
        return true;
    }
    let scheme = if base.secure { "https:" } else { "http:" };
    if starts_with(location, "//") {
        format(out, scheme, location);
        return true;
    }
    format(out, scheme, "//", base.authority);
    let query = find(base.target, "?");
    let path = if query >= 0 { base.target[..query] } else { base.target };
    let ref_end = find_any(location, QUERY_OR_FRAGMENT);
    let ref_path = if ref_end >= 0 { location[..ref_end] } else { location };
    let rest = if ref_end >= 0 { location[ref_end..] } else { "" };
    if ref_path.len == 0 {
        out.append(path);
        if rest[0] == '?' { out.append(rest); } else if query >= 0 { out.append(base.target[query..]); }
        return true;
    }
    if ref_path[0] == '/' {
        append_without_dots(out, ref_path);
    } else {
        var merged: u8[>..] = [];
        let slash = rfind(path, "/");
        if slash >= 0 { merged.append(path[..slash + 1]); } else { merged.push('/'); }
        merged.append(ref_path);
        append_without_dots(out, merged);
    }
    out.append(rest);
    return true;
}

let REFERENCE_DELIM = byte_set("/?#");
let QUERY_OR_FRAGMENT = byte_set("?#");

// Appends path, which starts with '/', to out without its "." and ".."
// segments (RFC 3986 §5.2.4).
fn append_without_dots(out: u8[>..]&, path: const u8[:]) {
    let root = out.len;
    var at = 0;
    while at < path.len {
        var end = at + 1;
        while end < path.len && path[end] != '/' { end++; }
        let segment = path[at + 1..end];
        let last = end == path.len;
        if segment == "." || segment == ".." {
            if segment == ".." {
                var cut = out.len;
                while cut > root {
                    cut--;
                    if out[cut] == '/' { break; }
                }
                out.resize(cut);
            }
            if last { out.push('/'); }
        } else {
            out.push('/');
            out.append(segment);
        }
        at = end;
    }
}

fn get<F>(s: Session&, url: const u8[:]) -> ClientResponse, Error { return request(s, "GET", url) { req => F(req); }; }
fn post<F>(s: Session&, url: const u8[:]) -> ClientResponse, Error { return request(s, "POST", url) { req => F(req); }; }
fn put<F>(s: Session&, url: const u8[:]) -> ClientResponse, Error { return request(s, "PUT", url) { req => F(req); }; }
fn patch<F>(s: Session&, url: const u8[:]) -> ClientResponse, Error { return request(s, "PATCH", url) { req => F(req); }; }
fn delete<F>(s: Session&, url: const u8[:]) -> ClientResponse, Error { return request(s, "DELETE", url) { req => F(req); }; }

fn get(s: Session&, url: const u8[:]) -> ClientResponse, Error { return request(s, "GET", url) { req => }; }
fn delete(s: Session&, url: const u8[:]) -> ClientResponse, Error { return request(s, "DELETE", url) { req => }; }

// A URL's parts, as slices of it. authority is host[:port], as the Host
// field takes it; host has no brackets around an IPv6 address; target is the
// path and query, "/" when the URL has neither.
struct Url { secure: bool = false, authority: const u8[:], host: const u8[:], port: i64 = 80, target: const u8[:] }

let AUTHORITY_END = byte_set("/?");
let NOT_IN_HOST = byte_set(" @\r\n\t");
let NOT_IN_TARGET = byte_set(" \r\n\t");

// The parts of url, http:// or https:// with a host, an optional port, and an
// optional path and query, without its fragment; false for anything else.
fn parse_url(url: const u8[:]) -> Url, bool {
    var u = Url { .. };
    var rest = url;
    if starts_with(url, "https://") {
        u.secure = true;
        u.port = 443;
        rest = url[8..];
    } else if starts_with(url, "http://") {
        rest = url[7..];
    } else {
        return u, false;
    }
    let hash = find(rest, "#");
    if hash >= 0 { rest = rest[..hash]; }
    var end = find_any(rest, AUTHORITY_END);
    if end < 0 { end = rest.len; }
    u.authority = rest[..end];
    u.target = if end == rest.len { "/" } else { rest[end..] };
    let host, port, ok = parse_authority(u.authority, u.port);
    guard ok && find_any(u.target, NOT_IN_TARGET) < 0 else { return u, false; }
    u.host = host;
    u.port = port;
    return u, true;
}

// The host and port of authority, host[:port], as a URL holds them, port
// unless it names one, and whether it's one: host bracketed for IPv6, with
// none of NOT_IN_HOST, and a port from 1 to 65535.
fn parse_authority(authority: const u8[:], port: i64) -> const u8[:], i64, bool {
    var host = authority;
    var port_at = -1;
    if authority.len > 0 && authority[0] == '[' {
        let close = find(authority, "]");
        guard close > 1 else { return "", 0, false; }
        host = authority[1..close];
        if close + 1 < authority.len {
            guard authority[close + 1] == ':' else { return "", 0, false; }
            port_at = close + 2;
        }
    } else {
        let colon = find(authority, ":");
        if colon >= 0 {
            host = authority[..colon];
            port_at = colon + 1;
        }
    }
    var p = port;
    if port_at >= 0 {
        let digits = authority[port_at..];
        let n, ok = parse_int(digits);
        guard ok && digits.len > 0 && is_digit(digits[0]) && n > 0 && n < 65536 else { return "", 0, false; }
        p = n;
    }
    guard host.len > 0 && find_any(host, NOT_IN_HOST) < 0 else { return "", 0, false; }
    return host, p, true;
}

// The parts of Session.proxy, as parse_proxy reads it: its host and port,
// and user:password, still percent-encoded, if it names them.
struct Proxy { host: const u8[:], port: i64 = 80, userinfo: const u8[:] }

// The parts of text, http://[user:password@]host[:port][/], and whether it's
// one; port 80 unless it names one.
fn parse_proxy(text: const u8[:]) -> Proxy, bool {
    var p = Proxy { .. };
    guard starts_with(text, "http://") else { return p, false; }
    var rest = text[7..];
    if rest.len > 0 && rest[rest.len - 1] == '/' { rest = rest[..rest.len - 1]; }
    let at = rfind(rest, "@");
    if at >= 0 {
        p.userinfo = rest[..at];
        rest = rest[at + 1..];
    }
    guard find_any(rest, AUTHORITY_END) < 0 else { return p, false; }
    let host, port, ok = parse_authority(rest, 80);
    p.host = host;
    p.port = port;
    return p, ok;
}

// Appends Proxy-Authorization's field line for p's credentials, if it has
// any: Basic, with them percent-decoded.
fn proxy_authorization(out: u8[>..]&, p: Proxy) {
    guard p.userinfo.len > 0 else { return; }
    var plain: u8[>..] = [];
    guard decode(p.userinfo, plain) else { return; }
    var token: u8[>..] = [];
    base64::encode(token, plain);
    format(out, "Proxy-Authorization: Basic ", token, "\r\n");
}

// Appends the request to out: its request line, Host, User-Agent, Accept,
// req's fields, its body's Content-Type and Content-Length, or
// Transfer-Encoding: chunked for a body stream declared in chunks, and the
// body, unless it waits for 100 Continue (expect_continue) or the program
// writes it. A POST, PUT, or PATCH says Content-Length: 0 for no body. Sent
// to an HTTP proxy, p, one with a host, the request line has the whole URL,
// and p's credentials go in Proxy-Authorization.
fn write_request(out: u8[>..]&, method: const u8[:], u: Url, req: const ClientRequest&, p: Proxy = Proxy { .. }) {
    format(out, method, " ");
    if p.host.len > 0 { format(out, "http://", u.authority); }
    format(out, u.target, " HTTP/1.1\r\nHost: ", u.authority, "\r\nUser-Agent: goose-http\r\nAccept: */*\r\n");
    proxy_authorization(out, p);
    out.append(req.lines);
    if req.media.len > 0 { format(out, "Content-Type: ", req.media, "\r\n"); }
    if req.length == -1 {
        out.append("Transfer-Encoding: chunked\r\n");
    } else if req.length >= 0 {
        format(out, "Content-Length: ", req.length, "\r\n");
    } else if req.payload.len > 0 || method == "POST" || method == "PUT" || method == "PATCH" {
        format(out, "Content-Length: ", req.payload.len, "\r\n");
    }
    if req.expect { out.append("Expect: 100-continue\r\n"); }
    out.append("\r\n");
    if !req.expect { out.append(req.payload); }
}

fn client_error(call: const u8[:]) -> Error { Error { call: call, code: EINVAL } }

// Sends the request, and reads its response, on the session's connection to
// url's peer: the open one, or a new one.
fn exchange(s: Session&, method: const u8[:], url: const u8[:], req: const ClientRequest&) -> ClientResponse, Error {
    return exchange_by(s, method, url, req, deadline(s.total_ms));
}

// exchange, ending by until, the clock's time (-1: no limit but each wait's):
// begin, response, read to the body's end, and end.
fn exchange_by(s: Session&, method: const u8[:], url: const u8[:], req: const ClientRequest&, until: i64) -> ClientResponse, Error {
    var r = ClientResponse { .. };
    guard req.length == -2 else { return r, client_error("body"); }
    var x, e = begin_by(s, method, url, req, until);
    guard e.code == 0 else { return r, e; }
    e = response(s, x);
    guard e.code == 0 else { return r, e; }
    var buf: u8[16384] = [0; 16384];
    loop {
        let n, got = read(s, x, buf);
        guard got.code == 0 else { return ClientResponse { .. }, got; }
        if n == 0 { break; }
        r.body.append(buf[..n]);
    }
    r.status = x.status;
    r.fields.append(x.fields);
    end(s, x);
    return r, no_error();
}

// A request whose response is read in pieces, on the session's connection:
// begin sends the request, response reads the response's head, read its body
// as it comes, and end lets the connection go.
struct ClientExchange {
    // The response's status and header field lines, each ending in CRLF,
    // once response has read them; then a chunked body's trailer field
    // lines, once read has come to its end.
    status: i64 = 0,
    fields: u8[..8192],
    trailers: u8[..8192],
    // The clock's time by which the request must end (-1: none), from
    // Session.total_ms at begin.
    until: i64 = -1,
    // What of the body is still to come, as the server's read_body reads a
    // request's.
    body: BodyReader = BodyReader.None,
    chunked: bool = false,
    // A body that ends when the connection does, which can't be reused; and
    // a request whose body the server answered before it was sent, whose
    // connection can't carry another either.
    to_close: bool = false,
    last: bool = false,
    // A body the program writes, as stream declared it: its length, -1 for
    // chunks, -2 for none; what's written of it; whether more may come; and
    // whether the server answered before it, so it isn't sent.
    upload: i64 = -2,
    uploaded: i64 = 0,
    sending: bool = false,
    rejected: bool = false,
    // The body's bytes as sent so far, which Session.max_body limits.
    taken: i64 = 0,
    head_only: bool = false,
    headed: bool = false,
    // The response has been read whole; or a failure closed the connection.
    done: bool = false,
    failed: bool = false,
    // Bytes read past what was used: framing not yet whole, and a run of
    // body data, held[run..run_end], that a smaller buf didn't take.
    run: i64 = 0,
    run_end: i64 = 0,
    held: u8[>..],
}

// Sends the request method makes to url, after F has added to it, as
// request does, and returns once it's sent. A failure is an Error as a
// request's, and the connection is closed then. begin doesn't follow
// redirects: resolve_url gives the URL a Location names.
fn begin<F>(s: Session&, method: const u8[:], url: const u8[:]) -> ClientExchange, Error {
    var lines: u8[>..] = [];
    var payload: u8[>..] = [];
    var req = ClientRequest { lines: lines, payload: payload };
    F(&req);
    return begin_by(s, method, url, req, deadline(s.total_ms));
}

fn begin(s: Session&, method: const u8[:], url: const u8[:]) -> ClientExchange, Error {
    return begin(s, method, url) { req => };
}

// begin for a request built already, which must end by until.
fn begin_by(s: Session&, method: const u8[:], url: const u8[:], req: const ClientRequest&, until: i64) -> ClientExchange, Error {
    var x = ClientExchange { until: until, head_only: method == "HEAD", .. };
    let u, ok = parse_url(url);
    guard ok else { return x, client_error("url"); }
    guard req.refused.len == 0 else { return x, client_error(if req.refused == "body" { "body" } else { "header" }); }
    var wire: u8[>..] = [];
    if s.proxy.len > 0 && !u.secure {
        let p, valid = parse_proxy(s.proxy);
        guard valid else { return x, client_error("proxy"); }
        write_request(wire, method, u, req, p);
    } else {
        write_request(wire, method, u, req);
    }
    var e = open(s, u, until);
    guard e.code == 0 else { return x, e; }
    e = put(s, wire, until);
    guard e.code == 0 else { return x, failed(s, x, e); }
    s.busy = true;
    x.upload = req.length;
    x.sending = req.length >= -1;
    if req.expect {
        e = await_continue(s, x);
        guard e.code == 0 else { return x, e; }
        if !x.rejected && req.payload.len > 0 {
            e = put(s, req.payload, until);
            guard e.code == 0 else { return x, failed(s, x, e); }
        }
    }
    return x, no_error();
}

// Waits, after a head that asked for 100 Continue, for the server's answer,
// up to Session.expect_ms: no error to go on with the body, after a 100 or
// once the wait is over; or with x.rejected, the server's final answer held
// for response, and the body not to be sent.
fn await_continue(s: Session&, x: ClientExchange&) -> Error {
    let wait = if s.expect_ms < 0 { -1 } else { deadline(s.expect_ms) };
    let phase = if wait < 0 { x.until } else if x.until < 0 { wait } else { min(wait, x.until) };
    var buf: u8[4096] = [0; 4096];
    loop {
        let h, verdict = response_head(x.held, false);
        if verdict == READ_COMPLETE && h.status >= 200 {
            x.rejected = true;
            x.sending = false;
            x.last = true;
            return no_error();
        }
        if verdict == READ_COMPLETE {
            drop_front(x.held, h.end);
            if h.status == 100 { return no_error(); }
            continue;
        }
        guard verdict == INCOMPLETE else { return failed(s, x, client_error("response")); }
        guard !expired(x.until) else { return failed(s, x, Error { call: "recv", code: ETIMEDOUT }); }
        guard !expired(phase) else { return no_error(); }
        let n, e = take(s, buf, phase);
        if e.code == ETIMEDOUT && !expired(x.until) { return no_error(); }
        guard e.code == 0 else { return failed(s, x, e); }
        guard n > 0 else { return failed(s, x, client_error("response")); }
        x.held.append(buf[..n]);
    }
}

// Writes the next bytes of a body that stream declared, within
// Session.total_ms: the bytes as they are for a Content-Length, or as one
// chunk. More than Content-Length said fails with call "body"; EPIPE, from
// "body", once the server has answered before the body, which x.status then
// is, and response returns. A failure closes the connection.
fn write(s: Session&, x: ClientExchange&, data: const u8[:]) -> Error {
    guard !x.failed else { return client_error("response"); }
    guard !x.rejected else { return Error { call: "body", code: EPIPE }; }
    guard x.sending else { return client_error("body"); }
    guard data.len > 0 else { return no_error(); }
    guard !expired(x.until) else { return failed(s, x, Error { call: "send", code: ETIMEDOUT }); }
    if x.upload >= 0 {
        guard x.uploaded + data.len <= x.upload else { return failed(s, x, client_error("body")); }
        x.uploaded += data.len;
        let e = put(s, data, x.until);
        return if e.code == 0 { e } else { failed(s, x, e) };
    }
    var size: u8[>..] = [];
    hex_size(size, data.len);
    size.append("\r\n");
    var e = put(s, size, x.until);
    if e.code == 0 { e = put(s, data, x.until); }
    if e.code == 0 { e = put(s, "\r\n", x.until); }
    x.uploaded += data.len;
    return if e.code == 0 { e } else { failed(s, x, e) };
}

// Ends a body that stream declared: sends the last chunk, or checks that
// every byte Content-Length said was written, and fails with call "body",
// closing the connection, where one wasn't. Nothing to do once the server
// has answered before the body.
fn end_body(s: Session&, x: ClientExchange&) -> Error {
    guard !x.failed else { return client_error("response"); }
    guard x.sending else { return no_error(); }
    x.sending = false;
    if x.upload >= 0 {
        return if x.uploaded == x.upload { no_error() } else { failed(s, x, client_error("body")) };
    }
    let e = put(s, "0\r\n\r\n", x.until);
    return if e.code == 0 { e } else { failed(s, x, e) };
}

// Reads the response's head into x.status and x.fields, skipping a 1xx
// before it, up to 16 of them. A failure closes the connection.
fn response(s: Session&, x: ClientExchange&) -> Error {
    guard !x.failed else { return client_error("response"); }
    guard !x.headed else { return no_error(); }
    guard !x.sending else { return client_error("body"); }
    var buf: u8[16384] = [0; 16384];
    var interim = 0;
    loop {
        let h, verdict = response_head(x.held, false);
        if verdict == READ_COMPLETE && h.status < 200 {
            interim++;
            guard interim <= 16 else { return failed(s, x, client_error("response")); }
            drop_front(x.held, h.end);
            continue;
        }
        if verdict == READ_COMPLETE {
            x.status = h.status;
            x.fields.append(x.held[h.eol..h.end - 2]);
            drop_front(x.held, h.end);
            x.headed = true;
            x.chunked = h.chunked;
            guard s.max_body < 0 || h.length <= s.max_body else { return failed(s, x, client_error("response")); }
            if x.head_only || h.status == 204 || h.status == 304 || h.length == 0 && !h.chunked {
                x.done = true;
            } else if h.chunked {
                x.body = BodyReader.ChunkSize;
            } else if h.length > 0 {
                x.body = BodyReader.Length { left: h.length };
            } else {
                x.body = BodyReader.Raw;
                x.to_close = true;
            }
            return no_error();
        }
        guard verdict == INCOMPLETE else { return failed(s, x, client_error("response")); }
        guard !expired(x.until) else { return failed(s, x, Error { call: "recv", code: ETIMEDOUT }); }
        let n, e = take(s, buf, x.until);
        guard e.code == 0 else { return failed(s, x, e); }
        guard n > 0 else { return failed(s, x, client_error("response")); }
        x.held.append(buf[..n]);
    }
}

// Reads the next bytes of the response's body into buf, reading its head
// first if response hasn't: how many, or 0 once the body has ended, when
// x.trailers holds a chunked body's trailer fields. Bytes the server sends
// are read straight into buf where the body's framing allows. A body past
// Session.max_body, as sent, one cut short, and a failure close the
// connection, and so does running past Session.total_ms, however steadily
// the bytes come.
fn read(s: Session&, x: ClientExchange&, buf: u8[:]) -> i64, Error {
    if !x.headed {
        let e = response(s, x);
        guard e.code == 0 else { return 0, e; }
    }
    guard !x.failed else { return 0, client_error("response"); }
    guard buf.len > 0 else { return 0, no_error(); }
    var more: u8[16384] = [0; 16384];
    loop {
        if x.run < x.run_end {
            let k = min(x.run_end - x.run, buf.len);
            copy_into(buf[..k], x.held[x.run..x.run + k]);
            x.run += k;
            if x.run == x.run_end {
                drop_front(x.held, x.run_end);
                x.run = 0;
                x.run_end = 0;
            }
            return k, no_error();
        }
        guard !x.done else { return 0, no_error(); }
        if x.held.len > 0 {
            let d0, d1, verdict = read_body(x.held, x.body);
            guard verdict != 400 else { return 0, failed(s, x, client_error("response")); }
            if verdict == 200 {
                let ended = match x.body { None => true, _ => false };
                if ended && x.chunked {
                    // The trailer section, its blank line included.
                    guard d1 - 2 - d0 <= 8192 else { return 0, failed(s, x, client_error("response")); }
                    x.trailers.append(x.held[d0..d1 - 2]);
                }
                x.done = ended;
                if ended && x.chunked || d0 == d1 {
                    drop_front(x.held, d1);
                } else {
                    guard took(s, x, d1 - d0) else { return 0, client_error("response"); }
                    x.run = d0;
                    x.run_end = d1;
                }
                continue;
            }
        } else {
            // With nothing held, data whose length the framing knows goes
            // straight into buf.
            let want = match x.body {
                Length l => min(l.left, buf.len),
                ChunkData d => min(d.left, buf.len),
                Raw => buf.len,
                _ => 0,
            };
            if want > 0 {
                guard !expired(x.until) else { return 0, failed(s, x, Error { call: "recv", code: ETIMEDOUT }); }
                let n, e = take(s, buf[..want], x.until);
                guard e.code == 0 else { return 0, failed(s, x, e); }
                if n == 0 {
                    guard x.to_close else { return 0, failed(s, x, client_error("response")); }
                    x.done = true;
                    return 0, no_error();
                }
                read_body(buf[..n], x.body);
                if match x.body { None => true, _ => false } { x.done = true; }
                guard took(s, x, n) else { return 0, client_error("response"); }
                return n, no_error();
            }
        }
        guard !expired(x.until) else { return 0, failed(s, x, Error { call: "recv", code: ETIMEDOUT }); }
        let n, e = take(s, more, x.until);
        guard e.code == 0 else { return 0, failed(s, x, e); }
        if n == 0 {
            guard x.to_close && x.held.len == 0 else { return 0, failed(s, x, client_error("response")); }
            x.done = true;
            continue;
        }
        x.held.append(more[..n]);
    }
}

// Counts n more body bytes against Session.max_body, and fails x past it.
fn took(s: Session&, x: ClientExchange&, n: i64) -> bool {
    x.taken += n;
    guard s.max_body < 0 || x.taken <= s.max_body else {
        failed(s, x, client_error("response"));
        return false;
    }
    return true;
}

// Lets the connection go: it stays for the session's next request only once
// the response has been read whole, the server hasn't asked to close it, and
// its body didn't end with it; otherwise it's closed, so a response left
// unread is never read as the next one's.
fn end(s: Session&, x: ClientExchange&) {
    let connection, has = field_in(x.fields, "Connection");
    let keep = x.done && !x.failed && !x.to_close && !x.last && x.held.len == 0 && !(has && has_close(connection));
    if !keep { hangup(s); }
    s.busy = false;
    x.failed = !keep || x.failed;
}

// Whether a Connection field's value lists close.
fn has_close(value: const u8[:]) -> bool {
    var found = false;
    each_split(value, ',') { if same_name(trim(it), "close") { found = true; } };
    return found;
}

// Closes the connection after a failure of x's, and returns the failure.
fn failed(s: Session&, x: ClientExchange&, e: Error) -> Error {
    hangup(s);
    x.failed = true;
    return e;
}

// Removes the first n bytes of b.
fn drop_front(b: u8[>..]&, n: i64) {
    let left = b.len - n;
    for i in left { b[i] = b[n + i]; }
    b.resize(left);
}

// The limit on one wait of a request that must end by until (-1: none): the
// session's limit on each wait, cut to the time left.
fn wait_ms(s: const Session&, until: i64) -> i64 {
    guard until >= 0 else { return s.ms; }
    let left = max(until - net_clock_ms(), 0);
    return if s.ms < 0 { left } else { min(s.ms, left) };
}

// Makes the session's connection one to u's peer: the open one, while the
// server hasn't closed it, or a new one, with its TLS handshake done. until,
// here and below, is the clock's time by which the request must end (-1:
// none), as deadline gives it.
fn open(s: Session&, u: Url, until: i64 = -1, tunnel: bool = false) -> Error {
    var peer: u8[..600] = [];
    guard u.authority.len < 300 else { return client_error("url"); }
    let proxied = s.proxy.len > 0;
    let through = proxied && (u.secure || tunnel);
    format(peer, if u.secure { "https://" } else { "http://" }, u.host, ":", u.port, " ", s.deny, " ", s.proxy,
           if through { " tunnel" } else { "" });
    if s.s.fd >= 0 && s.peer == peer {
        // A connection the server has closed, or that holds bytes nothing
        // asked for, such as TLS's close_notify, isn't reused.
        var probe: u8[1] = [0];
        if recv(s.s, probe, 0) == -ETIMEDOUT { return no_error(); }
        hangup(s);
    }
    park(s);
    if take_idle(s, peer) { return no_error(); }
    var p = Proxy { .. };
    if proxied {
        guard s.deny == 0 else { return client_error("proxy"); }
        let parsed, valid = parse_proxy(s.proxy);
        guard valid else { return client_error("proxy"); }
        p = parsed;
    }
    let to = if s.via.len > 0 { s.via[..] } else if proxied { p.host } else { u.host };
    let sock, e = connect(to, if proxied { p.port } else { u.port }, wait_ms(s, until), s.deny);
    guard e.code == 0 else { return e; }
    s.s = sock;
    if through {
        let t = open_tunnel(s, u, p, until);
        guard t.code == 0 else {
            hangup(s);
            return t;
        }
    }
    if u.secure {
        guard tls::ok(s.ctx) else {
            hangup(s);
            return client_error("tls");
        }
        s.c = tls::connect(s.ctx, u.host);
        let h = handshake(s, until);
        guard h.code == 0 else {
            hangup(s);
            return h;
        }
    }
    s.peer = peer;
    return no_error();
}

// Opens a tunnel to u's host and port through the proxy p that the session's
// socket is connected to (RFC 9110 §9.3.6), within until: CONNECT, with p's
// credentials, and a 2xx answer, after which the socket carries the origin's
// bytes. A 407 fails with call "proxy" and EACCES, another refusal with
// ECONNREFUSED, and an answer that isn't one with EINVAL.
fn open_tunnel(s: Session&, u: Url, p: Proxy, until: i64) -> Error {
    var target: u8[>..] = [];
    if find(u.host, ":") >= 0 { format(target, "[", u.host, "]:", u.port); } else { format(target, u.host, ":", u.port); }
    var wire: u8[>..] = [];
    format(wire, "CONNECT ", target, " HTTP/1.1\r\nHost: ", target, "\r\nUser-Agent: goose-http\r\n");
    proxy_authorization(wire, p);
    wire.append("\r\n");
    let e = put(s, wire, until);
    guard e.code == 0 else { return e; }
    var raw: u8[>..] = [];
    var buf: u8[4096] = [0; 4096];
    loop {
        let h, verdict = response_head(raw, false);
        if verdict == READ_COMPLETE && h.status < 200 {
            drop_front(raw, h.end);
            continue;
        }
        if verdict == READ_COMPLETE {
            guard h.status < 300 else {
                return Error { call: "proxy", code: if h.status == 407 { EACCES } else { ECONNREFUSED } };
            }
            // The client speaks first in TLS and WebSocket alike, so nothing
            // may follow the answer yet.
            guard raw.len == h.end else { return client_error("proxy"); }
            return no_error();
        }
        guard verdict == INCOMPLETE else { return client_error("proxy"); }
        guard !expired(until) else { return Error { call: "recv", code: ETIMEDOUT }; }
        let n, got = take(s, buf, until);
        guard got.code == 0 else { return got; }
        guard n > 0 else { return client_error("proxy"); }
        raw.append(buf[..n]);
    }
}

fn handshake(s: Session&, until: i64 = -1) -> Error {
    guard tls::ok(s.c) else { return client_error("tls"); }
    var wire: u8[16384] = [0; 16384];
    loop {
        let r = tls::handshake(s.c);
        let e = flush(s, until);
        guard e.code == 0 else { return e; }
        if r == 0 { return no_error(); }
        guard r == tls::WANT_INPUT else { return client_error("tls"); }
        guard !expired(until) else { return Error { call: "recv", code: ETIMEDOUT }; }
        let n = recv(s.s, wire, wait_ms(s, until));
        guard n > 0 else { return Error { call: "recv", code: if n == 0 { ECONNRESET } else { -n } }; }
        guard tls::feed(s.c, wire[..n]) == n else { return client_error("tls"); }
    }
}

// Sends what TLS has to send.
fn flush(s: Session&, until: i64 = -1) -> Error {
    var buf: u8[16384] = [0; 16384];
    loop {
        let n = tls::drain(s.c, buf);
        guard n > 0 else { return no_error(); }
        let e = send_all(s.s, buf[..n], wait_ms(s, until));
        guard e.code == 0 else { return e; }
    }
}

// Sends bytes on the session's connection.
fn put(s: Session&, bytes: const u8[:], until: i64 = -1) -> Error {
    guard tls::ok(s.c) else { return send_all(s.s, bytes, wait_ms(s, until)); }
    guard tls::write(s.c, bytes) == bytes.len else { return client_error("tls"); }
    return flush(s, until);
}

// Bytes from the session's connection into buf: how many, or 0 once the
// server has closed it. Under TLS, only close_notify is a close: a socket
// that ends without it could cut a body that ends with the connection.
fn take(s: Session&, buf: u8[:], until: i64 = -1) -> i64, Error {
    guard tls::ok(s.c) else {
        let n = recv(s.s, buf, wait_ms(s, until));
        return if n >= 0 { n } else { 0 }, if n >= 0 { no_error() } else { Error { call: "recv", code: -n } };
    }
    var wire: u8[16384] = [0; 16384];
    loop {
        let n = tls::read(s.c, buf);
        if n > 0 { return n, no_error(); }
        if n == tls::CLOSED { return 0, no_error(); }
        guard n == tls::WANT_INPUT else { return 0, client_error("tls"); }
        guard !expired(until) else { return 0, Error { call: "recv", code: ETIMEDOUT }; }
        let m = recv(s.s, wire, wait_ms(s, until));
        guard m > 0 else { return 0, Error { call: "recv", code: if m == 0 { ECONNRESET } else { -m } }; }
        guard tls::feed(s.c, wire[..m]) == m else { return 0, client_error("tls"); }
    }
}

// Closes the session's connection, if one is open.
fn hangup(s: Session&) {
    if tls::ok(s.c) {
        tls::free(s.c);
        s.c = tls::Conn { .. };
    }
    hangup(s.s);
    s.peer.clear();
    s.busy = false;
}

// Keeps the session's connection among its idle ones, for its origin's next
// request, where max_idle allows and no exchange is using it, the oldest
// making room; closes it otherwise.
fn park(s: Session&) {
    let most = min(s.max_idle, IDLE_MAX);
    guard s.s.fd >= 0 && !s.busy && most > 0 && s.peer.len > 0 else {
        hangup(s);
        return;
    }
    while s.idle.len >= most { close_idle(s, 0); }
    s.idle.push(IdleConnection { s: s.s, c: s.c, peer: s.peer, since: net_clock_ms() });
    s.s = Socket { .. };
    s.c = tls::Conn { .. };
    s.peer.clear();
}

// Makes the idle connection to peer the session's own, if one is fit: kept
// no longer than idle_ms, and not closed by its server since, nor holding
// bytes nothing asked for. Closes those that aren't fit, and those past
// idle_ms.
fn take_idle(s: Session&, peer: const u8[:]) -> bool {
    var i = 0;
    while i < s.idle.len {
        let stale = net_clock_ms() - s.idle[i].since > s.idle_ms;
        guard stale || s.idle[i].peer == peer else {
            i++;
            continue;
        }
        var probe: u8[1] = [0];
        if !stale && recv(s.idle[i].s, probe, 0) == -ETIMEDOUT {
            s.s = s.idle[i].s;
            s.c = s.idle[i].c;
            s.peer.clear();
            s.peer.append(peer);
            for j in s.idle.len - i - 1 { s.idle[i + j] = s.idle[i + j + 1]; }
            s.idle.resize(s.idle.len - 1);
            return true;
        }
        close_idle(s, i);
    }
    return false;
}

// Closes the session's idle connection i.
fn close_idle(s: Session&, i: i64) {
    if tls::ok(s.idle[i].c) { tls::free(s.idle[i].c); }
    hangup(s.idle[i].s);
    for j in s.idle.len - i - 1 { s.idle[i + j] = s.idle[i + j + 1]; }
    s.idle.resize(s.idle.len - 1);
}

// What read_response finds in the bytes so far, beside INCOMPLETE.
let READ_COMPLETE = 1;
let READ_AT_CLOSE = 2;
let READ_MALFORMED = -1;

// The most a response's status line and fields may take.
let MAX_RESPONSE_HEAD = 8192;

// A response's head, as response_head reads it: its status, the ends of its
// status line and of its fields, after the blank line, and its body's
// framing: a Content-Length, or -1, and whether it's chunked.
struct ResponseHead { status: i64 = 0, eol: i64 = 0, end: i64 = 0, length: i64 = -1, chunked: bool = false }

// Reads the head that rest starts with: READ_COMPLETE, INCOMPLETE until it
// has all come, or READ_MALFORMED, for a status line or fields that don't
// parse, a head past MAX_RESPONSE_HEAD, two Content-Lengths that differ, or a
// Transfer-Encoding but chunked. closed says no more bytes will come.
fn response_head(rest: const u8[:], closed: bool) -> ResponseHead, i64 {
    var h = ResponseHead { .. };
    let short = if closed || rest.len > MAX_RESPONSE_HEAD { READ_MALFORMED } else { INCOMPLETE };
    let eol = line_end(rest, 0);
    guard eol != 0 else { return h, short; }
    guard eol > 0 else { return h, READ_MALFORMED; }
    let status = rest[..eol - 2];
    guard starts_with(status, "HTTP/1.") && status.len >= 12 && is_digit(status[7]) && status[8] == ' '
    else { return h, READ_MALFORMED; }
    let code, ok = parse_int(status[9..12]);
    guard ok && is_digit(status[9]) && code >= 100 && code < 600 && (status.len == 12 || status[12] == ' ')
    else { return h, READ_MALFORMED; }
    let end = trailer_end(rest, eol);
    guard end != 0 else { return h, short; }
    guard end > 0 && end <= MAX_RESPONSE_HEAD else { return h, READ_MALFORMED; }
    let fields = rest[eol..end - 2];
    var pos = 0;
    while pos < fields.len {
        let name, value, next = field_at(fields, pos);
        pos = next;
        if same_name(name, "Content-Length") {
            let n, valid = parse_int(value);
            guard valid && value.len > 0 && is_digit(value[0]) && (h.length < 0 || h.length == n)
            else { return h, READ_MALFORMED; }
            h.length = n;
        } else if same_name(name, "Transfer-Encoding") {
            guard same_name(value, "chunked") else { return h, READ_MALFORMED; }
            h.chunked = true;
        }
    }
    h.status = code;
    h.eol = eol;
    h.end = end;
    return h, READ_COMPLETE;
}

// Reads an HTTP/1.1 response from raw into r: READ_COMPLETE, INCOMPLETE when
// more bytes are needed, or READ_MALFORMED, also for a body past max_body as
// sent. closed says the connection has ended, so a body with neither a
// length nor chunks ends with raw: READ_AT_CLOSE. The body is copied into r
// once it has all come. A response to a HEAD, a 204, and a 304 have no body,
// whatever their fields say, and a 1xx before the final response is skipped.
fn read_response(raw: const u8[:], closed: bool, head: bool, max_body: i64, r: ClientResponse&) -> i64 {
    var at = 0;
    loop {
        r.status = 0;
        r.fields.clear();
        let rest = raw[at..];
        let h, verdict = response_head(rest, closed);
        guard verdict == READ_COMPLETE else { return verdict; }
        let code = h.status;
        let end = h.end;
        let length = h.length;
        let chunked = h.chunked;
        r.status = code;
        r.fields.append(rest[h.eol..end - 2]);

        let body = rest[end..];
        if code < 200 {
            at += end;
            continue;
        }
        if head || code == 204 || code == 304 { return READ_COMPLETE; }
        if chunked {
            let n, verdict = chunked_len(body, max_body);
            if verdict == INCOMPLETE { return if closed { READ_MALFORMED } else { INCOMPLETE }; }
            guard verdict == 200 else { return READ_MALFORMED; }
            r.body.append(body[..n]);
            let len, trailers = dechunk(r.body);
            r.body.resize(len);
            return READ_COMPLETE;
        }
        if length >= 0 {
            guard length <= max_body else { return READ_MALFORMED; }
            guard body.len >= length else { return if closed { READ_MALFORMED } else { INCOMPLETE }; }
            r.body.append(body[..length]);
            return READ_COMPLETE;
        }
        guard body.len <= max_body else { return READ_MALFORMED; }
        guard closed else { return INCOMPLETE; }
        r.body.append(body);
        return READ_AT_CLOSE;
    }
}
