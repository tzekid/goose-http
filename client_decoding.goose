// A client response's body decoded as its Content-Encoding says, gzip or
// deflate, with goose-compress's decoder. Only a program that imports this
// module needs goose-compress, which its root file declares at the tag this
// file names:
//
//   import http from "github.com/kaitk/goose-http@<tag>";
//   import tls from "github.com/kaitk/goose-tls@v0.0.6";
//   import compress from "github.com/tzekid/goose-compress@0d31e4f6360f9ac6e2a3464bb2457f527d6e27cc";
//   import http.client_decoding;
//
//   let r, err = http::get(session, url) { req => http::accept_compressed(req); };
//   if err.code == 0 { err = http::decode_body(r); }   // r.body: the decoded bytes
//
// The response's fields stay as received: Content-Encoding and Content-Length
// describe the body as sent.
namespace http;

import std;
import compress from "github.com/tzekid/goose-compress@0d31e4f6360f9ac6e2a3464bb2457f527d6e27cc";
import message;
import client;

// The most decoded bytes a body may make, by default: compressed bodies grow
// a thousandfold, so the limit on the body as sent doesn't bound them.
let DECODED_MAX = 64 << 20;

// Asks for a body compressed with gzip or deflate, the codings this module
// decodes, and no other.
fn accept_compressed(req: ClientRequest&) { header(req, "Accept-Encoding", "gzip, deflate"); }

// The coding fields name, as decode's format, IDENTITY for none, or -1 for
// one this module doesn't decode, such as br, zstd, or a chain of codings.
let IDENTITY = -2;

fn coding_of(fields: const u8[:]) -> i64 {
    let value, has = field_in(fields, "Content-Encoding");
    guard has else { return IDENTITY; }
    let v = trim(value);
    if same_name(v, "gzip") || same_name(v, "x-gzip") { return compress::GZIP; }
    // HTTP's deflate is zlib's stream; a raw one isn't guessed at.
    if same_name(v, "deflate") { return compress::ZLIB; }
    if same_name(v, "identity") || v.len == 0 { return IDENTITY; }
    return -1;
}

// Decodes r.body, in place, as r's Content-Encoding says, into at most limit
// bytes: no error for a body that isn't compressed, which stays as it is;
// call "response" for a coding this module doesn't decode, a stream that's
// corrupt or cut short, or one past limit.
fn decode_body(r: ClientResponse&, limit: i64 = DECODED_MAX) -> Error {
    let format = coding_of(r.fields);
    guard format != IDENTITY else { return no_error(); }
    guard format >= 0 else { return client_error("response"); }
    var plain: u8[>..] = [];
    guard compress::decompress(r.body, plain, format, limit) else { return client_error("response"); }
    r.body.clear();
    r.body.append(plain);
    return no_error();
}

// A body read in pieces and decoded as it comes: the decoder, the limit on
// what it makes, and the encoded bytes read but not decoded yet.
struct BodyDecoder {
    limit: i64 = DECODED_MAX,
    format: i64 = IDENTITY,
    started: bool = false,
    done: bool = false,
    made: i64 = 0,
    d: compress::Decoder = compress::Decoder { .. },
    buf: u8[16384] = [0; 16384],
    at: i64 = 0,
    encoded: u8[>..],
}

// Reads the next of x's body, decoded as its Content-Encoding says, and
// appends at most most bytes of it to out: how many, or 0 once the body and
// its stream have ended. A body that isn't compressed goes through as read
// does. A coding this module doesn't decode, a stream that's corrupt, cut
// short, or followed by more of the body, and one past b.limit fail with
// call "response" and close the connection.
fn read_decoded(s: Session&, x: ClientExchange&, b: BodyDecoder&, out: u8[>..]&, most: i64) -> i64, Error {
    if !x.headed {
        let e = response(s, x);
        guard e.code == 0 else { return 0, e; }
    }
    if !b.started {
        b.format = coding_of(x.fields);
        b.started = true;
        guard b.format != -1 else { return 0, failed(s, x, client_error("response")); }
        if b.format >= 0 { compress::reset(b.d, b.format); }
    }
    guard most > 0 else { return 0, no_error(); }
    if b.format == IDENTITY {
        let n, e = read(s, x, b.buf[..min(most, b.buf.len)]);
        if n > 0 { out.append(b.buf[..n]); }
        return n, e;
    }
    let begin = out.len;
    loop {
        if b.at < b.encoded.len {
            // One byte past the limit shows a body that goes past it. After
            // a stream's end, the decoder judges what follows: another gzip
            // member, or an error.
            let room = min(most - (out.len - begin), b.limit - b.made + 1);
            let before = out.len;
            let used, status = compress::decode(b.d, b.encoded[b.at..], out, room);
            b.at += used;
            b.made += out.len - before;
            guard status != compress::DECODE_ERROR && b.made <= b.limit else {
                return 0, failed(s, x, client_error("response"));
            }
            b.done = status == compress::DECODE_DONE;
            if b.done && b.at < b.encoded.len { return 0, failed(s, x, client_error("response")); }
            if out.len > begin { return out.len - begin, no_error(); }
            if status == compress::DECODE_FULL { continue; }
        }
        b.encoded.clear();
        b.at = 0;
        let n, e = read(s, x, b.buf);
        guard e.code == 0 else { return 0, e; }
        if n == 0 {
            guard b.done else { return 0, failed(s, x, client_error("response")); }
            return 0, no_error();
        }
        b.encoded.append(b.buf[..n]);
    }
}
