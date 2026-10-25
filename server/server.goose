// The benchmark server, serving with http::serve unless LOOP says otherwise:
// io_uring on Linux, IOCP on Windows. It serves no TLS, so it doesn't map
// OpenSSL; server_tls.goose adds the TLS listener, with LOOP=uring on this
// loop.
import http from "../";
import compress from "github.com/tzekid/goose-compress@0d31e4f6360f9ac6e2a3464bb2457f527d6e27cc";
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import app;

fn main() { run("uring", no_tls, workers); }
