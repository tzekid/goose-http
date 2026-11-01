// The benchmark server, serving with http::serve unless LOOP says otherwise:
// io_uring on Linux, IOCP on Windows. It serves no TLS, so it doesn't map
// OpenSSL; server_tls.goose adds the TLS listener, with LOOP=uring on this
// loop.
import http from "../";
import compress from "github.com/tzekid/goose-compress@81aedc4ac044a458a9124337d0c6c731cadb27ef";
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import app;

fn main() { run("uring", no_tls, workers); }
