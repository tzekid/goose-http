// The benchmark server, serving with http::serve_epoll unless LOOP says
// otherwise: epoll on Linux, kqueue on macOS. It serves no TLS, so it doesn't
// map OpenSSL; server_tls.goose adds the TLS listener.
import http from "../";
import compress from "github.com/tzekid/goose-compress@81aedc4ac044a458a9124337d0c6c731cadb27ef";
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import app;

fn main() { run("epoll", no_tls, workers); }
