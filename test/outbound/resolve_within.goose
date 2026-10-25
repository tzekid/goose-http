// net_resolve_within (shim/resolve.c), the lookup connect makes within its
// time limit: a name every resolver finds in the hosts file, with a limit,
// without one, and with none left; a name too long to look up; and connect
// to that name with no time left, which fails at the lookup.
import std;
import http from "../../";

fn main() {
    var addrs: u8[128] = [0; 128];
    let n = http::net_resolve_within("LOCALHOST", addrs, 5000);
    print("within 5 s: ", n > 0);
    let m = http::net_resolve_within("LOCALHOST", addrs, -1);
    print("without a limit: ", m > 0);
    print("with none left: ", http::net_resolve_within("LOCALHOST", addrs, 0) == -http::ETIMEDOUT);
    var long: u8[>..] = [];
    for i in 300 { long.push('a'); }
    print("a name too long: ", http::net_resolve_within(long, addrs, 1000) == -http::EINVAL);
    let s, e = http::connect("LOCALHOST", 80, 0);
    print("connect with none left: ", e.call, " ", e.code == http::ETIMEDOUT, ", socket ", s.fd);
}
