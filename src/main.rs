extern crate pnetlink;

use pnetlink::socket::NetlinkProtocol;
use pnetlink::socket::NetlinkSocket;

fn main() {
    // FIXME
    let RTMGRP_IPV4_IFADDR: u32 = 0x10;
    let RTMGRP_IPV6_IFADDR: u32 = 0x100;

    let dev_name = std::env::args_os().nth(1).expect("Need a device name!");
    println!("Watching for IP changes on {}...", dev_name.to_string_lossy());

    let mut nl_sock = NetlinkSocket::bind(NetlinkProtocol::Route,
        RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR)
        .expect("Opening netlink socket failed!");

    loop {
        let mut nl_buf: [u8; 4096] = [0; 4096];

        let sz = nl_sock.recv(&mut nl_buf)
            .expect("Reading netlink socket failed!");

        println!("{}", sz);
    }
}
