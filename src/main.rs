extern crate pnetlink;
extern crate pnet;

use pnetlink::socket::NetlinkProtocol;
use pnetlink::socket::NetlinkSocket;
use pnetlink::packet::netlink::NetlinkConnection;
use pnetlink::packet::netlink::NetlinkReader;
use pnetlink::packet::route::addr::RTM_NEWADDR;
use pnetlink::packet::route::IfAddrPacket;
use pnetlink::packet::route::link::Links;

use pnet::packet::Packet;

fn main() {
    // FIXME
    let RTMGRP_IPV4_IFADDR: u32 = 0x10;
    let RTMGRP_IPV6_IFADDR: u32 = 0x100;

    let dev_name = std::env::args_os().nth(1).expect("Need a device name!");
    println!("Watching for IP changes on {}...", dev_name.to_string_lossy());

    // This part gets the unique index of the interface
    let iface_idx;
    {
        let mut nl_query_conn = NetlinkConnection::new();
        // FIXME: Non-UTF-8?
        let link = nl_query_conn.get_link_by_name(&dev_name.to_string_lossy())
            .expect("Device name not found!").expect("Device name not found!");
        println!("link {:?}", link);
        iface_idx = link.get_index();
    }

    let mut nl_sock = NetlinkSocket::bind(NetlinkProtocol::Route,
        RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR)
        .expect("Opening netlink socket failed!");
    let mut nl_reader = NetlinkReader::new(&mut nl_sock);

    while let Ok(Some(pkt)) = nl_reader.read_netlink() {
        //let pkt = pkt.get_packet();

        println!("{:?}", pkt);

        // Only process new addresses (don't bother with deleting)
        if pkt.get_kind() == RTM_NEWADDR {
            if let Some(addrpkt) = IfAddrPacket::new(&pkt.payload()) {
                println!("ifa {:?}", addrpkt);

                if addrpkt.get_index() == iface_idx {
                    println!("ASDFASDF");
                }
            }
        }
    }
}
