extern crate pnetlink;
extern crate pnet;

use pnetlink::socket::NetlinkProtocol;
use pnetlink::socket::NetlinkSocket;
use pnetlink::packet::netlink::NetlinkConnection;
use pnetlink::packet::netlink::NetlinkReader;
use pnetlink::packet::route::addr::IFA_ADDRESS;
use pnetlink::packet::route::addr::RTM_NEWADDR;
use pnetlink::packet::route::addr::Addr;
use pnetlink::packet::route::IfAddrPacket;
use pnetlink::packet::route::RtAttrPacket;
use pnetlink::packet::route::link::Links;

use std::net::{Ipv4Addr,Ipv6Addr};

// Duplicate all this logic because raisins
fn nl_align(len: usize) -> usize {
    const RTA_ALIGNTO: usize = 4;

    ((len)+RTA_ALIGNTO-1) & !(RTA_ALIGNTO-1)
}

pub struct my_RtAttrIterator<'a> {
    buf: &'a [u8],
}

impl<'a> my_RtAttrIterator<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        my_RtAttrIterator {
            buf: buf,
        }
    }
}

impl<'a> Iterator for my_RtAttrIterator<'a> {
    type Item = RtAttrPacket<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(rta) = RtAttrPacket::new(&self.buf[..]) {
            let len = rta.get_rta_len() as usize;
            if len < 4 {
                return None;
            }
            self.buf = &self.buf[nl_align(len as usize)..];
            return Some(rta);
        }
        None
    }
}

use pnet::packet::Packet;

fn main() {
    // FIXME
    const RTMGRP_IPV4_IFADDR: u32 = 0x10;
    const RTMGRP_IPV6_IFADDR: u32 = 0x100;

    let dev_name = std::env::args_os().nth(1).expect("Need a device name!");
    println!("Watching for IP changes on {}...", dev_name.to_string_lossy());

    // This part gets the unique index of the interface
    let iface_idx;
    {
        let mut nl_query_conn = NetlinkConnection::new();
        // FIXME: Non-UTF-8?
        let link = nl_query_conn.get_link_by_name(&dev_name.to_string_lossy())
            .expect("Device name not found!").expect("Device name not found!");
        iface_idx = link.get_index();
    }

    let mut nl_sock = NetlinkSocket::bind(NetlinkProtocol::Route,
        RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR)
        .expect("Opening netlink socket failed!");
    let mut nl_reader = NetlinkReader::new(&mut nl_sock);

    while let Ok(Some(pkt)) = nl_reader.read_netlink() {
        // Only process new addresses (don't bother with deleting)
        if pkt.get_kind() == RTM_NEWADDR {
            if let Some(addrpkt) = IfAddrPacket::new(&pkt.payload()) {
                if addrpkt.get_index() == iface_idx {
                    let iter = my_RtAttrIterator::new(addrpkt.payload());
                    for rta in iter {
                        if rta.get_rta_type() == IFA_ADDRESS {
                            println!("rta {:?}", rta);
                            let addr = Addr::ip_from_family_and_bytes(
                                addrpkt.get_family(), rta.payload());
                            println!("ip {:?}", addr);
                        }
                    }
                }
            }
        }
    }
}
