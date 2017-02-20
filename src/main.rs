extern crate pnetlink;
extern crate pnet;

use std::fs::File;
use std::path::Path;
use std::io::BufReader;
// ???
use std::io::BufRead;
use std::io::Write;

use std::process::Command;
use std::process::Stdio;
use std::process::ChildStdin;

use pnetlink::socket::NetlinkProtocol;
use pnetlink::socket::NetlinkSocket;
use pnetlink::packet::netlink::NetlinkConnection;
use pnetlink::packet::netlink::NetlinkReader;
use pnetlink::packet::route::addr::IFA_ADDRESS;
use pnetlink::packet::route::addr::RTM_NEWADDR;
use pnetlink::packet::route::addr::Addr;
use pnetlink::packet::route::addr::IpAddr;
use pnetlink::packet::route::IfAddrPacket;
use pnetlink::packet::route::RtAttrPacket;
use pnetlink::packet::route::link::Links;

use std::net::{Ipv4Addr,Ipv6Addr};

// ???
use pnet::packet::Packet;

// FIXME
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV6_IFADDR: u32 = 0x100;

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

fn update_ipv4(stdin: &mut ChildStdin, domain: &str, ipaddr: &Ipv4Addr) {
    let delete_str = format!("update delete {} A\n", domain);
    stdin.write_all(delete_str.as_bytes());
    let update_str = format!("update add {} 60 A {}\n", domain, ipaddr);
    stdin.write_all(update_str.as_bytes());
    stdin.write_all("send\n".as_bytes());
}

fn update_ipv6(stdin: &mut ChildStdin, domain: &str, ipaddr: &Ipv6Addr) {
    let delete_str = format!("update delete {} AAAA\n", domain);
    stdin.write_all(delete_str.as_bytes());
    let update_str = format!("update add {} 60 AAAA {}\n", domain, ipaddr);
    stdin.write_all(update_str.as_bytes());
    stdin.write_all("send\n".as_bytes());
}

fn main() {
    // Load config file
    let conf_file_name = std::env::args_os().nth(2)
        .expect("Need a config file!");
    let conf_file_name = Path::new(&conf_file_name);
    let conf_file = File::open(&conf_file_name)
        .expect("Failed to open config file!");
    let mut conf_file_reader = BufReader::new(conf_file);

    let mut dns_key_file = String::new();
    let mut main_dns_name = String::new();
    let other_dns_names: Vec<((u16, u16, u16, u16), String)>;

    conf_file_reader.read_line(&mut dns_key_file);
    conf_file_reader.read_line(&mut main_dns_name);
    let dns_key_file = dns_key_file.trim();
    let main_dns_name = main_dns_name.trim();
    other_dns_names = conf_file_reader.lines().map(|l| {
        // WTF?
        let l = l.unwrap();
        let l = l.trim();

        let mut l_split = l.split_whitespace();
        let domain_part = l_split.next().unwrap();
        let addr_part = l_split.next().unwrap();
        let addr_split: Vec<&str> = addr_part.split(':').collect();
        let addr_split: Vec<u16> = addr_split.iter()
            .map(|&x| u16::from_str_radix(x, 16).unwrap()).collect();

        ((addr_split[0], addr_split[1], addr_split[2], addr_split[3]),
            domain_part.to_string())
    }).collect();

    println!("Main domain name: {}", main_dns_name);
    for (_, other_name) in other_dns_names {
        println!("Extra domain name: {}", other_name);
    }

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

    // Spawn nsupdate
    let nsupdate = Command::new("nsupdate")
        .arg("-k").arg(dns_key_file)
        .stdin(Stdio::piped()).spawn().expect("Failed to launch nsupdate!");
    let mut nsupdate_in = nsupdate.stdin.unwrap();

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
                            let addr = Addr::ip_from_family_and_bytes(
                                addrpkt.get_family(), rta.payload());
                            println!("ip {:?}", addr);
                            match addr {
                                IpAddr::V4(v4addr) => {
                                    update_ipv4(&mut nsupdate_in,
                                        main_dns_name, &v4addr);
                                }
                                IpAddr::V6(v6addr) => {
                                    update_ipv6(&mut nsupdate_in,
                                        main_dns_name, &v6addr);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
