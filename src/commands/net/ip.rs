use crate::commands::CommandResult;
use crate::persona::Persona;
use crate::shell::Shell;

const FALLBACK_LINK_LOCAL: &str = "fe80::1";
const MAC_OCTETS: usize = 6;
const UNIVERSAL_LOCAL_BIT: u8 = 0x02;

pub fn ip(shell: &Shell, args: &[String]) -> CommandResult {
    let object = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str);
    let p = &shell.persona;
    match object {
        Some("a" | "addr" | "address") | None => CommandResult::ok(ip_addr(p)),
        Some("l" | "link") => CommandResult::ok(ip_link(p)),
        Some("r" | "route") => CommandResult::ok(ip_route(p)),
        Some("n" | "neigh") => CommandResult::ok(ip_neigh(p)),
        Some(other) => CommandResult::err(
            format!("Object \"{other}\" is unknown, try \"ip help\".\n"),
            1,
        ),
    }
}

fn link_local(mac: &str) -> String {
    let o: Vec<u8> = mac
        .split(':')
        .filter_map(|b| u8::from_str_radix(b, 16).ok())
        .collect();
    if o.len() != MAC_OCTETS {
        return FALLBACK_LINK_LOCAL.to_string();
    }

    let first = o[0] ^ UNIVERSAL_LOCAL_BIT;
    format!(
        "fe80::{:x}{:02x}:{:02x}ff:fe{:02x}:{:02x}{:02x}",
        first, o[1], o[2], o[3], o[4], o[5]
    )
}

fn ip_addr(p: &Persona) -> String {
    format!(
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n\
        \x20   link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n\
        \x20   inet 127.0.0.1/8 scope host lo\n\
        \x20      valid_lft forever preferred_lft forever\n\
        \x20   inet6 ::1/128 scope host\n\
        \x20      valid_lft forever preferred_lft forever\n\
        2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n\
        \x20   link/ether {mac} brd ff:ff:ff:ff:ff:ff\n\
        \x20   inet {ip}/24 brd {bcast} scope global dynamic eth0\n\
        \x20      valid_lft 84235sec preferred_lft 84235sec\n\
        \x20   inet6 {ll}/64 scope link\n\
        \x20      valid_lft forever preferred_lft forever\n",
        mac = p.mac,
        ip = p.ipv4,
        bcast = p.broadcast(),
        ll = link_local(&p.mac),
    )
}

fn ip_link(p: &Persona) -> String {
    format!(
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n\
        \x20   link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n\
        2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\n\
        \x20   link/ether {mac} brd ff:ff:ff:ff:ff:ff\n",
        mac = p.mac,
    )
}

fn ip_route(p: &Persona) -> String {
    format!(
        "default via {gw} dev eth0 proto dhcp src {ip} metric 100\n\
         {subnet}.0/24 dev eth0 proto kernel scope link src {ip} metric 100\n",
        gw = p.gateway(),
        ip = p.ipv4,
        subnet = p.subnet,
    )
}

fn ip_neigh(p: &Persona) -> String {
    format!("{} dev eth0 lladdr {} REACHABLE\n", p.gateway(), p.mac)
}
