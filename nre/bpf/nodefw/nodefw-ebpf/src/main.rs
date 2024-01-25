#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
// TODO see if this is preferred over ptr_at
// use memoffset::offset_of;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use nodefw_common::Rule;

const MAX_BLOCKLIST_SIZE: u32 = 1024;

// the key is an ipv4 or ipv6 octet value expressed as an array.
#[map]
static BLOCKLIST: HashMap<[u8; 16usize], Rule> = HashMap::with_max_entries(MAX_BLOCKLIST_SIZE, 0);

fn block_ip(ctx: &XdpContext, address: [u8; 16usize]) -> bool {
    unsafe {
        // TODO find a way to check map len, if possible
        // if BLOCKLIST.len() == MAX_BLOCKLIST_SIZE {
        //     return true;
        // }
        if let Some(v) = BLOCKLIST.get(&address) {
            info!(ctx, "ttl: {} port: {}", v.ttl, v.port);
        }
        BLOCKLIST.get(&address).is_some()
    }
}

#[xdp]
pub fn nodefw(ctx: XdpContext) -> u32 {
    match try_nodefw(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn eval_ip(ctx: XdpContext) -> Result<u32, ()> {
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let mut source_addr: [u8; 16usize] = [0; 16];
    source_addr[12..].copy_from_slice(unsafe { &(*ipv4hdr).src_addr.to_le_bytes() });
    let src_addr: u32 = u32::from_be_bytes(source_addr[12..].try_into().unwrap());
    let dest_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let port = u16::from_be(unsafe { (*tcphdr).dest });
            port
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*udphdr).source })
        }
        _ => 0,
    };

    if dest_port == 2046 {
        info!(&ctx, "source_addr: {:i} dest port: {}", src_addr, dest_port);

        if block_ip(&ctx, source_addr) {
            info!(&ctx, "drop source_addr: {:i} dest port: {}", src_addr, dest_port);
            // FAIL OPEN WHILE TESTING; should be XDP_DROP
            return Ok(xdp_action::XDP_PASS);
        }
    }
    // FAIL OPEN WHILE TESTING
    Ok(xdp_action::XDP_PASS)
}
fn eval_ipv6(ctx: XdpContext) -> Result<u32, ()> {
    let ipv6hdr: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = unsafe { (*ipv6hdr).src_addr.in6_u.u6_addr8 };
    // we don't print info for v6 yet, need to convert it for the aya logger
    if block_ip(&ctx, source_addr) {
        return Ok(xdp_action::XDP_PASS);
    }
    Ok(xdp_action::XDP_PASS)
}

fn try_nodefw(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    return match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => eval_ip(ctx),
        EtherType::Ipv6 => eval_ipv6(ctx),
        _ => return Ok(xdp_action::XDP_PASS),
    };
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
