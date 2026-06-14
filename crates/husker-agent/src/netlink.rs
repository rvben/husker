//! Minimal `NETLINK_ROUTE` message encoding for static interface setup, used by
//! the guest supervisor to configure networking without `iproute2`/`busybox`
//! (a distroless OCI rootfs ships neither). Only the four operations the
//! supervisor needs are implemented: bring a link up, add an address, and add a
//! default route.
//!
//! The message encoders are pure (they only build byte buffers from stable
//! kernel UAPI constants) so they are unit-tested on any host; the socket I/O
//! that actually applies them is Linux-only (see [`apply`]).

use std::net::Ipv4Addr;

// ── Kernel UAPI constants (stable ABI) ──────────────────────────────────────

/// Modify/create a link (used here to set `IFF_UP`).
pub const RTM_NEWLINK: u16 = 16;
/// Add an address to an interface.
pub const RTM_NEWADDR: u16 = 20;
/// Add a route.
pub const RTM_NEWROUTE: u16 = 24;

const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_ACK: u16 = 0x004;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_REPLACE: u16 = 0x100;

const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;

const IFF_UP: u32 = 0x1;

// rtnetlink attribute types.
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;

const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RTN_UNICAST: u8 = 1;

/// Round `len` up to the 4-byte netlink alignment.
fn align4(len: usize) -> usize {
    (len + 3) & !3
}

/// Append an `rtattr` (header + payload) padded to the 4-byte alignment.
fn push_attr(buf: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let len = 4 + payload.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(payload);
    buf.resize(align4(buf.len()), 0);
}

/// Write the final `nlmsg_len` (total message length) into the header.
fn finalize(mut buf: Vec<u8>) -> Vec<u8> {
    let len = buf.len() as u32;
    buf[0..4].copy_from_slice(&len.to_ne_bytes());
    buf
}

/// Start a netlink message: a 16-byte `nlmsghdr` with `nlmsg_len` left as 0
/// (filled by [`finalize`]). `pid` is 0 (kernel) and `seq` identifies the reply.
fn header(msg_type: u16, flags: u16, seq: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len (placeholder)
    buf.extend_from_slice(&msg_type.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
    buf
}

/// Build an `RTM_NEWLINK` message that sets `IFF_UP` on `ifindex`.
pub fn link_up_msg(seq: u32, ifindex: u32) -> Vec<u8> {
    let mut buf = header(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, seq);
    // struct ifinfomsg
    buf.push(AF_UNSPEC); // ifi_family
    buf.push(0); // __pad
    buf.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
    buf.extend_from_slice(&(ifindex as i32).to_ne_bytes()); // ifi_index
    buf.extend_from_slice(&IFF_UP.to_ne_bytes()); // ifi_flags
    buf.extend_from_slice(&IFF_UP.to_ne_bytes()); // ifi_change
    finalize(buf)
}

/// Build an `RTM_NEWADDR` message assigning `addr/prefix` to `ifindex`.
pub fn add_addr_msg(seq: u32, ifindex: u32, addr: Ipv4Addr, prefix: u8) -> Vec<u8> {
    let mut buf = header(
        RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        seq,
    );
    // struct ifaddrmsg
    buf.push(AF_INET); // ifa_family
    buf.push(prefix); // ifa_prefixlen
    buf.push(0); // ifa_flags
    buf.push(RT_SCOPE_UNIVERSE); // ifa_scope
    buf.extend_from_slice(&ifindex.to_ne_bytes()); // ifa_index
    let octets = addr.octets();
    push_attr(&mut buf, IFA_LOCAL, &octets);
    push_attr(&mut buf, IFA_ADDRESS, &octets);
    finalize(buf)
}

/// Build an `RTM_NEWROUTE` message adding a default route via `gateway` on
/// `ifindex`.
pub fn default_route_msg(seq: u32, ifindex: u32, gateway: Ipv4Addr) -> Vec<u8> {
    let mut buf = header(
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        seq,
    );
    // struct rtmsg
    buf.push(AF_INET); // rtm_family
    buf.push(0); // rtm_dst_len (0 == default route)
    buf.push(0); // rtm_src_len
    buf.push(0); // rtm_tos
    buf.push(RT_TABLE_MAIN); // rtm_table
    buf.push(RTPROT_BOOT); // rtm_protocol
    buf.push(RT_SCOPE_UNIVERSE); // rtm_scope
    buf.push(RTN_UNICAST); // rtm_type
    buf.extend_from_slice(&0u32.to_ne_bytes()); // rtm_flags
    push_attr(&mut buf, RTA_GATEWAY, &gateway.octets());
    push_attr(&mut buf, RTA_OIF, &ifindex.to_ne_bytes());
    finalize(buf)
}

pub use apply::configure_static;

/// Socket I/O that sends the encoded messages to the kernel.
mod apply {
    use std::ffi::CString;
    use std::io;
    use std::net::Ipv4Addr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::{add_addr_msg, default_route_msg, link_up_msg};

    /// Resolve an interface name to its kernel index (`if_nametoindex`).
    fn interface_index(name: &str) -> io::Result<u32> {
        let cname = CString::new(name).map_err(|_| io::Error::other("interface name has NUL"))?;
        // SAFETY: cname is a valid NUL-terminated string held for the call.
        let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if idx == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(idx)
        }
    }

    /// Resolve an interface index, retrying briefly: a virtio_net device can
    /// register a moment after its module loads, so the name may not resolve on
    /// the first try.
    fn interface_index_wait(name: &str) -> io::Result<u32> {
        let mut last = io::Error::other("interface never appeared");
        for _ in 0..40 {
            match interface_index(name) {
                Ok(idx) => return Ok(idx),
                Err(e) => {
                    last = e;
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        }
        Err(last)
    }

    /// Open a `NETLINK_ROUTE` socket as an owned fd (closed on drop).
    fn open_socket() -> io::Result<OwnedFd> {
        // SAFETY: socket() returns -1 on error (checked) or a new fd we own.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a valid, freshly-opened descriptor we exclusively own.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Send one request and read the kernel's ACK, returning an error when the
    /// kernel reports a non-zero `nlmsgerr` (ignoring `EEXIST`, so re-applying a
    /// route/address already present is not fatal).
    fn send_recv(sock: &OwnedFd, msg: &[u8]) -> io::Result<()> {
        let fd = sock.as_raw_fd();
        // SAFETY: msg is a valid slice; we pass its pointer and length.
        let sent = unsafe { libc::send(fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut buf = [0u8; 4096];
        // SAFETY: buf is a valid, sufficiently large buffer for the reply.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        // The kernel always answers an NLM_F_ACK request with an NLMSG_ERROR
        // message: a 16-byte nlmsghdr followed by an i32 error (0 == success).
        if n < 20 {
            return Err(io::Error::other("short netlink ACK"));
        }
        let err = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
        if err == 0 || err == -libc::EEXIST {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(-err))
        }
    }

    /// Bring `iface` up, assign `addr/prefix`, and (when `gateway` is set) add a
    /// default route through it - all via netlink, with no userspace tools.
    pub fn configure_static(
        iface: &str,
        addr: Ipv4Addr,
        prefix: u8,
        gateway: Option<Ipv4Addr>,
    ) -> io::Result<()> {
        let sock = open_socket()?;
        let lo = interface_index("lo")?;
        let ifindex = interface_index_wait(iface)?;

        send_recv(&sock, &link_up_msg(1, lo))?;
        send_recv(&sock, &link_up_msg(2, ifindex))?;
        send_recv(&sock, &add_addr_msg(3, ifindex, addr, prefix))?;
        if let Some(gw) = gateway {
            send_recv(&sock, &default_route_msg(4, ifindex, gw))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u32(buf: &[u8], off: usize) -> u32 {
        u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
    }
    fn read_u16(buf: &[u8], off: usize) -> u16 {
        u16::from_ne_bytes([buf[off], buf[off + 1]])
    }

    #[test]
    fn link_up_msg_has_correct_header_and_flags() {
        let msg = link_up_msg(2, 7);
        // nlmsg_len equals the buffer length, 4-byte aligned.
        assert_eq!(read_u32(&msg, 0) as usize, msg.len());
        assert_eq!(msg.len() % 4, 0);
        assert_eq!(read_u16(&msg, 4), RTM_NEWLINK);
        assert_eq!(read_u16(&msg, 6), NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(read_u32(&msg, 8), 2, "seq");
        // ifinfomsg: ifi_index at offset 16+4 = 20.
        assert_eq!(read_u32(&msg, 20) as i32, 7, "ifi_index");
        // ifi_flags and ifi_change both IFF_UP.
        assert_eq!(read_u32(&msg, 24), IFF_UP);
        assert_eq!(read_u32(&msg, 28), IFF_UP);
        // header(16) + ifinfomsg(16) = 32, no attrs.
        assert_eq!(msg.len(), 32);
    }

    #[test]
    fn add_addr_msg_encodes_address_and_prefix() {
        let addr = Ipv4Addr::new(192, 0, 2, 5);
        let msg = add_addr_msg(3, 9, addr, 30);
        assert_eq!(read_u32(&msg, 0) as usize, msg.len());
        assert_eq!(read_u16(&msg, 4), RTM_NEWADDR);
        assert_eq!(
            read_u16(&msg, 6),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE
        );
        // ifaddrmsg at offset 16: family, prefixlen, flags, scope, index(u32).
        assert_eq!(msg[16], AF_INET);
        assert_eq!(msg[17], 30, "prefix len");
        assert_eq!(read_u32(&msg, 20), 9, "ifa_index");
        // First attr (IFA_LOCAL) at offset 24: len=8, type=IFA_LOCAL, 4 addr bytes.
        assert_eq!(read_u16(&msg, 24), 8);
        assert_eq!(read_u16(&msg, 26), IFA_LOCAL);
        assert_eq!(&msg[28..32], &addr.octets());
        // Second attr (IFA_ADDRESS) at offset 32.
        assert_eq!(read_u16(&msg, 34), IFA_ADDRESS);
        assert_eq!(&msg[36..40], &addr.octets());
        assert_eq!(msg.len(), 40);
    }

    #[test]
    fn default_route_msg_encodes_gateway_and_oif() {
        let gw = Ipv4Addr::new(192, 0, 2, 1);
        let msg = default_route_msg(4, 9, gw);
        assert_eq!(read_u32(&msg, 0) as usize, msg.len());
        assert_eq!(read_u16(&msg, 4), RTM_NEWROUTE);
        // rtmsg at offset 16: family, dst_len=0 (default route).
        assert_eq!(msg[16], AF_INET);
        assert_eq!(msg[17], 0, "dst_len 0 = default route");
        assert_eq!(msg[20], RT_TABLE_MAIN);
        assert_eq!(msg[22], RT_SCOPE_UNIVERSE);
        assert_eq!(msg[23], RTN_UNICAST);
        // rtmsg is 12 bytes (16..28); first attr RTA_GATEWAY at 28.
        assert_eq!(read_u16(&msg, 28), 8);
        assert_eq!(read_u16(&msg, 30), RTA_GATEWAY);
        assert_eq!(&msg[32..36], &gw.octets());
        // RTA_OIF attr next at 36: len=8, type=RTA_OIF, ifindex u32.
        assert_eq!(read_u16(&msg, 38), RTA_OIF);
        assert_eq!(read_u32(&msg, 40), 9, "oif index");
    }

    #[test]
    fn align4_rounds_up_to_four() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
    }
}
