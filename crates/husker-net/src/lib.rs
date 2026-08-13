//! Linux networking helpers for bridge/TAP lifecycle, NAT, and port forwarding.

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Mutex;

use tracing::{debug, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("no addresses available in pool")]
    PoolExhausted,
    #[error("address not owned by this allocator: {0}")]
    NotAllocated(Ipv4Addr),
    #[error("command failed: {cmd}: {message}")]
    CommandFailed { cmd: String, message: String },
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid interface name '{name}': {reason}")]
    InvalidInterfaceName { name: String, reason: String },
    #[error(
        "bridge subnet {subnet} overlaps an existing host route {conflict} (dev {dev}). \
         Set network.bridge_subnet (or HUSKER_BRIDGE_SUBNET) to a non-overlapping range, \
         e.g. 172.30.0.0/16 or 10.200.0.0/16."
    )]
    SubnetConflict {
        subnet: String,
        conflict: String,
        dev: String,
    },
}

/// Boxed network operation used by the object-safe host-network boundary.
pub type NetworkFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, NetError>> + Send + 'a>>;

/// Per-VM Linux host-network operations used by the lifecycle orchestrator.
///
/// Keeping command execution behind this boundary lets core exercise failure
/// and rollback behavior without root privileges or changes to the host.
pub trait HostNetwork: Send + Sync {
    fn create_tap<'a>(&'a self, name: &'a str) -> NetworkFuture<'a, ()>;

    fn delete_tap<'a>(&'a self, name: &'a str) -> NetworkFuture<'a, ()>;

    fn attach_to_bridge<'a>(
        &'a self,
        tap_name: &'a str,
        bridge_name: &'a str,
    ) -> NetworkFuture<'a, ()>;

    fn add_port_forward<'a>(
        &'a self,
        host_port: u16,
        guest_ip: Ipv4Addr,
        guest_port: u16,
        tap_name: &'a str,
        bridge_name: &'a str,
    ) -> NetworkFuture<'a, ()>;

    fn remove_port_forward<'a>(
        &'a self,
        host_port: u16,
        tap_name: &'a str,
        bridge_name: &'a str,
    ) -> NetworkFuture<'a, ()>;

    fn remove_all_port_forwards<'a>(
        &'a self,
        tap_name: &'a str,
        bridge_name: &'a str,
    ) -> NetworkFuture<'a, ()>;

    fn read_all_port_forward_counters<'a>(
        &'a self,
        bridge_name: &'a str,
    ) -> NetworkFuture<'a, HashMap<String, (u64, u64)>>;
}

/// Daemon-wide Linux bridge and NAT lifecycle operations.
///
/// This stays separate from [`HostNetwork`] so core depends only on per-VM
/// capabilities while the platform adapter owns bridge/NAT setup and teardown.
pub trait DaemonNetwork: Send + Sync {
    fn create_bridge<'a>(
        &'a self,
        name: &'a str,
        gateway_ip: Ipv4Addr,
        prefix_len: u8,
    ) -> NetworkFuture<'a, ()>;

    fn delete_bridge<'a>(&'a self, name: &'a str) -> NetworkFuture<'a, ()>;

    fn init_nat<'a>(
        &'a self,
        bridge_name: &'a str,
        bridge_subnet: &'a str,
        host_interface: &'a str,
        isolation: Option<&'a IsolationPolicy>,
    ) -> NetworkFuture<'a, ()>;

    fn cleanup_nat<'a>(&'a self, bridge_name: &'a str) -> NetworkFuture<'a, ()>;
}

/// Production host-network implementation backed by `ip` and `nft` commands.
#[derive(Debug, Default)]
pub struct SystemHostNetwork;

impl HostNetwork for SystemHostNetwork {
    fn create_tap<'a>(&'a self, name: &'a str) -> NetworkFuture<'a, ()> {
        Box::pin(create_tap(name))
    }

    fn delete_tap<'a>(&'a self, name: &'a str) -> NetworkFuture<'a, ()> {
        Box::pin(delete_tap(name))
    }

    fn attach_to_bridge<'a>(
        &'a self,
        tap_name: &'a str,
        bridge_name: &'a str,
    ) -> NetworkFuture<'a, ()> {
        Box::pin(attach_to_bridge(tap_name, bridge_name))
    }

    fn add_port_forward<'a>(
        &'a self,
        host_port: u16,
        guest_ip: Ipv4Addr,
        guest_port: u16,
        tap_name: &'a str,
        bridge_name: &'a str,
    ) -> NetworkFuture<'a, ()> {
        Box::pin(add_port_forward(
            host_port,
            guest_ip,
            guest_port,
            tap_name,
            bridge_name,
        ))
    }

    fn remove_port_forward<'a>(
        &'a self,
        host_port: u16,
        tap_name: &'a str,
        bridge_name: &'a str,
    ) -> NetworkFuture<'a, ()> {
        Box::pin(remove_port_forward(host_port, tap_name, bridge_name))
    }

    fn remove_all_port_forwards<'a>(
        &'a self,
        tap_name: &'a str,
        bridge_name: &'a str,
    ) -> NetworkFuture<'a, ()> {
        Box::pin(remove_all_port_forwards(tap_name, bridge_name))
    }

    fn read_all_port_forward_counters<'a>(
        &'a self,
        bridge_name: &'a str,
    ) -> NetworkFuture<'a, HashMap<String, (u64, u64)>> {
        Box::pin(read_all_port_forward_counters(bridge_name))
    }
}

impl DaemonNetwork for SystemHostNetwork {
    fn create_bridge<'a>(
        &'a self,
        name: &'a str,
        gateway_ip: Ipv4Addr,
        prefix_len: u8,
    ) -> NetworkFuture<'a, ()> {
        Box::pin(create_bridge(name, gateway_ip, prefix_len))
    }

    fn delete_bridge<'a>(&'a self, name: &'a str) -> NetworkFuture<'a, ()> {
        Box::pin(delete_bridge(name))
    }

    fn init_nat<'a>(
        &'a self,
        bridge_name: &'a str,
        bridge_subnet: &'a str,
        host_interface: &'a str,
        isolation: Option<&'a IsolationPolicy>,
    ) -> NetworkFuture<'a, ()> {
        Box::pin(init_nat(
            bridge_name,
            bridge_subnet,
            host_interface,
            isolation,
        ))
    }

    fn cleanup_nat<'a>(&'a self, bridge_name: &'a str) -> NetworkFuture<'a, ()> {
        Box::pin(cleanup_nat(bridge_name))
    }
}

/// Linux interface name length limit (IFNAMSIZ - 1 for null terminator).
const IFNAMSIZ_MAX: usize = 15;

/// Derive the per-bridge nftables table name.
///
/// Each daemon owns a table named after its bridge so two husker daemons on one
/// host never clobber each other's NAT. The encoding is injective: a constant
/// `husker_` prefix followed by the bridge name, ASCII alphanumerics kept
/// verbatim and every other byte escaped as `_<hex>`. Within the encoded suffix
/// the only `_` are escape introducers, so distinct bridges always map to
/// distinct tables (e.g. `husker-a` and `husker_a` do not collide).
pub fn nft_table_for_bridge(bridge: &str) -> String {
    let mut out = String::from("husker_");
    for &b in bridge.as_bytes() {
        if b.is_ascii_alphanumeric() {
            out.push(b as char);
        } else {
            out.push('_');
            out.push_str(&format!("{b:02x}"));
        }
    }
    out
}

// ── IP Allocation ──────────────────────────────────────────────────────

struct AllocatorState {
    next_index: u32,
    /// Released indices below `next_index`, reused before fresh ones.
    freed: BTreeSet<u32>,
    /// Indices at or above `next_index` reserved out of band (seeded from
    /// persisted VMs on startup). `allocate` skips these as it advances, so it
    /// never hands out an in-use IP without materializing the intervening gap.
    reserved: BTreeSet<u32>,
}

/// Allocates individual guest IPs from a shared subnet.
///
/// The subnet gateway gets `.1`; guests get `.2` through the last usable
/// address (excluding the broadcast address).
///
/// Released IPs are reused before allocating fresh ones,
/// with the lowest freed index chosen first.
pub struct IpAllocator {
    base: u32,
    prefix_len: u8,
    max_index: u32,
    state: Mutex<AllocatorState>,
}

impl IpAllocator {
    /// Create a new allocator for a subnet.
    ///
    /// `prefix_len` must be 1..=30. Panics on out-of-range values.
    pub fn new(base: Ipv4Addr, prefix_len: u8) -> Self {
        assert!(
            (1..=30).contains(&prefix_len),
            "IpAllocator prefix_len must be 1..=30 (got {prefix_len})"
        );

        let base_u32 = u32::from(base);
        let host_bits = 32 - prefix_len;
        // Exclude network (.0), gateway (.1), and broadcast (last)
        let max_guests = (1u32 << host_bits) - 3;

        Self {
            base: base_u32,
            prefix_len,
            max_index: max_guests,
            state: Mutex::new(AllocatorState {
                next_index: 0,
                freed: BTreeSet::new(),
                reserved: BTreeSet::new(),
            }),
        }
    }

    /// Return the gateway IP (`.1` in the subnet).
    pub fn gateway(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.base + 1)
    }

    /// Return the configured prefix length.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Allocate the next guest IP address.
    ///
    /// Returns individual addresses starting at `.2`.
    /// Reuses previously released IPs before allocating new ones.
    pub fn allocate(&self) -> Result<Ipv4Addr, NetError> {
        let mut state = self.state.lock().unwrap();

        let index = if let Some(&idx) = state.freed.iter().next() {
            state.freed.remove(&idx);
            idx
        } else {
            // Advance to the next fresh index, skipping any reserved (seeded as
            // in-use) above the high-water mark.
            loop {
                if state.next_index >= self.max_index {
                    return Err(NetError::PoolExhausted);
                }
                let idx = state.next_index;
                state.next_index += 1;
                if !state.reserved.remove(&idx) {
                    break idx;
                }
            }
        };

        let guest_ip = Ipv4Addr::from(self.base + 2 + index);
        debug!(index, %guest_ip, "allocated guest IP");
        Ok(guest_ip)
    }

    /// Release a previously allocated guest IP back to the pool.
    pub fn release(&self, guest_ip: Ipv4Addr) -> Result<(), NetError> {
        let guest_u32 = u32::from(guest_ip);

        if guest_u32 < self.base + 2 {
            return Err(NetError::NotAllocated(guest_ip));
        }

        let index = guest_u32 - self.base - 2;
        if index >= self.max_index {
            return Err(NetError::NotAllocated(guest_ip));
        }
        let mut state = self.state.lock().unwrap();

        if index < state.next_index {
            // Allocated below the high-water: make it available for reuse.
            if !state.freed.insert(index) {
                return Err(NetError::NotAllocated(guest_ip));
            }
        } else if !state.reserved.remove(&index) {
            // At/above the high-water and not reserved: never allocated.
            return Err(NetError::NotAllocated(guest_ip));
        }

        debug!(index, %guest_ip, "released guest IP");
        Ok(())
    }

    /// Reserve a specific guest IP so `allocate` will not hand it out.
    ///
    /// The allocator is in-memory and resets to empty on daemon restart; this
    /// lets startup rebuild its state from persisted VMs (each VM's recorded
    /// `guest_ip` is reserved) so a new allocation cannot collide with a still
    /// known IP and `release` of a pre-restart IP succeeds. The intervening
    /// indices are never materialized, so reserving a high IP in a large subnet
    /// stays cheap. Returns `NotAllocated` for an IP outside this subnet.
    pub fn reserve(&self, guest_ip: Ipv4Addr) -> Result<(), NetError> {
        let guest_u32 = u32::from(guest_ip);
        if guest_u32 < self.base + 2 {
            return Err(NetError::NotAllocated(guest_ip));
        }
        let index = guest_u32 - self.base - 2;
        if index >= self.max_index {
            return Err(NetError::NotAllocated(guest_ip));
        }

        let mut state = self.state.lock().unwrap();
        if index < state.next_index {
            // Below the high-water: mark in use by taking it out of the freed
            // (available) set if present.
            state.freed.remove(&index);
        } else {
            // At/above the high-water: record it so `allocate` skips it without
            // enumerating the (possibly huge) gap of intervening indices.
            state.reserved.insert(index);
        }
        debug!(index, %guest_ip, "reserved guest IP");
        Ok(())
    }
}

// ── Network Helpers ────────────────────────────────────────────────────

/// Convert a prefix length to a dotted-quad netmask.
pub fn prefix_len_to_netmask(prefix_len: u8) -> Ipv4Addr {
    let mask = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };
    Ipv4Addr::from(mask)
}

// ── MAC Address ────────────────────────────────────────────────────────

/// Generate a deterministic MAC address from an index.
///
/// Format: `AA:FC:00:XX:XX:XX` where `XX:XX:XX` encodes the lower 24 bits.
/// The `AA` prefix has the locally-administered bit set.
pub fn generate_mac(index: u32) -> String {
    let bytes = index.to_be_bytes();
    format!(
        "AA:FC:00:{:02X}:{:02X}:{:02X}",
        bytes[1], bytes[2], bytes[3]
    )
}

// ── Interface Name Validation ──────────────────────────────────────────

/// Validate a Linux network interface name (TAP device or bridge).
///
/// Linux requires interface names to be at most 15 bytes (IFNAMSIZ - 1)
/// and only contain alphanumeric characters, underscores, or hyphens.
fn validate_interface_name(name: &str) -> Result<(), NetError> {
    if name.is_empty() {
        return Err(NetError::InvalidInterfaceName {
            name: name.into(),
            reason: "name cannot be empty".into(),
        });
    }
    if name.len() > IFNAMSIZ_MAX {
        return Err(NetError::InvalidInterfaceName {
            name: name.into(),
            reason: format!("exceeds {} character limit", IFNAMSIZ_MAX),
        });
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(NetError::InvalidInterfaceName {
            name: name.into(),
            reason: "contains invalid characters (only alphanumeric, underscore, hyphen allowed)"
                .into(),
        });
    }
    Ok(())
}

// ── Bridge Management ──────────────────────────────────────────────────

/// Create a Linux bridge device with a gateway IP.
///
/// Also attempts to disable `bridge-nf-call-iptables` so that
/// bridge-local traffic bypasses nftables entirely.
pub async fn create_bridge(
    name: &str,
    gateway_ip: Ipv4Addr,
    prefix_len: u8,
) -> Result<(), NetError> {
    validate_interface_name(name)?;
    info!(bridge = name, %gateway_ip, prefix_len, "creating bridge");

    run_cmd("ip", &["link", "add", name, "type", "bridge"]).await?;

    // If any subsequent step fails, delete the interface we just created
    // to avoid leaving a zombie bridge.
    if let Err(e) = configure_bridge(name, gateway_ip, prefix_len).await {
        warn!(bridge = name, "bridge setup failed, cleaning up interface");
        if let Err(cleanup) = run_cmd("ip", &["link", "del", name]).await {
            warn!(bridge = name, error = %cleanup, "failed to delete bridge during rollback");
        }
        return Err(e);
    }

    Ok(())
}

/// Configure a newly-created bridge interface (address, link-up, sysctl).
async fn configure_bridge(
    name: &str,
    gateway_ip: Ipv4Addr,
    prefix_len: u8,
) -> Result<(), NetError> {
    run_cmd(
        "ip",
        &[
            "addr",
            "add",
            &format!("{gateway_ip}/{prefix_len}"),
            "dev",
            name,
        ],
    )
    .await?;
    run_cmd("ip", &["link", "set", "dev", name, "up"]).await?;

    // Bridge-local traffic should bypass nftables for performance.
    // Non-fatal: the br_netfilter module may not be loaded.
    if let Err(e) = run_cmd("sysctl", &["-w", "net.bridge.bridge-nf-call-iptables=0"]).await {
        warn!(
            "could not disable bridge-nf-call-iptables: {e} \
             (inter-VM traffic will still work via nftables forward rules)"
        );
    }

    Ok(())
}

/// Delete a Linux bridge device.
pub async fn delete_bridge(name: &str) -> Result<(), NetError> {
    validate_interface_name(name)?;
    info!(bridge = name, "deleting bridge");
    run_cmd("ip", &["link", "set", "dev", name, "down"]).await?;
    run_cmd("ip", &["link", "del", name]).await?;
    Ok(())
}

/// Attach a TAP device to a bridge as a slave port.
pub async fn attach_to_bridge(tap_name: &str, bridge_name: &str) -> Result<(), NetError> {
    validate_interface_name(tap_name)?;
    validate_interface_name(bridge_name)?;
    debug!(
        tap = tap_name,
        bridge = bridge_name,
        "attaching TAP to bridge"
    );
    run_cmd(
        "ip",
        &["link", "set", "dev", tap_name, "master", bridge_name],
    )
    .await?;
    Ok(())
}

// ── TAP Devices ────────────────────────────────────────────────────────

/// Create a TAP device.
///
/// The TAP is a plain L2 port (no IP address) — it gets its connectivity
/// by being attached to the bridge. Requires root or `CAP_NET_ADMIN`.
pub async fn create_tap(name: &str) -> Result<(), NetError> {
    validate_interface_name(name)?;
    info!(tap = name, "creating TAP device");

    run_cmd("ip", &["tuntap", "add", "dev", name, "mode", "tap"]).await?;

    if let Err(e) = run_cmd("ip", &["link", "set", "dev", name, "up"]).await {
        warn!(tap = name, "TAP link-up failed, cleaning up device");
        if let Err(cleanup) = run_cmd("ip", &["tuntap", "del", "dev", name, "mode", "tap"]).await {
            warn!(tap = name, error = %cleanup, "failed to delete TAP during rollback");
        }
        return Err(e);
    }

    Ok(())
}

/// Delete a TAP device.
///
/// Removing the TAP automatically detaches it from any bridge.
pub async fn delete_tap(name: &str) -> Result<(), NetError> {
    validate_interface_name(name)?;
    info!(tap = name, "deleting TAP device");
    run_cmd("ip", &["tuntap", "del", "dev", name, "mode", "tap"]).await?;
    Ok(())
}

// ── Guest network isolation ────────────────────────────────────────────

/// Private destination ranges an isolated guest may not reach: RFC1918 plus
/// the CGNAT block (100.64/10, which the tailnet uses). Same-bridge traffic is
/// L2 and never reaches the forward hook, so a guest's own subnet does not need
/// excluding here.
const PRIVATE_DEST_RANGES: &str = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10";

/// Policy applied by [`init_nat`] when guest isolation is enabled.
///
/// Isolation denies an untrusted guest every private (LAN/homelab) destination
/// while keeping internet egress, and blocks the guest from reaching the host
/// itself. It is a daemon-wide policy over the shared bridge, not per-VM.
///
/// It filters IPv4 only. Guests get no IPv6 egress (no v6 NAT, address, or
/// route), so there is nothing to deny there; the one remaining v6 surface is a
/// guest reaching another guest's, or the host's, link-local `fe80::` across the
/// shared L2 segment, which no ip-family rule can see. That is dissolved by the
/// planned per-tap-routed rework (which removes the shared segment), not here.
#[derive(Debug, Clone, Default)]
pub struct IsolationPolicy {
    /// Resolver IPs to carve out on port 53 so DNS survives the private-address
    /// deny. Only resolvers inside a private range need (and get) a carve-out; a
    /// public resolver is reachable anyway.
    pub resolvers: Vec<Ipv4Addr>,
}

/// Whether `ip` is in an RFC1918 or CGNAT range, i.e. a destination the
/// private-address deny would otherwise drop.
fn is_private_v4(ip: Ipv4Addr) -> bool {
    ip.is_private() || matches!(ip.octets(), [100, b, ..] if (64..=127).contains(&b))
}

/// DNS carve-out rules: accept UDP/TCP port 53 to each private resolver.
///
/// Keyed on `iifname <bridge>` and the resolver's destination address only,
/// never on the guest source address (which a guest fully controls and can
/// spoof). Used in both the forward chain (for a routed resolver like a LAN
/// Pi-hole) and the input chain (for a host-local resolver, whose packets are
/// local delivery and never reach forward); one of the two matches per resolver,
/// the other is inert.
fn dns_carveout_rules(bridge: &str, policy: &IsolationPolicy) -> Vec<Vec<String>> {
    let mut rules = Vec::new();
    for r in policy.resolvers.iter().filter(|r| is_private_v4(**r)) {
        for proto in ["udp", "tcp"] {
            rules.push(vec![
                "iifname".into(),
                bridge.into(),
                "ip".into(),
                "daddr".into(),
                r.to_string(),
                proto.into(),
                "dport".into(),
                "53".into(),
                "accept".into(),
                "comment".into(),
                "\"husker:isolation-dns\"".into(),
            ]);
        }
    }
    rules
}

/// The forward-chain rules an isolation policy installs, in order, each as an
/// `nft` argument vector (after `add rule ip <table> forward`). Returned as data
/// so the exact rules and their ordering can be unit-tested without running
/// `nft`. These must be added BEFORE the broad `iifname <bridge> accept` rules,
/// or the accept shadows them and they are dead.
///
/// Matching is keyed on `iifname <bridge>` (the ingress interface, which the
/// kernel sets and a guest cannot forge), never on the guest source address. A
/// guest that spoofs its source IP outside the bridge subnet would slip past a
/// source-matched deny into the broad accept below.
fn isolation_forward_rules(bridge: &str, policy: &IsolationPolicy) -> Vec<Vec<String>> {
    let mut rules = Vec::new();
    // Established/related first: a guest's reply to a client that reached it
    // through a DNAT port forward has the client's (possibly private) address as
    // destination and would otherwise be dropped by the private-address deny
    // below. Conntrack lets those replies through without opening guest-initiated
    // access, since a guest-initiated flow to the LAN is `ct state new` and never
    // reaches established state (the deny drops its first packet).
    rules.push(vec![
        "iifname".into(),
        bridge.into(),
        "ct".into(),
        "state".into(),
        "established,related".into(),
        "accept".into(),
        "comment".into(),
        "\"husker:isolation-est\"".into(),
    ]);
    // DNS carve-out: a private resolver must be reachable on port 53 before the
    // private-address deny below would drop it.
    rules.extend(dns_carveout_rules(bridge, policy));
    // Deny every private destination beyond the bridge (LAN + homelab).
    rules.push(vec![
        "iifname".into(),
        bridge.into(),
        "ip".into(),
        "daddr".into(),
        format!("{{ {PRIVATE_DEST_RANGES} }}"),
        "drop".into(),
        "comment".into(),
        "\"husker:isolation-deny-private\"".into(),
    ]);
    rules
}

/// The input-chain rules that stop an isolated guest reaching the host itself.
///
/// A guest addresses the host's own IPs (the bridge gateway, and any host LAN IP
/// it routes to) as local delivery, so those packets hit the INPUT hook, not
/// FORWARD; a forward-chain deny never sees them. A guest needs nothing from the
/// host EXCEPT a resolver that runs on the host, so the DNS carve-outs precede
/// the drop; then all remaining guest-originated input traffic is dropped.
///
/// Keyed on `iifname <bridge>`, not the guest source address, for the same
/// anti-spoofing reason as the forward rules.
fn isolation_input_rules(bridge: &str, policy: &IsolationPolicy) -> Vec<Vec<String>> {
    let mut rules = dns_carveout_rules(bridge, policy);
    rules.push(vec![
        "iifname".into(),
        bridge.into(),
        "drop".into(),
        "comment".into(),
        "\"husker:isolation-host-guard\"".into(),
    ]);
    rules
}

// ── nftables NAT ───────────────────────────────────────────────────────

/// Initialize the husker nftables table with bridge-level rules.
///
/// Installs the permanent rules covering the entire bridge subnet:
/// - Masquerade outbound traffic from the bridge subnet
/// - Accept forwarding from the bridge
/// - Accept forwarding to the bridge
///
/// When `isolation` is `Some`, also installs (before the accepts) a DNS
/// carve-out and a private-destination deny in the forward chain, plus an input
/// chain that blocks the guest from reaching the host. See [`IsolationPolicy`].
///
/// Port-forward DNAT rules are added per-VM in the prerouting chain.
/// Call once at daemon startup. Requires root or `CAP_NET_ADMIN`.
pub async fn init_nat(
    bridge_name: &str,
    bridge_subnet: &str,
    host_interface: &str,
    isolation: Option<&IsolationPolicy>,
) -> Result<(), NetError> {
    info!(
        bridge = bridge_name,
        subnet = bridge_subnet,
        host_iface = host_interface,
        "initializing nftables table"
    );

    // IP forwarding is required for NAT to route packets between bridge
    // and external interfaces.
    run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"]).await?;

    let table = nft_table_for_bridge(bridge_name);

    // Delete only THIS bridge's table (ignore error if absent), then recreate.
    // Other daemons' tables are untouched.
    let _ = run_cmd("nft", &["delete", "table", "ip", &table]).await;

    run_cmd("nft", &["add", "table", "ip", &table]).await?;

    // Postrouting chain with masquerade rule
    run_cmd(
        "nft",
        &[
            "add",
            "chain",
            "ip",
            &table,
            "postrouting",
            "{ type nat hook postrouting priority srcnat; policy accept; }",
        ],
    )
    .await?;
    run_cmd(
        "nft",
        &[
            "add",
            "rule",
            "ip",
            &table,
            "postrouting",
            "ip",
            "saddr",
            bridge_subnet,
            "oifname",
            host_interface,
            "masquerade",
            "comment",
            "\"husker:bridge-masq\"",
        ],
    )
    .await?;

    // Forward chain with bridge accept rules
    run_cmd(
        "nft",
        &[
            "add",
            "chain",
            "ip",
            &table,
            "forward",
            "{ type filter hook forward priority filter; policy accept; }",
        ],
    )
    .await?;

    // Isolation forward rules (DNS carve-out + private-destination deny) MUST
    // precede the broad bridge accepts below, or the accept shadows them.
    if let Some(policy) = isolation {
        for rule in isolation_forward_rules(bridge_name, policy) {
            let mut args = vec!["add", "rule", "ip", &table, "forward"];
            args.extend(rule.iter().map(String::as_str));
            run_cmd("nft", &args).await?;
        }
    }

    run_cmd(
        "nft",
        &[
            "add",
            "rule",
            "ip",
            &table,
            "forward",
            "iifname",
            bridge_name,
            "accept",
            "comment",
            "\"husker:bridge-fwd-out\"",
        ],
    )
    .await?;
    run_cmd(
        "nft",
        &[
            "add",
            "rule",
            "ip",
            &table,
            "forward",
            "oifname",
            bridge_name,
            "accept",
            "comment",
            "\"husker:bridge-fwd-in\"",
        ],
    )
    .await?;

    // Prerouting chain for per-VM port forwards
    run_cmd(
        "nft",
        &[
            "add",
            "chain",
            "ip",
            &table,
            "prerouting",
            "{ type nat hook prerouting priority dstnat; policy accept; }",
        ],
    )
    .await?;

    // Isolation host guard: a separate input chain so the guest cannot reach the
    // host's own addresses (which are local delivery, hitting INPUT, not the
    // forward chain above). Lives in this same table so `cleanup_nat` removes it.
    if let Some(policy) = isolation {
        run_cmd(
            "nft",
            &[
                "add",
                "chain",
                "ip",
                &table,
                "input",
                "{ type filter hook input priority filter; policy accept; }",
            ],
        )
        .await?;
        // DNS carve-outs (for a host-local resolver) precede the host-guard drop.
        for rule in isolation_input_rules(bridge_name, policy) {
            let mut args = vec!["add", "rule", "ip", &table, "input"];
            args.extend(rule.iter().map(String::as_str));
            run_cmd("nft", &args).await?;
        }
    }

    Ok(())
}

// ── Host uplink resolution ─────────────────────────────────────────────

/// Sentinel config value meaning "pick the default-route interface at startup".
pub const HOST_INTERFACE_AUTO: &str = "auto";

/// Historical fallback uplink when no default route can be found.
const HOST_INTERFACE_FALLBACK: &str = "eth0";

/// How the effective guest-NAT uplink interface was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostInterfaceSource {
    /// Operator-configured name, used verbatim.
    Configured,
    /// Auto-detected from the host's IPv4 default route.
    DefaultRoute,
    /// No default route found; fell back to the historical default.
    Fallback,
}

/// Result of [`resolve_host_interface`]: the interface the masquerade rule
/// pins, plus any problems worth surfacing to the operator.
#[derive(Debug)]
pub struct HostInterfaceResolution {
    pub effective: String,
    pub source: HostInterfaceSource,
    /// Human-readable problems (missing/down/route mismatch). NAT rules are
    /// still installed; these explain why guests may have no WAN until fixed.
    pub warnings: Vec<String>,
}

/// Resolve the guest-NAT uplink from the configured value.
///
/// `"auto"` (or empty) picks the interface carrying the IPv4 default route.
/// An explicit name is honored verbatim but validated: a missing or down
/// interface, or one that does not carry the default route, silently breaks
/// guest egress (the masquerade rule never matches any packet), so each of
/// those conditions becomes a warning.
pub fn resolve_host_interface(configured: &str) -> HostInterfaceResolution {
    resolve_host_interface_with(
        configured,
        default_route_interface().as_deref(),
        |iface| std::path::Path::new(&format!("/sys/class/net/{iface}")).exists(),
        interface_operstate,
    )
}

fn resolve_host_interface_with(
    configured: &str,
    default_route: Option<&str>,
    exists: impl Fn(&str) -> bool,
    operstate: impl Fn(&str) -> Option<String>,
) -> HostInterfaceResolution {
    let configured = configured.trim();
    if configured.is_empty() || configured.eq_ignore_ascii_case(HOST_INTERFACE_AUTO) {
        return match default_route {
            Some(iface) => HostInterfaceResolution {
                effective: iface.to_string(),
                source: HostInterfaceSource::DefaultRoute,
                warnings: Vec::new(),
            },
            None => HostInterfaceResolution {
                effective: HOST_INTERFACE_FALLBACK.into(),
                source: HostInterfaceSource::Fallback,
                warnings: vec![format!(
                    "no IPv4 default route found; guest NAT falls back to \
                     '{HOST_INTERFACE_FALLBACK}' - guests have no WAN until the host \
                     gains an uplink (then restart the daemon)"
                )],
            },
        };
    }

    let mut warnings = Vec::new();
    if !exists(configured) {
        warnings.push(format!(
            "host_interface '{configured}' does not exist - guests get no WAN/DNS \
             (set host_interface = \"auto\" to follow the default route)"
        ));
    } else if let Some(state) = operstate(configured)
        && (state == "down" || state == "lowerlayerdown")
    {
        warnings.push(format!(
            "host_interface '{configured}' is {state} (no carrier?) - guests get \
             no WAN/DNS until it comes up"
        ));
    }
    if let Some(route_iface) = default_route
        && route_iface != configured
    {
        warnings.push(format!(
            "IPv4 default route is via '{route_iface}' but guest NAT masquerades \
             via '{configured}'; guest egress will not be NATed (set \
             host_interface = \"auto\" or \"{route_iface}\")"
        ));
    }
    HostInterfaceResolution {
        effective: configured.to_string(),
        source: HostInterfaceSource::Configured,
        warnings,
    }
}

/// The interface carrying the host's IPv4 default route (lowest metric wins),
/// read from `/proc/net/route`.
pub fn default_route_interface() -> Option<String> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_default_route_interface(&content)
}

fn parse_default_route_interface(route_table: &str) -> Option<String> {
    let mut best: Option<(u32, String)> = None;
    for line in route_table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        // Destination and mask both zero = default route.
        if fields[1] != "00000000" || fields[7] != "00000000" {
            continue;
        }
        // RTF_UP (0x1): skip routes that are not up.
        let flags = u32::from_str_radix(fields[3], 16).unwrap_or(0);
        if flags & 0x1 == 0 {
            continue;
        }
        let metric = fields[6].parse::<u32>().unwrap_or(u32::MAX);
        let better = match &best {
            Some((m, _)) => metric < *m,
            None => true,
        };
        if better {
            best = Some((metric, fields[0].to_string()));
        }
    }
    best.map(|(_, iface)| iface)
}

/// The kernel operstate for an interface (`up`, `down`, `unknown`, ...), if
/// readable from sysfs.
pub fn interface_operstate(iface: &str) -> Option<String> {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/operstate"))
        .ok()
        .map(|s| s.trim().to_string())
}

// ── Port Forwarding ───────────────────────────────────────────────────

/// Add a port forward from `host_port` to `guest_ip:guest_port` in the nftables table for `bridge_name`.
///
/// Creates a DNAT rule in the prerouting chain. The bridge-level forward rules already allow all
/// traffic to/from the bridge, so no per-port-forward accept rule is needed.
pub async fn add_port_forward(
    host_port: u16,
    guest_ip: Ipv4Addr,
    guest_port: u16,
    tap_name: &str,
    bridge_name: &str,
) -> Result<(), NetError> {
    let table = nft_table_for_bridge(bridge_name);
    let comment = format!("\"husker-pf:{}:{}\"", tap_name, host_port);
    let dnat_target = format!("{}:{}", guest_ip, guest_port);

    info!(host_port, %guest_ip, guest_port, tap = tap_name, "adding port forward");

    // DNAT rule in prerouting chain
    run_cmd(
        "nft",
        &[
            "add",
            "rule",
            "ip",
            &table,
            "prerouting",
            "tcp",
            "dport",
            &host_port.to_string(),
            "counter",
            "dnat",
            "to",
            &dnat_target,
            "comment",
            &comment,
        ],
    )
    .await?;

    Ok(())
}

/// Remove a specific port forward by host port and TAP name from the nftables table for `bridge_name`.
///
/// Queries the table for rules tagged with the port-forward comment and deletes them by handle.
pub async fn remove_port_forward(
    host_port: u16,
    tap_name: &str,
    bridge_name: &str,
) -> Result<(), NetError> {
    let table = nft_table_for_bridge(bridge_name);
    info!(host_port, tap = tap_name, "removing port forward");

    let output = match run_cmd("nft", &["-j", "list", "table", "ip", &table]).await {
        Ok(output) => output,
        // A missing table (nft "No such file or directory") means there are no
        // rules to remove, which is success. Surface any OTHER failure (nft not
        // installed, permission denied) at warn so it does not vanish silently
        // while leaving orphaned DNAT rules behind.
        Err(e) => {
            if matches!(&e, NetError::CommandFailed { message, .. } if message.contains("No such file or directory"))
            {
                debug!(table = %table, "nft table absent; no port-forward rules to remove");
            } else {
                warn!(table = %table, error = %e, "nft list failed during port-forward removal; rules may remain");
            }
            return Ok(());
        }
    };

    let comment_tag = format!("husker-pf:{}:{}", tap_name, host_port);
    let rules = find_rules_by_comment(&output, &comment_tag);

    let mut failures = Vec::new();
    for (chain, handle) in rules {
        debug!(chain = %chain, handle, "deleting port forward rule");
        if let Err(e) = run_cmd(
            "nft",
            &[
                "delete",
                "rule",
                "ip",
                &table,
                &chain,
                "handle",
                &handle.to_string(),
            ],
        )
        .await
        {
            failures.push(format!("{chain} handle {handle}: {e}"));
        }
    }

    if !failures.is_empty() {
        return Err(NetError::CommandFailed {
            cmd: "nft delete rule".into(),
            message: failures.join("; "),
        });
    }
    Ok(())
}

/// Remove all port forwards for a VM identified by its TAP name, from the nftables table for `bridge_name`.
pub async fn remove_all_port_forwards(tap_name: &str, bridge_name: &str) -> Result<(), NetError> {
    let table = nft_table_for_bridge(bridge_name);
    let output = match run_cmd("nft", &["-j", "list", "table", "ip", &table]).await {
        Ok(output) => output,
        // A missing table (nft "No such file or directory") means there are no
        // rules to remove, which is success. Surface any OTHER failure (nft not
        // installed, permission denied) at warn so it does not vanish silently
        // while leaving orphaned DNAT rules behind.
        Err(e) => {
            if matches!(&e, NetError::CommandFailed { message, .. } if message.contains("No such file or directory"))
            {
                debug!(table = %table, "nft table absent; no port-forward rules to remove");
            } else {
                warn!(table = %table, error = %e, "nft list failed during port-forward removal; rules may remain");
            }
            return Ok(());
        }
    };

    let prefix = format!("husker-pf:{tap_name}:");
    let rules = find_rules_by_comment_prefix(&output, &prefix);

    let mut failures = Vec::new();
    for (chain, handle) in rules {
        debug!(chain = %chain, handle, "deleting port forward rule");
        if let Err(e) = run_cmd(
            "nft",
            &[
                "delete",
                "rule",
                "ip",
                &table,
                &chain,
                "handle",
                &handle.to_string(),
            ],
        )
        .await
        {
            failures.push(format!("{chain} handle {handle}: {e}"));
        }
    }

    if !failures.is_empty() {
        return Err(NetError::CommandFailed {
            cmd: "nft delete rule".into(),
            message: failures.join("; "),
        });
    }
    Ok(())
}

/// Remove this daemon's per-bridge nftables table.
///
/// Call on daemon shutdown to clean up its own rules. Other daemons' tables
/// (keyed by their own bridge) are left intact.
pub async fn cleanup_nat(bridge_name: &str) -> Result<(), NetError> {
    let table = nft_table_for_bridge(bridge_name);
    info!(table = %table, "removing nftables table");
    run_cmd("nft", &["delete", "table", "ip", &table]).await?;
    Ok(())
}

/// Parse nft JSON output to find rules matching a comment tag.
///
/// Returns `Vec<(chain_name, handle)>` for each matching rule.
fn find_rules_by_comment(nft_json: &str, comment_tag: &str) -> Vec<(String, u64)> {
    let parsed: serde_json::Value = match serde_json::from_str(nft_json) {
        Ok(v) => v,
        Err(e) => {
            warn!("failed to parse nft JSON output: {e}");
            return Vec::new();
        }
    };

    let Some(entries) = parsed.get("nftables").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    let mut results = Vec::new();
    for entry in entries {
        let Some(rule) = entry.get("rule") else {
            continue;
        };
        let Some(comment) = rule.get("comment").and_then(|c| c.as_str()) else {
            continue;
        };

        if comment != comment_tag {
            continue;
        }

        let chain = rule.get("chain").and_then(|c| c.as_str()).unwrap_or("");
        let handle = rule.get("handle").and_then(|h| h.as_u64()).unwrap_or(0);

        if !chain.is_empty() && handle > 0 {
            results.push((chain.to_string(), handle));
        }
    }

    results
}

/// Parse nft JSON output to find rules whose comment starts with a given prefix.
///
/// Returns `Vec<(chain_name, handle)>` for each matching rule.
fn find_rules_by_comment_prefix(nft_json: &str, prefix: &str) -> Vec<(String, u64)> {
    let parsed: serde_json::Value = match serde_json::from_str(nft_json) {
        Ok(v) => v,
        Err(e) => {
            warn!("failed to parse nft JSON output: {e}");
            return Vec::new();
        }
    };

    let Some(entries) = parsed.get("nftables").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    let mut results = Vec::new();
    for entry in entries {
        let Some(rule) = entry.get("rule") else {
            continue;
        };
        let Some(comment) = rule.get("comment").and_then(|c| c.as_str()) else {
            continue;
        };

        if !comment.starts_with(prefix) {
            continue;
        }

        let chain = rule.get("chain").and_then(|c| c.as_str()).unwrap_or("");
        let handle = rule.get("handle").and_then(|h| h.as_u64()).unwrap_or(0);

        if !chain.is_empty() && handle > 0 {
            results.push((chain.to_string(), handle));
        }
    }

    results
}

/// Walk `nft -j list table` JSON for the rule with the given comment and return
/// its inline (packets, bytes) counter, if present.
///
/// The counter is an anonymous per-rule counter statement embedded in the DNAT
/// rule (see `add_port_forward`), so it serializes as `{"counter":{"packets":N,
/// "bytes":M}}` (an object) rather than a named-counter reference (a string).
fn parse_counter_from_table_json(json: &str, comment_tag: &str) -> Option<(u64, u64)> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    for item in v.get("nftables")?.as_array()? {
        let rule = match item.get("rule") {
            Some(r) => r,
            None => continue,
        };
        if rule.get("comment").and_then(|c| c.as_str()) != Some(comment_tag) {
            continue;
        }
        for expr in rule.get("expr")?.as_array()? {
            if let Some(counter) = expr.get("counter") {
                let p = counter.get("packets")?.as_u64()?;
                let b = counter.get("bytes")?.as_u64()?;
                return Some((p, b));
            }
        }
    }
    None
}

/// Collect every husker-managed port-forward rule's (packets, bytes) counter,
/// keyed by its own `husker-pf:<tap>:<port>` comment.
fn parse_all_counters_from_table_json(json: &str) -> HashMap<String, (u64, u64)> {
    let mut out = HashMap::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return out;
    };
    let Some(items) = v.get("nftables").and_then(|n| n.as_array()) else {
        return out;
    };
    for item in items {
        let Some(rule) = item.get("rule") else {
            continue;
        };
        let Some(comment) = rule.get("comment").and_then(|c| c.as_str()) else {
            continue;
        };
        if !comment.starts_with("husker-pf:") {
            continue;
        }
        let Some(expr) = rule.get("expr").and_then(|e| e.as_array()) else {
            continue;
        };
        for e in expr {
            if let Some(c) = e.get("counter")
                && let (Some(p), Some(b)) = (
                    c.get("packets").and_then(|x| x.as_u64()),
                    c.get("bytes").and_then(|x| x.as_u64()),
                )
            {
                out.insert(comment.to_string(), (p, b));
            }
        }
    }
    out
}

/// Read the DNAT rule's traffic counter for a single port forward.
///
/// Runs a single `nft -j list table` call and picks out the rule tagged
/// `husker-pf:<tap_name>:<host_port>`.
pub async fn read_port_forward_counter(
    host_port: u16,
    tap_name: &str,
    bridge_name: &str,
) -> Result<(u64, u64), NetError> {
    let table = nft_table_for_bridge(bridge_name);
    let output = run_cmd("nft", &["-j", "list", "table", "ip", &table]).await?;
    let tag = format!("husker-pf:{tap_name}:{host_port}");
    parse_counter_from_table_json(&output, &tag).ok_or_else(|| NetError::CommandFailed {
        cmd: "nft -j list table".into(),
        message: format!("no counter found for rule tagged {tag}"),
    })
}

/// Read every husker-managed port-forward counter in one `nft list table` call.
///
/// Used by the idle-policy loop's per-tick snapshot so it does not shell out to
/// `nft` once per forward; results are keyed by each rule's own `husker-pf:`
/// comment (see `parse_all_counters_from_table_json`).
pub async fn read_all_port_forward_counters(
    bridge_name: &str,
) -> Result<HashMap<String, (u64, u64)>, NetError> {
    let table = nft_table_for_bridge(bridge_name);
    let output = run_cmd("nft", &["-j", "list", "table", "ip", &table]).await?;
    Ok(parse_all_counters_from_table_json(&output))
}

// ── Helpers ────────────────────────────────────────────────────────────

async fn run_cmd(cmd: &str, args: &[&str]) -> Result<String, NetError> {
    debug!(cmd, args = args.join(" "), "executing command");

    let output = tokio::process::Command::new(cmd)
        .args(args)
        .output()
        .await?;

    if !output.status.success() {
        return Err(NetError::CommandFailed {
            cmd: format!("{cmd} {}", args.join(" ")),
            message: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

// ── Subnet conflict detection ──────────────────────────────────────────

/// Network address of `addr` masked to `prefix_len` bits.
///
/// `prefix_len` is clamped to 32 so an out-of-range value can never produce an
/// invalid (UB) shift amount, even though callers already validate the range.
fn network_addr(addr: Ipv4Addr, prefix_len: u8) -> u32 {
    let bits = u32::from(addr);
    match prefix_len.min(32) {
        0 => 0,
        p => bits & (!0u32 << (32 - p)),
    }
}

/// Whether two IPv4 CIDR blocks overlap (one fully contains the other's
/// network, which for CIDRs means they share the network address at the
/// shorter prefix length).
fn cidrs_overlap(a: Ipv4Addr, a_prefix: u8, b: Ipv4Addr, b_prefix: u8) -> bool {
    let p = a_prefix.min(b_prefix);
    network_addr(a, p) == network_addr(b, p)
}

/// A destination route parsed from one line of `ip route show`.
#[derive(Debug, PartialEq, Eq)]
struct RouteEntry {
    base: Ipv4Addr,
    prefix_len: u8,
    dev: Option<String>,
}

/// Parse a route destination token: `"10.0.0.0/24"` or a bare host `"10.0.0.5"`
/// (treated as `/32`). Returns `None` for anything that is not an IPv4 dest.
fn parse_dest_cidr(s: &str) -> Option<(Ipv4Addr, u8)> {
    match s.split_once('/') {
        Some((ip, pfx)) => {
            let ip: Ipv4Addr = ip.parse().ok()?;
            let pfx: u8 = pfx.parse().ok()?;
            (pfx <= 32).then_some((ip, pfx))
        }
        None => s.parse::<Ipv4Addr>().ok().map(|ip| (ip, 32)),
    }
}

/// Parse one `ip route show` line into its destination CIDR and device.
///
/// Returns `None` for the default route and for any line whose first token is
/// not an IPv4 destination (e.g. `blackhole`/`unreachable` routes, IPv6).
fn parse_route_entry(line: &str) -> Option<RouteEntry> {
    let mut toks = line.split_whitespace();
    let dest = toks.next()?;
    if dest == "default" {
        return None;
    }
    let (base, prefix_len) = parse_dest_cidr(dest)?;
    // Capture the `dev <name>` that follows, if any.
    let mut dev = None;
    while let Some(t) = toks.next() {
        if t == "dev" {
            dev = toks.next().map(String::from);
            break;
        }
    }
    Some(RouteEntry {
        base,
        prefix_len,
        dev,
    })
}

/// A route at this prefix length or shorter is "default-equivalent": the
/// default route (`0.0.0.0/0`) and the split-default `/1` routes (`0.0.0.0/1` +
/// `128.0.0.0/1`) that VPNs install for `redirect-gateway`. These represent "the
/// rest of the internet"; a more-specific bridge subnet wins longest-prefix
/// match without hijacking them, so they are never a real conflict.
const DEFAULT_EQUIVALENT_MAX_PREFIX: u8 = 1;

/// Find the first existing host route that overlaps `configured`, skipping
/// default-equivalent routes and any route already on `own_bridge` (husker's own
/// device, so a leftover bridge from a crashed run is not reported as a foreign
/// conflict).
fn find_subnet_conflict(
    configured: (Ipv4Addr, u8),
    route_output: &str,
    own_bridge: &str,
) -> Option<RouteEntry> {
    route_output
        .lines()
        .filter_map(parse_route_entry)
        .find(|r| {
            r.prefix_len > DEFAULT_EQUIVALENT_MAX_PREFIX
                && r.dev.as_deref() != Some(own_bridge)
                && cidrs_overlap(configured.0, configured.1, r.base, r.prefix_len)
        })
}

/// Fail if the configured bridge subnet overlaps an existing host route.
///
/// Run at daemon startup (after deleting husker's own stale bridge) so a
/// misconfigured or colliding subnet is rejected with guidance instead of
/// silently hijacking or blackholing host traffic once NAT rules are installed.
/// `subnet_label` is the original CIDR string, used only for the error message.
pub async fn check_subnet_conflict(
    base: Ipv4Addr,
    prefix_len: u8,
    subnet_label: &str,
    bridge_name: &str,
) -> Result<(), NetError> {
    let routes = run_cmd("ip", &["-4", "route", "show"]).await?;
    if let Some(conflict) = find_subnet_conflict((base, prefix_len), &routes, bridge_name) {
        return Err(NetError::SubnetConflict {
            subnet: subnet_label.to_string(),
            conflict: format!("{}/{}", conflict.base, conflict.prefix_len),
            dev: conflict.dev.unwrap_or_else(|| "?".to_string()),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── Guest isolation rules ──────────────────────────────────────────

    fn rule_str(rule: &[String]) -> String {
        rule.join(" ")
    }

    #[test]
    fn is_private_v4_covers_rfc1918_and_cgnat() {
        for ip in ["10.10.30.10", "192.168.1.1", "172.20.0.1", "100.64.0.5"] {
            assert!(is_private_v4(ip.parse().unwrap()), "{ip} should be private");
        }
        for ip in ["1.1.1.1", "8.8.8.8", "203.0.113.5"] {
            assert!(!is_private_v4(ip.parse().unwrap()), "{ip} should be public");
        }
    }

    #[test]
    fn isolation_forward_rules_deny_private_after_dns_carveout() {
        let policy = IsolationPolicy {
            resolvers: vec!["10.10.30.10".parse().unwrap()],
        };
        let rules = isolation_forward_rules("husker0", &policy);
        let joined: Vec<String> = rules.iter().map(|r| rule_str(r)).collect();

        // DNS carve-out for the private resolver on port 53, udp and tcp.
        assert!(joined.iter().any(|r| r.contains("10.10.30.10")
            && r.contains("udp dport 53")
            && r.contains("accept")));
        assert!(joined.iter().any(|r| r.contains("10.10.30.10")
            && r.contains("tcp dport 53")
            && r.contains("accept")));
        // Private-destination deny is present.
        let deny_idx = joined.iter().position(|r| r.contains("drop")).unwrap();
        assert!(joined[deny_idx].contains("10.0.0.0/8"));
        assert!(joined[deny_idx].contains("192.168.0.0/16"));
        assert!(joined[deny_idx].contains("100.64.0.0/10"));
        // Every carve-out accept precedes the deny, or the deny shadows DNS.
        let last_accept = joined.iter().rposition(|r| r.contains("accept")).unwrap();
        assert!(
            last_accept < deny_idx,
            "DNS carve-out must precede the deny; got {joined:?}"
        );
    }

    /// The deny and carve-out must key on the ingress interface, never on the
    /// guest source address: a guest fully controls its source and would spoof
    /// a non-subnet address to slip a private-destination packet past a
    /// source-matched deny into the broad bridge accept.
    #[test]
    fn isolation_rules_do_not_key_on_guest_source_address() {
        let policy = IsolationPolicy {
            resolvers: vec!["10.10.30.10".parse().unwrap()],
        };
        for rule in isolation_forward_rules("husker0", &policy)
            .iter()
            .chain(isolation_input_rules("husker0", &policy).iter())
        {
            let s = rule_str(rule);
            assert!(
                !s.contains("saddr"),
                "isolation rule must not match on guest source: {s}"
            );
            assert!(
                s.contains("iifname husker0"),
                "isolation rule must key on ingress interface: {s}"
            );
        }
    }

    #[test]
    fn isolation_forward_rules_skip_carveout_for_public_resolver() {
        // A public resolver is reachable anyway, so it earns no carve-out rule.
        let policy = IsolationPolicy {
            resolvers: vec!["1.1.1.1".parse().unwrap()],
        };
        let rules = isolation_forward_rules("husker0", &policy);
        let joined: Vec<String> = rules.iter().map(|r| rule_str(r)).collect();
        assert!(!joined.iter().any(|r| r.contains("1.1.1.1")));
        // Just the established accept and the deny, no DNS carve-out.
        assert_eq!(rules.len(), 2, "expected [established, deny]: {joined:?}");
        assert!(joined[0].contains("ct state established,related"));
        assert!(joined[1].contains("drop"));
    }

    /// Reply traffic for a connection reaching a guest through a DNAT port
    /// forward must be accepted before the private-destination deny, or forwards
    /// from a private (LAN/VPN) client break. It must not open guest-initiated
    /// access: a guest-initiated LAN flow is `ct state new`, never established.
    #[test]
    fn isolation_forward_rules_accept_established_before_deny() {
        let policy = IsolationPolicy {
            resolvers: vec!["10.10.30.10".parse().unwrap()],
        };
        let joined: Vec<String> = isolation_forward_rules("husker0", &policy)
            .iter()
            .map(|r| rule_str(r))
            .collect();
        let est_idx = joined
            .iter()
            .position(|r| r.contains("ct state established,related") && r.contains("accept"))
            .expect("established accept present");
        let deny_idx = joined.iter().position(|r| r.contains("drop")).unwrap();
        assert!(
            est_idx < deny_idx,
            "established accept must precede the deny: {joined:?}"
        );
        // Only established/related, never a blanket `ct state new` accept that
        // would let guest-initiated LAN traffic through.
        assert!(!joined[est_idx].contains("new"));
    }

    /// The input chain must let a host-local resolver's DNS through before the
    /// host guard drops everything else, or enabling isolation breaks DNS for
    /// deployments whose resolver runs on the host.
    #[test]
    fn isolation_input_rules_carve_out_dns_before_host_guard() {
        let policy = IsolationPolicy {
            resolvers: vec!["10.10.30.10".parse().unwrap()],
        };
        let rules = isolation_input_rules("husker0", &policy);
        let joined: Vec<String> = rules.iter().map(|r| rule_str(r)).collect();
        let dns_idx = joined
            .iter()
            .position(|r| r.contains("10.10.30.10") && r.contains("dport 53"))
            .expect("input DNS carve-out present");
        let guard_idx = joined
            .iter()
            .position(|r| r.contains("isolation-host-guard"))
            .expect("host guard present");
        assert!(
            dns_idx < guard_idx,
            "DNS carve-out must precede the guard: {joined:?}"
        );
        // The guard drops all guest-bridge input, not a source-scoped subset.
        assert!(joined[guard_idx].contains("iifname husker0"));
        assert!(joined[guard_idx].contains("drop"));
        assert!(!joined[guard_idx].contains("saddr"));
    }

    // ── Host uplink resolution ─────────────────────────────────────────

    const ROUTE_TABLE: &str = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
        enp1s0\t00000000\t010014AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
        enp1s0\t000014AC\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
        wlan0\t00000000\t010014AC\t0003\t0\t0\t600\t00000000\t0\t0\t0\n";

    #[test]
    fn default_route_picks_lowest_metric() {
        assert_eq!(
            parse_default_route_interface(ROUTE_TABLE).as_deref(),
            Some("enp1s0"),
            "wired default (metric 100) beats wifi (metric 600)"
        );
    }

    #[test]
    fn default_route_skips_non_default_and_down_routes() {
        // Only a non-default route: no answer.
        let non_default = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
            eth0\t000014AC\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(parse_default_route_interface(non_default), None);
        // A default route without RTF_UP is ignored.
        let down = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
            eth0\t00000000\t010014AC\t0002\t0\t0\t0\t00000000\t0\t0\t0\n";
        assert_eq!(parse_default_route_interface(down), None);
        assert_eq!(parse_default_route_interface(""), None);
    }

    #[test]
    fn resolve_auto_follows_default_route() {
        for configured in ["auto", "AUTO", "", "  "] {
            let r = resolve_host_interface_with(
                configured,
                Some("enp1s0"),
                |_| true,
                |_| Some("up".into()),
            );
            assert_eq!(r.effective, "enp1s0");
            assert_eq!(r.source, HostInterfaceSource::DefaultRoute);
            assert!(r.warnings.is_empty(), "warnings: {:?}", r.warnings);
        }
    }

    #[test]
    fn resolve_auto_without_default_route_falls_back_with_warning() {
        let r = resolve_host_interface_with("auto", None, |_| true, |_| Some("up".into()));
        assert_eq!(r.effective, "eth0");
        assert_eq!(r.source, HostInterfaceSource::Fallback);
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("no IPv4 default route"));
    }

    #[test]
    fn resolve_configured_healthy_interface_has_no_warnings() {
        let r =
            resolve_host_interface_with("enp1s0", Some("enp1s0"), |_| true, |_| Some("up".into()));
        assert_eq!(r.effective, "enp1s0");
        assert_eq!(r.source, HostInterfaceSource::Configured);
        assert!(r.warnings.is_empty(), "warnings: {:?}", r.warnings);
    }

    #[test]
    fn resolve_configured_missing_interface_warns() {
        let r = resolve_host_interface_with("eth9", None, |_| false, |_| None);
        assert_eq!(r.effective, "eth9", "explicit config is honored verbatim");
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("does not exist"));
    }

    #[test]
    fn resolve_configured_down_interface_warns() {
        let r = resolve_host_interface_with(
            "enp4s0",
            Some("enp4s0"),
            |_| true,
            |_| Some("down".into()),
        );
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("is down"));
    }

    #[test]
    fn resolve_configured_route_mismatch_warns() {
        // The husker01 incident: pinned iface exists but is down AND the
        // default route runs via another NIC - both problems surface.
        let r = resolve_host_interface_with(
            "enp4s0",
            Some("enp1s0"),
            |_| true,
            |_| Some("down".into()),
        );
        assert_eq!(r.effective, "enp4s0");
        assert_eq!(r.warnings.len(), 2, "warnings: {:?}", r.warnings);
        assert!(r.warnings[1].contains("default route is via 'enp1s0'"));
    }

    // ── Subnet conflict detection ──────────────────────────────────────

    #[test]
    fn network_addr_handles_boundary_prefixes_without_ub() {
        let ip = Ipv4Addr::new(192, 168, 1, 5);
        assert_eq!(network_addr(ip, 0), 0, "/0 masks to 0.0.0.0");
        assert_eq!(network_addr(ip, 32), u32::from(ip), "/32 keeps all bits");
        // Out-of-range prefixes are clamped to /32 rather than triggering an
        // invalid shift; the exact value is unimportant, only that it cannot panic.
        assert_eq!(network_addr(ip, 33), u32::from(ip));
        assert_eq!(network_addr(ip, 255), u32::from(ip));
    }

    #[test]
    fn cidrs_overlap_detects_containment_either_direction() {
        let a = Ipv4Addr::new(10, 100, 0, 0);
        // Identical block overlaps itself.
        assert!(cidrs_overlap(a, 16, a, 16));
        // A supernet route (10.0.0.0/8) contains husker's 10.100.0.0/16.
        assert!(cidrs_overlap(a, 16, Ipv4Addr::new(10, 0, 0, 0), 8));
        // A more-specific route inside the subnet still overlaps.
        assert!(cidrs_overlap(a, 16, Ipv4Addr::new(10, 100, 5, 0), 24));
        // A disjoint block does not overlap.
        assert!(!cidrs_overlap(a, 16, Ipv4Addr::new(172, 30, 0, 0), 16));
        // /0 contains everything.
        assert!(cidrs_overlap(a, 16, Ipv4Addr::new(0, 0, 0, 0), 0));
    }

    #[test]
    fn parse_route_entry_extracts_cidr_and_dev() {
        let e =
            parse_route_entry("192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.5")
                .unwrap();
        assert_eq!(e.base, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(e.prefix_len, 24);
        assert_eq!(e.dev.as_deref(), Some("wlan0"));

        // A bare host route is a /32.
        let host = parse_route_entry("10.0.0.5 dev tap0 scope link").unwrap();
        assert_eq!(host.prefix_len, 32);
        assert_eq!(host.dev.as_deref(), Some("tap0"));

        // The default route and non-IPv4 lines are ignored.
        assert!(parse_route_entry("default via 192.168.1.1 dev wlan0").is_none());
        assert!(parse_route_entry("blackhole 10.1.2.0/24").is_none());
    }

    #[test]
    fn find_subnet_conflict_reports_overlap_and_skips_own_and_default() {
        let routes = "\
default via 192.168.1.1 dev eth0 proto dhcp metric 100
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.50
172.30.0.0/24 dev husker0 proto kernel scope link src 172.30.0.1
";
        // A subnet overlapping the LAN is flagged with the offending route.
        let hit = find_subnet_conflict((Ipv4Addr::new(192, 168, 1, 0), 24), routes, "husker0")
            .expect("LAN overlap must be detected");
        assert_eq!(hit.base, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(hit.dev.as_deref(), Some("eth0"));

        // A subnet matching only husker's own bridge device is not a conflict.
        assert!(
            find_subnet_conflict((Ipv4Addr::new(172, 30, 0, 0), 24), routes, "husker0").is_none(),
            "husker's own bridge route must not count as a foreign conflict"
        );

        // A disjoint subnet is clean.
        assert!(
            find_subnet_conflict((Ipv4Addr::new(10, 200, 0, 0), 16), routes, "husker0").is_none()
        );
    }

    #[test]
    fn find_subnet_conflict_ignores_default_equivalent_routes() {
        // VPNs (OpenVPN `redirect-gateway def1`) install split-default /1 routes
        // instead of a single default. Every subnet overlaps one of these, but a
        // more-specific bridge subnet wins longest-prefix-match without hijacking
        // them, so they must not be treated as conflicts.
        let routes = "\
0.0.0.0/1 dev tun0 scope link
128.0.0.0/1 dev tun0 scope link
0.0.0.0/0 dev tun0
";
        assert!(
            find_subnet_conflict((Ipv4Addr::new(10, 100, 0, 0), 16), routes, "husker0").is_none(),
            "split-default and 0.0.0.0/0 routes must not count as conflicts"
        );

        // A real, more-specific overlapping network (e.g. a corporate /8 over VPN)
        // is still a genuine conflict.
        let real = "10.0.0.0/8 dev tun0 scope link\n";
        assert!(
            find_subnet_conflict((Ipv4Addr::new(10, 100, 0, 0), 16), real, "husker0").is_some(),
            "a real supernet route that would shadow the bridge subnet is a conflict"
        );
    }

    // ── IP Allocator ───────────────────────────────────────────────────

    #[test]
    fn ip_allocator_sequential() {
        let alloc = IpAllocator::new(Ipv4Addr::new(172, 20, 0, 0), 24);

        let guest1 = alloc.allocate().unwrap();
        assert_eq!(guest1, Ipv4Addr::new(172, 20, 0, 2));

        let guest2 = alloc.allocate().unwrap();
        assert_eq!(guest2, Ipv4Addr::new(172, 20, 0, 3));

        let guest3 = alloc.allocate().unwrap();
        assert_eq!(guest3, Ipv4Addr::new(172, 20, 0, 4));
    }

    #[test]
    fn reserve_excludes_ip_and_allows_later_release() {
        // RFC 5737 documentation range; gateway is .1, guests start at .2 (index 0).
        let alloc = IpAllocator::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        let ip2 = Ipv4Addr::new(203, 0, 113, 2); // index 0
        let ip5 = Ipv4Addr::new(203, 0, 113, 5); // index 3

        // Reserve out of order, modelling seeding from persisted VMs on restart.
        alloc.reserve(ip5).unwrap();
        alloc.reserve(ip2).unwrap();

        // allocate() must never hand out a reserved (in-use) IP.
        let handed: Vec<_> = (0..5).map(|_| alloc.allocate().unwrap()).collect();
        assert!(!handed.contains(&ip2), "reserved .2 handed out: {handed:?}");
        assert!(!handed.contains(&ip5), "reserved .5 handed out: {handed:?}");

        // A reserved IP can still be released (its VM destroyed) and then reused.
        alloc.release(ip5).unwrap();
        assert_eq!(alloc.allocate().unwrap(), ip5);
    }

    #[test]
    fn reserve_rejects_ip_outside_subnet() {
        let alloc = IpAllocator::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        // .1 is the gateway (below the first guest), and a different subnet is
        // out of range; both must be rejected, not silently mis-indexed.
        assert!(alloc.reserve(Ipv4Addr::new(203, 0, 113, 1)).is_err());
        assert!(alloc.reserve(Ipv4Addr::new(198, 51, 100, 7)).is_err());
    }

    #[test]
    fn reserve_above_high_water_is_skipped_and_reusable() {
        // Reserving an index far above the start must not enumerate the gap (it
        // is recorded as reserved and skipped by allocate), and releasing it
        // later returns it to the pool.
        let alloc = IpAllocator::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        let reserved = Ipv4Addr::new(203, 0, 113, 200); // index 198
        alloc.reserve(reserved).unwrap();

        // Drain the pool: the reserved address is never handed out.
        let handed: Vec<_> = std::iter::repeat_with(|| alloc.allocate().unwrap())
            .take(252)
            .collect();
        assert!(!handed.contains(&reserved));

        // Once its VM is destroyed, the reserved IP can be released and reused.
        alloc.release(reserved).unwrap();
        assert_eq!(alloc.allocate().unwrap(), reserved);
    }

    #[test]
    fn ip_allocator_exhaustion() {
        // /30: network(.0), gateway(.1), one guest(.2), broadcast(.3)
        let alloc = IpAllocator::new(Ipv4Addr::new(10, 0, 0, 0), 30);
        assert!(alloc.allocate().is_ok());
        assert!(matches!(alloc.allocate(), Err(NetError::PoolExhausted)));
    }

    #[test]
    fn ip_allocator_release_and_reuse() {
        let alloc = IpAllocator::new(Ipv4Addr::new(10, 0, 0, 0), 30);

        let guest = alloc.allocate().unwrap();
        assert_eq!(guest, Ipv4Addr::new(10, 0, 0, 2));

        // Pool exhausted
        assert!(alloc.allocate().is_err());

        // Release and reallocate
        alloc.release(guest).unwrap();
        let guest2 = alloc.allocate().unwrap();
        assert_eq!(guest2, Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn ip_allocator_release_reuses_lowest_index() {
        let alloc = IpAllocator::new(Ipv4Addr::new(172, 20, 0, 0), 24);

        let guest1 = alloc.allocate().unwrap(); // .2
        let _guest2 = alloc.allocate().unwrap(); // .3
        let guest3 = alloc.allocate().unwrap(); // .4

        // Release .4 then .2
        alloc.release(guest3).unwrap();
        alloc.release(guest1).unwrap();

        // Next allocation reuses .2 (lowest freed)
        let reused = alloc.allocate().unwrap();
        assert_eq!(reused, guest1);

        // Then .4
        let reused2 = alloc.allocate().unwrap();
        assert_eq!(reused2, guest3);

        // Then fresh .5
        let fresh = alloc.allocate().unwrap();
        assert_eq!(fresh, Ipv4Addr::new(172, 20, 0, 5));
    }

    proptest! {
        #[test]
        fn prop_allocator_reuses_released_ips_in_ascending_order(
            indices in proptest::collection::vec(0usize..40, 0..40)
        ) {
            let alloc = IpAllocator::new(Ipv4Addr::new(172, 20, 0, 0), 24);
            let mut allocated = Vec::new();
            for _ in 0..40 {
                allocated.push(alloc.allocate().unwrap());
            }

            let mut released_indices: Vec<usize> = indices
                .into_iter()
                .map(|i| i % allocated.len())
                .collect();
            released_indices.sort_unstable();
            released_indices.dedup();

            for idx in &released_indices {
                alloc.release(allocated[*idx]).unwrap();
            }

            let mut expected: Vec<Ipv4Addr> =
                released_indices.iter().map(|idx| allocated[*idx]).collect();
            expected.sort_by_key(|ip| u32::from(*ip));

            for ip in expected {
                let next = alloc.allocate().unwrap();
                prop_assert_eq!(next, ip);
            }
        }
    }

    #[test]
    fn ip_allocator_release_not_allocated() {
        let alloc = IpAllocator::new(Ipv4Addr::new(172, 20, 0, 0), 24);

        // Release without any allocation
        assert!(matches!(
            alloc.release(Ipv4Addr::new(172, 20, 0, 2)),
            Err(NetError::NotAllocated(_))
        ));
    }

    #[test]
    fn ip_allocator_release_wrong_range() {
        let alloc = IpAllocator::new(Ipv4Addr::new(172, 20, 0, 0), 24);
        alloc.allocate().unwrap();

        // IP outside the allocator's range
        assert!(matches!(
            alloc.release(Ipv4Addr::new(10, 0, 0, 2)),
            Err(NetError::NotAllocated(_))
        ));
    }

    #[test]
    fn ip_allocator_double_release() {
        let alloc = IpAllocator::new(Ipv4Addr::new(172, 20, 0, 0), 24);
        let guest = alloc.allocate().unwrap();

        alloc.release(guest).unwrap();
        assert!(matches!(
            alloc.release(guest),
            Err(NetError::NotAllocated(_))
        ));
    }

    #[test]
    fn ip_allocator_release_gateway_rejected() {
        let alloc = IpAllocator::new(Ipv4Addr::new(172, 20, 0, 0), 24);
        alloc.allocate().unwrap();

        // The gateway IP (.1) is not a valid guest address
        assert!(matches!(
            alloc.release(Ipv4Addr::new(172, 20, 0, 1)),
            Err(NetError::NotAllocated(_))
        ));
    }

    #[test]
    fn ip_allocator_release_network_rejected() {
        let alloc = IpAllocator::new(Ipv4Addr::new(172, 20, 0, 0), 24);
        alloc.allocate().unwrap();

        // The network address (.0) is not a valid guest address
        assert!(matches!(
            alloc.release(Ipv4Addr::new(172, 20, 0, 0)),
            Err(NetError::NotAllocated(_))
        ));
    }

    #[test]
    fn ip_allocator_gateway_and_prefix() {
        let alloc = IpAllocator::new(Ipv4Addr::new(172, 20, 0, 0), 24);
        assert_eq!(alloc.gateway(), Ipv4Addr::new(172, 20, 0, 1));
        assert_eq!(alloc.prefix_len(), 24);

        let alloc16 = IpAllocator::new(Ipv4Addr::new(10, 0, 0, 0), 16);
        assert_eq!(alloc16.gateway(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(alloc16.prefix_len(), 16);
    }

    #[test]
    fn ip_allocator_large_subnet() {
        // /16 gives 65533 guests
        let alloc = IpAllocator::new(Ipv4Addr::new(172, 20, 0, 0), 16);

        let first = alloc.allocate().unwrap();
        assert_eq!(first, Ipv4Addr::new(172, 20, 0, 2));

        let second = alloc.allocate().unwrap();
        assert_eq!(second, Ipv4Addr::new(172, 20, 0, 3));
    }

    // ── Netmask Conversion ────────────────────────────────────────────

    #[test]
    fn netmask_conversion() {
        assert_eq!(prefix_len_to_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_len_to_netmask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(prefix_len_to_netmask(30), Ipv4Addr::new(255, 255, 255, 252));
        assert_eq!(prefix_len_to_netmask(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(prefix_len_to_netmask(32), Ipv4Addr::new(255, 255, 255, 255));
    }

    // ── MAC Address ────────────────────────────────────────────────────

    #[test]
    fn mac_generation() {
        assert_eq!(generate_mac(0), "AA:FC:00:00:00:00");
        assert_eq!(generate_mac(1), "AA:FC:00:00:00:01");
        assert_eq!(generate_mac(256), "AA:FC:00:00:01:00");
    }

    #[test]
    fn mac_generation_high_values() {
        assert_eq!(generate_mac(0x00FF_FFFF), "AA:FC:00:FF:FF:FF");
        // High byte overflows — only lower 3 bytes are used
        assert_eq!(generate_mac(0x0100_0000), "AA:FC:00:00:00:00");
    }

    // ── nft table name derivation ──────────────────────────────────────

    #[test]
    fn nft_table_basic_alphanumeric() {
        assert_eq!(nft_table_for_bridge("husker0"), "husker_husker0");
    }

    #[test]
    fn nft_table_injective_dash_vs_underscore() {
        // A naive '-' -> '_' substitution would collide these two and let a
        // second daemon clobber the first's table. The escape encoding must not.
        assert_ne!(
            nft_table_for_bridge("husker-a"),
            nft_table_for_bridge("husker_a")
        );
        assert_eq!(nft_table_for_bridge("husker-a"), "husker_husker_2da");
        assert_eq!(nft_table_for_bridge("husker_a"), "husker_husker_5fa");
    }

    #[test]
    fn nft_table_is_valid_identifier() {
        // Output must contain only [A-Za-z0-9_] (a valid nft identifier).
        let t = nft_table_for_bridge("br-0_x");
        assert!(
            t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "invalid nft identifier: {t}"
        );
        // Multi-escape: each non-alphanumeric byte is encoded independently.
        assert_eq!(nft_table_for_bridge("a-b"), "husker_a_2db");
    }

    // ── Interface Name Validation ──────────────────────────────────────

    #[test]
    fn interface_name_valid() {
        assert!(validate_interface_name("husker0").is_ok());
        assert!(validate_interface_name("tap-test_1").is_ok());
        assert!(validate_interface_name("a").is_ok());
        // Exactly 15 characters
        assert!(validate_interface_name("abcdefghijklmno").is_ok());
    }

    #[test]
    fn interface_name_empty() {
        assert!(matches!(
            validate_interface_name(""),
            Err(NetError::InvalidInterfaceName { .. })
        ));
    }

    #[test]
    fn interface_name_too_long() {
        // 16 characters exceeds the limit
        assert!(matches!(
            validate_interface_name("abcdefghijklmnop"),
            Err(NetError::InvalidInterfaceName { .. })
        ));
    }

    #[test]
    fn interface_name_invalid_chars() {
        assert!(matches!(
            validate_interface_name("tap.0"),
            Err(NetError::InvalidInterfaceName { .. })
        ));
        assert!(matches!(
            validate_interface_name("tap/bad"),
            Err(NetError::InvalidInterfaceName { .. })
        ));
        assert!(matches!(
            validate_interface_name("tap name"),
            Err(NetError::InvalidInterfaceName { .. })
        ));
    }

    // ── nftables JSON Parsing ──────────────────────────────────────────

    #[test]
    fn find_rules_empty_json() {
        assert!(find_rules_by_comment("{}", "husker:tap0").is_empty());
    }

    #[test]
    fn find_rules_invalid_json() {
        assert!(find_rules_by_comment("not json", "husker:tap0").is_empty());
    }

    #[test]
    fn find_rules_no_matching_comment() {
        let json = r#"{"nftables": [
            {"rule": {"chain": "forward", "handle": 5, "comment": "husker:other"}}
        ]}"#;
        assert!(find_rules_by_comment(json, "husker:tap0").is_empty());
    }

    #[test]
    fn find_rules_matching_comments() {
        let json = r#"{"nftables": [
            {"metainfo": {"version": "1.0.9"}},
            {"table": {"family": "ip", "name": "husker", "handle": 1}},
            {"chain": {"family": "ip", "table": "husker", "name": "postrouting"}},
            {"rule": {"chain": "postrouting", "handle": 3, "comment": "husker:husker5"}},
            {"rule": {"chain": "forward", "handle": 4, "comment": "husker:husker5"}},
            {"rule": {"chain": "forward", "handle": 5, "comment": "husker:husker5"}},
            {"rule": {"chain": "forward", "handle": 6, "comment": "husker:other"}}
        ]}"#;

        let rules = find_rules_by_comment(json, "husker:husker5");
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0], ("postrouting".to_string(), 3));
        assert_eq!(rules[1], ("forward".to_string(), 4));
        assert_eq!(rules[2], ("forward".to_string(), 5));
    }

    #[test]
    fn find_rules_skips_invalid_entries() {
        let json = r#"{"nftables": [
            {"rule": {"chain": "", "handle": 5, "comment": "husker:tap0"}},
            {"rule": {"chain": "forward", "handle": 0, "comment": "husker:tap0"}},
            {"rule": {"chain": "forward", "comment": "husker:tap0"}},
            {"rule": {"chain": "forward", "handle": 7, "comment": "husker:tap0"}}
        ]}"#;

        let rules = find_rules_by_comment(json, "husker:tap0");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0], ("forward".to_string(), 7));
    }

    #[test]
    fn find_rules_empty_nftables_array() {
        let json = r#"{"nftables": []}"#;
        assert!(find_rules_by_comment(json, "husker:tap0").is_empty());
    }

    // ── Port Forward Comment Prefix Matching ──────────────────────────

    #[test]
    fn find_rules_by_prefix_matches() {
        let json = r#"{"nftables": [
            {"rule": {"chain": "prerouting", "handle": 10, "comment": "husker-pf:tap0:8080"}},
            {"rule": {"chain": "forward", "handle": 11, "comment": "husker-pf:tap0:8080"}},
            {"rule": {"chain": "prerouting", "handle": 12, "comment": "husker-pf:tap0:9090"}},
            {"rule": {"chain": "forward", "handle": 13, "comment": "husker-pf:tap1:8080"}}
        ]}"#;

        let rules = find_rules_by_comment_prefix(json, "husker-pf:tap0:");
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0], ("prerouting".to_string(), 10));
        assert_eq!(rules[1], ("forward".to_string(), 11));
        assert_eq!(rules[2], ("prerouting".to_string(), 12));
    }

    #[test]
    fn find_rules_by_prefix_no_match() {
        let json = r#"{"nftables": [
            {"rule": {"chain": "forward", "handle": 5, "comment": "husker-pf:tap1:8080"}}
        ]}"#;
        assert!(find_rules_by_comment_prefix(json, "husker-pf:tap0:").is_empty());
    }

    #[test]
    fn find_rules_by_prefix_empty_json() {
        assert!(find_rules_by_comment_prefix("{}", "husker-pf:tap0:").is_empty());
    }

    #[test]
    fn find_rules_by_prefix_invalid_json() {
        assert!(find_rules_by_comment_prefix("not json", "husker-pf:tap0:").is_empty());
    }

    #[test]
    fn find_rules_by_prefix_skips_invalid_entries() {
        let json = r#"{"nftables": [
            {"rule": {"chain": "", "handle": 5, "comment": "husker-pf:tap0:80"}},
            {"rule": {"chain": "forward", "handle": 0, "comment": "husker-pf:tap0:80"}},
            {"rule": {"chain": "forward", "comment": "husker-pf:tap0:80"}},
            {"rule": {"chain": "forward", "handle": 7, "comment": "husker-pf:tap0:80"}}
        ]}"#;

        let rules = find_rules_by_comment_prefix(json, "husker-pf:tap0:");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0], ("forward".to_string(), 7));
    }

    #[test]
    fn port_forward_comment_tag_format() {
        let tap_name = "husker5";
        let host_port: u16 = 8080;
        let comment = format!("husker-pf:{}:{}", tap_name, host_port);
        assert_eq!(comment, "husker-pf:husker5:8080");

        let prefix = format!("husker-pf:{tap_name}:");
        assert!(comment.starts_with(&prefix));
    }

    // ── Port Forward Counter Parsing ────────────────────────────────────

    #[test]
    fn parses_counter_for_matching_comment() {
        let json = r#"{"nftables":[{"rule":{"chain":"prerouting","handle":7,
          "comment":"husker-pf:tap0:8080",
          "expr":[{"match":{}},{"counter":{"packets":12,"bytes":3456}},{"dnat":{}}]}}]}"#;
        assert_eq!(
            parse_counter_from_table_json(json, "husker-pf:tap0:8080"),
            Some((12, 3456))
        );
        assert_eq!(
            parse_counter_from_table_json(json, "husker-pf:tap0:9999"),
            None
        );
    }

    #[test]
    fn parse_counter_missing_expr_returns_none() {
        let json = r#"{"nftables":[{"rule":{"chain":"prerouting","handle":7,
          "comment":"husker-pf:tap0:8080"}}]}"#;
        assert_eq!(
            parse_counter_from_table_json(json, "husker-pf:tap0:8080"),
            None
        );
    }

    #[test]
    fn parse_counter_invalid_json_returns_none() {
        assert_eq!(
            parse_counter_from_table_json("not json", "husker-pf:tap0:8080"),
            None
        );
    }

    #[test]
    fn parse_all_counters_collects_by_comment() {
        let json = r#"{"nftables":[
            {"rule":{"chain":"prerouting","handle":7,
              "comment":"husker-pf:tap0:8080",
              "expr":[{"counter":{"packets":12,"bytes":3456}},{"dnat":{}}]}},
            {"rule":{"chain":"prerouting","handle":8,
              "comment":"husker-pf:tap1:9090",
              "expr":[{"counter":{"packets":1,"bytes":64}},{"dnat":{}}]}},
            {"rule":{"chain":"forward","handle":9,
              "comment":"other-rule"}}
        ]}"#;

        let counters = parse_all_counters_from_table_json(json);
        assert_eq!(counters.len(), 2);
        assert_eq!(counters.get("husker-pf:tap0:8080"), Some(&(12, 3456)));
        assert_eq!(counters.get("husker-pf:tap1:9090"), Some(&(1, 64)));
        assert!(!counters.contains_key("other-rule"));
    }

    #[test]
    fn parse_all_counters_empty_json() {
        assert!(parse_all_counters_from_table_json("{}").is_empty());
    }

    #[test]
    fn parse_all_counters_invalid_json() {
        assert!(parse_all_counters_from_table_json("not json").is_empty());
    }
}
