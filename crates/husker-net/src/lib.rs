//! Linux networking helpers for bridge/TAP lifecycle, NAT, and port forwarding.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
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
    freed: BTreeSet<u32>,
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
            if state.next_index >= self.max_index {
                return Err(NetError::PoolExhausted);
            }
            let idx = state.next_index;
            state.next_index += 1;
            idx
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
        let mut state = self.state.lock().unwrap();

        if index >= state.next_index || index >= self.max_index {
            return Err(NetError::NotAllocated(guest_ip));
        }

        if !state.freed.insert(index) {
            return Err(NetError::NotAllocated(guest_ip));
        }

        debug!(index, %guest_ip, "released guest IP");
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

// ── nftables NAT ───────────────────────────────────────────────────────

/// Initialize the husker nftables table with bridge-level rules.
///
/// Installs three permanent rules covering the entire bridge subnet:
/// - Masquerade outbound traffic from the bridge subnet
/// - Accept forwarding from the bridge
/// - Accept forwarding to the bridge
///
/// Port-forward DNAT rules are added per-VM in the prerouting chain.
/// Call once at daemon startup. Requires root or `CAP_NET_ADMIN`.
pub async fn init_nat(
    bridge_name: &str,
    bridge_subnet: &str,
    host_interface: &str,
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

    Ok(())
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
        // A missing table means there are no rules to remove (success). Any other
        // read failure is logged so it does not vanish silently.
        Err(e) => {
            debug!(table = %table, error = %e, "nft list failed; assuming no port-forward rules to remove");
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
        // A missing table means there are no rules to remove (success). Any other
        // read failure is logged so it does not vanish silently.
        Err(e) => {
            debug!(table = %table, error = %e, "nft list failed; assuming no port-forward rules to remove");
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
}
