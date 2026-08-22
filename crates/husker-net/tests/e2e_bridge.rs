//! E2E tests for bridge networking on real Linux.
//!
//! These tests create actual kernel resources (bridges, TAPs, nftables rules)
//! and must be run as root on Linux. They are ignored by default — run with:
//!
//!   cargo test -p husker-net --test e2e_bridge -- --ignored --test-threads=1
//!
//! `--test-threads=1` is required because tests share kernel state.
//!
//! Each test cleans up after itself, and uses a unique bridge/TAP/table name so
//! a stray thread can never clobber another test's kernel state.
//!
//! All addresses are RFC 5737 documentation ranges (192.0.2.0/24 = TEST-NET-1,
//! 198.51.100.0/24 = TEST-NET-2, 203.0.113.0/24 = TEST-NET-3), which never route
//! on a real network. There are only three such /24s but four bridge-creating
//! tests, so `full_lifecycle_bridge_tap_nat` reuses TEST-NET-1: safe because the
//! suite is serial and every test deletes its own bridge before creating it, so
//! the two TEST-NET-1 bridges (`huskertest0`, `huskertst8`) never coexist.

use std::net::Ipv4Addr;
use std::process::Command;

fn cmd_output(cmd: &str, args: &[&str]) -> String {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("{cmd} failed to execute: {e}"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    format!("{stdout}{stderr}")
}

fn interface_exists(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", name])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn interface_has_address(name: &str, addr: &str) -> bool {
    let output = cmd_output("ip", &["addr", "show", name]);
    output.contains(addr)
}

fn interface_has_master(tap: &str, bridge: &str) -> bool {
    let output = cmd_output("ip", &["link", "show", tap]);
    output.contains(&format!("master {bridge}"))
}

fn ip_forward_enabled() -> bool {
    let output = cmd_output("sysctl", &["net.ipv4.ip_forward"]);
    output.contains("= 1")
}

fn nft_table_exists(bridge: &str) -> bool {
    let table = husker_net::nft_table_for_bridge(bridge);
    Command::new("nft")
        .args(["list", "table", "ip", &table])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn nft_table_output(bridge: &str) -> String {
    let table = husker_net::nft_table_for_bridge(bridge);
    cmd_output("nft", &["list", "table", "ip", &table])
}

fn nft_egress_table_output(bridge: &str) -> String {
    let table = format!("{}_egress", husker_net::nft_table_for_bridge(bridge));
    cmd_output("nft", &["list", "table", "bridge", &table])
}

// ── Bridge lifecycle ─────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn bridge_create_and_delete() {
    let bridge = "huskertest0";

    // Clean up from any prior failed run
    let _ = husker_net::delete_bridge(bridge).await;

    // Create bridge
    husker_net::create_bridge(bridge, Ipv4Addr::new(192, 0, 2, 1), 24)
        .await
        .expect("create_bridge should succeed");

    // Verify: interface exists, is up, has correct address
    assert!(interface_exists(bridge), "bridge interface should exist");
    assert!(
        interface_has_address(bridge, "192.0.2.1/24"),
        "bridge should have gateway address"
    );

    // Verify bridge type
    let output = cmd_output("ip", &["-d", "link", "show", bridge]);
    assert!(
        output.contains("bridge"),
        "interface should be bridge type: {output}"
    );

    // Delete bridge
    husker_net::delete_bridge(bridge)
        .await
        .expect("delete_bridge should succeed");

    assert!(
        !interface_exists(bridge),
        "bridge should not exist after delete"
    );
}

// ── TAP lifecycle ────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn tap_create_and_delete() {
    let tap = "huskertest1";

    // Clean up from any prior failed run
    let _ = husker_net::delete_tap(tap).await;

    husker_net::create_tap(tap)
        .await
        .expect("create_tap should succeed");

    assert!(interface_exists(tap), "TAP should exist after creation");

    // Verify it's a tap device
    let output = cmd_output("ip", &["-d", "link", "show", tap]);
    assert!(
        output.contains("tun"),
        "should be a TUN/TAP device: {output}"
    );

    husker_net::delete_tap(tap)
        .await
        .expect("delete_tap should succeed");

    assert!(!interface_exists(tap), "TAP should not exist after delete");
}

// ── TAP attached to bridge ───────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn tap_attaches_to_bridge() {
    let bridge = "huskertest2";
    let tap = "huskertest3";

    // Clean up from any prior failed run
    let _ = husker_net::delete_tap(tap).await;
    let _ = husker_net::delete_bridge(bridge).await;

    // Create bridge and TAP
    husker_net::create_bridge(bridge, Ipv4Addr::new(198, 51, 100, 1), 24)
        .await
        .expect("create_bridge");
    husker_net::create_tap(tap).await.expect("create_tap");

    // Attach TAP to bridge
    husker_net::attach_to_bridge(tap, bridge)
        .await
        .expect("attach_to_bridge");

    assert!(
        interface_has_master(tap, bridge),
        "TAP should be a slave of the bridge"
    );

    // Verify deleting TAP removes it from bridge
    husker_net::delete_tap(tap).await.expect("delete_tap");
    assert!(!interface_exists(tap), "TAP should be gone");

    // Bridge should still exist
    assert!(
        interface_exists(bridge),
        "bridge should survive TAP deletion"
    );

    // Cleanup
    husker_net::delete_bridge(bridge)
        .await
        .expect("delete_bridge");
}

// ── Multiple TAPs on one bridge ──────────────────────────────────────

#[tokio::test]
#[ignore]
async fn multiple_taps_on_bridge() {
    let bridge = "huskertest4";
    let taps = ["huskertst5", "huskertst6", "huskertst7"];

    // Cleanup
    for tap in &taps {
        let _ = husker_net::delete_tap(tap).await;
    }
    let _ = husker_net::delete_bridge(bridge).await;

    husker_net::create_bridge(bridge, Ipv4Addr::new(203, 0, 113, 1), 24)
        .await
        .expect("create_bridge");

    for tap in &taps {
        husker_net::create_tap(tap).await.expect("create_tap");
        husker_net::attach_to_bridge(tap, bridge)
            .await
            .expect("attach_to_bridge");
    }

    // All TAPs should be bridge slaves
    for tap in &taps {
        assert!(
            interface_has_master(tap, bridge),
            "{tap} should be slave of {bridge}"
        );
    }

    // Delete middle TAP — others should remain attached
    husker_net::delete_tap(taps[1]).await.expect("delete_tap");
    assert!(interface_has_master(taps[0], bridge));
    assert!(!interface_exists(taps[1]));
    assert!(interface_has_master(taps[2], bridge));

    // Cleanup
    husker_net::delete_tap(taps[0]).await.expect("delete_tap");
    husker_net::delete_tap(taps[2]).await.expect("delete_tap");
    husker_net::delete_bridge(bridge)
        .await
        .expect("delete_bridge");
}

// ── nftables rules ───────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn nftables_init_and_cleanup() {
    let bridge = "huskernft0";

    // Clean up from prior runs
    let _ = husker_net::cleanup_nat(bridge).await;

    // Initialize NAT with test bridge
    husker_net::init_nat(bridge, "192.0.2.0/24", "eth0", None)
        .await
        .expect("init_nat should succeed");

    assert!(
        nft_table_exists(bridge),
        "husker nftables table should exist"
    );
    assert!(ip_forward_enabled(), "init_nat should enable IP forwarding");

    let output = nft_table_output(bridge);
    assert!(
        output.contains("masquerade"),
        "should have masquerade rule: {output}"
    );
    assert!(
        output.contains("husker:bridge-masq"),
        "masquerade rule should have bridge-masq comment"
    );
    assert!(
        output.contains("husker:bridge-fwd-out"),
        "should have forward-out rule"
    );
    assert!(
        output.contains("husker:bridge-fwd-in"),
        "should have forward-in rule"
    );

    // Verify chain types
    assert!(
        output.contains("type nat hook postrouting"),
        "postrouting chain should exist"
    );
    assert!(
        output.contains("type filter hook forward"),
        "forward chain should exist"
    );
    assert!(
        output.contains("type nat hook prerouting"),
        "prerouting chain should exist"
    );

    // Cleanup
    husker_net::cleanup_nat(bridge).await.expect("cleanup_nat");
    assert!(
        !nft_table_exists(bridge),
        "husker table should be gone after cleanup"
    );
}

#[tokio::test]
#[ignore]
async fn per_vm_egress_policy_installs_and_removes_real_nft_rules() {
    let bridge = "huskereg0";
    let tap = "huskereg1";
    let _ = husker_net::cleanup_nat(bridge).await;
    husker_net::init_nat(bridge, "192.0.2.0/24", "eth0", None)
        .await
        .expect("init_nat should create the bridge-family policy table");

    husker_net::apply_egress_policy(
        tap,
        bridge,
        Ipv4Addr::new(192, 0, 2, 1),
        &[Ipv4Addr::new(192, 0, 2, 53)],
        &[husker_net::EgressRule {
            destination: Ipv4Addr::new(203, 0, 113, 8),
            protocol: husker_net::EgressProtocol::Tcp,
            port: 443,
        }],
    )
    .await
    .expect("policy should install atomically");

    let output = nft_egress_table_output(bridge);
    assert!(
        output.contains("hook input"),
        "missing input hook: {output}"
    );
    assert!(
        output.contains("hook forward"),
        "missing forward hook: {output}"
    );
    assert!(
        output.contains("iifname \"huskereg1\""),
        "policy is not TAP-keyed: {output}"
    );
    assert!(
        output.contains("203.0.113.8 tcp dport 443 accept"),
        "missing allow rule: {output}"
    );
    assert!(
        output.contains("husker-egress:huskereg1:default-deny"),
        "missing deny rule: {output}"
    );

    husker_net::remove_egress_policy(tap, bridge)
        .await
        .expect("policy removal should succeed");
    let output = nft_egress_table_output(bridge);
    assert!(
        !output.contains("husker-egress:huskereg1:"),
        "owned rules survived removal: {output}"
    );

    husker_net::cleanup_nat(bridge)
        .await
        .expect("cleanup should remove both nftables tables");
}

// ── Port forwarding ──────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn port_forward_add_and_remove() {
    let bridge = "huskerpf0";
    let _ = husker_net::cleanup_nat(bridge).await;

    // Init NAT first (creates the table and chains)
    husker_net::init_nat(bridge, "192.0.2.0/24", "eth0", None)
        .await
        .expect("init_nat");

    // Add a port forward
    husker_net::add_port_forward(8080, Ipv4Addr::new(192, 0, 2, 2), 80, "huskertst1", bridge)
        .await
        .expect("add_port_forward");

    let output = nft_table_output(bridge);
    assert!(output.contains("dnat"), "should have DNAT rule: {output}");
    assert!(
        output.contains("husker-pf:huskertst1:8080"),
        "DNAT should have comment tag"
    );

    // Add a second port forward
    husker_net::add_port_forward(9090, Ipv4Addr::new(192, 0, 2, 3), 443, "huskertst2", bridge)
        .await
        .expect("add_port_forward 2");

    // Remove first port forward
    husker_net::remove_port_forward(8080, "huskertst1", bridge)
        .await
        .expect("remove_port_forward");

    let output = nft_table_output(bridge);
    assert!(
        !output.contains("husker-pf:huskertst1:8080"),
        "first port forward should be removed"
    );
    assert!(
        output.contains("husker-pf:huskertst2:9090"),
        "second port forward should remain"
    );

    // Remove all port forwards for huskertst2
    husker_net::remove_all_port_forwards("huskertst2", bridge)
        .await
        .expect("remove_all_port_forwards");

    let output = nft_table_output(bridge);
    assert!(
        !output.contains("husker-pf:huskertst2"),
        "all huskertst2 port forwards should be removed"
    );

    // Cleanup
    husker_net::cleanup_nat(bridge).await.expect("cleanup_nat");
}

// ── Full lifecycle simulation ────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn full_lifecycle_bridge_tap_nat() {
    let bridge = "huskertst8";

    // Cleanup from prior runs
    let _ = husker_net::cleanup_nat(bridge).await;
    let _ = husker_net::delete_tap("huskertst9").await;
    let _ = husker_net::delete_tap("hskts10").await;
    let _ = husker_net::delete_bridge(bridge).await;

    // 1. Create allocator
    let alloc = husker_net::IpAllocator::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let gateway = alloc.gateway();
    let prefix_len = alloc.prefix_len();
    assert_eq!(gateway, Ipv4Addr::new(192, 0, 2, 1));

    // 2. Create bridge
    husker_net::create_bridge(bridge, gateway, prefix_len)
        .await
        .expect("create_bridge");
    assert!(interface_exists(bridge));
    assert!(interface_has_address(bridge, "192.0.2.1/24"));

    // 3. Init NAT
    husker_net::init_nat(bridge, "192.0.2.0/24", "eth0", None)
        .await
        .expect("init_nat");

    // 4. Simulate creating VM 1
    let vm1_ip = alloc.allocate().expect("allocate vm1");
    assert_eq!(vm1_ip, Ipv4Addr::new(192, 0, 2, 2));

    let tap1 = "huskertst9";
    husker_net::create_tap(tap1).await.expect("create_tap vm1");
    husker_net::attach_to_bridge(tap1, bridge)
        .await
        .expect("attach vm1");

    // Verify kernel args would be correct
    let netmask = husker_net::prefix_len_to_netmask(prefix_len);
    let kernel_ip = format!("ip={vm1_ip}::{gateway}:{netmask}::eth0:off");
    assert_eq!(kernel_ip, "ip=192.0.2.2::192.0.2.1:255.255.255.0::eth0:off");

    // 5. Simulate creating VM 2
    let vm2_ip = alloc.allocate().expect("allocate vm2");
    assert_eq!(vm2_ip, Ipv4Addr::new(192, 0, 2, 3));

    let tap2 = "hskts10";
    husker_net::create_tap(tap2).await.expect("create_tap vm2");
    husker_net::attach_to_bridge(tap2, bridge)
        .await
        .expect("attach vm2");

    // Both TAPs attached
    assert!(interface_has_master(tap1, bridge));
    assert!(interface_has_master(tap2, bridge));

    // 6. Add port forwards
    husker_net::add_port_forward(2222, vm1_ip, 22, tap1, bridge)
        .await
        .expect("add pf vm1");
    husker_net::add_port_forward(2223, vm2_ip, 22, tap2, bridge)
        .await
        .expect("add pf vm2");

    let nft_out = nft_table_output(bridge);
    assert!(nft_out.contains("husker-pf:huskertst9:2222"));
    assert!(nft_out.contains("husker-pf:hskts10:2223"));

    // 7. Destroy VM 1
    husker_net::remove_all_port_forwards(tap1, bridge)
        .await
        .expect("remove pf vm1");
    husker_net::delete_tap(tap1).await.expect("delete tap vm1");
    alloc.release(vm1_ip).expect("release vm1 ip");

    // VM 2 still intact
    assert!(interface_has_master(tap2, bridge));
    let nft_out = nft_table_output(bridge);
    assert!(!nft_out.contains("husker-pf:huskertst9:2222"));
    assert!(nft_out.contains("husker-pf:hskts10:2223"));

    // 8. Allocate new VM — should reuse VM 1's IP
    let vm3_ip = alloc.allocate().expect("allocate vm3");
    assert_eq!(vm3_ip, vm1_ip, "should reuse released IP");

    // 9. Destroy VM 2 and cleanup
    husker_net::remove_all_port_forwards(tap2, bridge)
        .await
        .expect("remove pf vm2");
    husker_net::delete_tap(tap2).await.expect("delete tap vm2");
    alloc.release(vm2_ip).expect("release vm2 ip");
    alloc.release(vm3_ip).expect("release vm3 ip");

    // 10. Daemon shutdown
    husker_net::cleanup_nat(bridge).await.expect("cleanup_nat");
    husker_net::delete_bridge(bridge)
        .await
        .expect("delete_bridge");

    // Everything should be clean
    assert!(!interface_exists(bridge));
    assert!(!interface_exists(tap1));
    assert!(!interface_exists(tap2));
    assert!(!nft_table_exists(bridge));
}

// ── init_nat idempotency ─────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn init_nat_is_idempotent() {
    let bridge = "huskeridem0";
    let _ = husker_net::cleanup_nat(bridge).await;

    // First init
    husker_net::init_nat(bridge, "192.0.2.0/24", "eth0", None)
        .await
        .expect("first init_nat");

    // Second init (should not error — deletes and recreates)
    husker_net::init_nat(bridge, "192.0.2.0/24", "eth0", None)
        .await
        .expect("second init_nat should also succeed");

    // Should still have exactly the right rules (no duplicates)
    let output = nft_table_output(bridge);
    let masq_count = output.matches("husker:bridge-masq").count();
    assert_eq!(
        masq_count, 1,
        "should have exactly one masquerade rule, got {masq_count}"
    );

    husker_net::cleanup_nat(bridge).await.expect("cleanup");
}

// ── two-daemon coexistence ───────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn two_bridges_do_not_clobber_each_others_nat() {
    let bridge_a = "huskercoex0";
    let bridge_b = "huskercoex1";
    let _ = husker_net::cleanup_nat(bridge_a).await;
    let _ = husker_net::cleanup_nat(bridge_b).await;

    husker_net::init_nat(bridge_a, "198.51.100.0/24", "eth0", None)
        .await
        .expect("init_nat A");
    husker_net::init_nat(bridge_b, "203.0.113.0/24", "eth0", None)
        .await
        .expect("init_nat B");

    husker_net::add_port_forward(
        18080,
        Ipv4Addr::new(198, 51, 100, 2),
        80,
        "huskercoexa",
        bridge_a,
    )
    .await
    .expect("pf A");
    husker_net::add_port_forward(
        18081,
        Ipv4Addr::new(203, 0, 113, 2),
        80,
        "huskercoexb",
        bridge_b,
    )
    .await
    .expect("pf B");

    assert!(nft_table_exists(bridge_a), "table A missing");
    assert!(nft_table_exists(bridge_b), "table B missing");
    assert!(
        nft_table_output(bridge_a).contains("18080"),
        "A lost its DNAT"
    );
    assert!(
        nft_table_output(bridge_b).contains("18081"),
        "B lost its DNAT"
    );

    husker_net::cleanup_nat(bridge_a).await.expect("cleanup A");
    assert!(!nft_table_exists(bridge_a), "table A should be gone");
    assert!(nft_table_exists(bridge_b), "table B must survive A cleanup");
    assert!(
        nft_table_output(bridge_b).contains("18081"),
        "B's DNAT must survive"
    );

    husker_net::cleanup_nat(bridge_b).await.expect("cleanup B");
}

// ── guest isolation ──────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn isolation_installs_deny_carveout_and_host_guard_in_order() {
    let bridge = "huskeriso0";
    let subnet = "192.0.2.0/24";
    let _ = husker_net::cleanup_nat(bridge).await;

    // A private resolver (inside the deny set) must earn a carve-out; a public
    // one must not.
    let policy = husker_net::IsolationPolicy {
        resolvers: vec!["10.0.0.53".parse().unwrap(), "1.1.1.1".parse().unwrap()],
    };
    husker_net::init_nat(bridge, subnet, "eth0", Some(&policy))
        .await
        .expect("init_nat with isolation");

    let output = nft_table_output(bridge);

    // The isolation rules are present.
    assert!(
        output.contains("husker:isolation-deny-private"),
        "deny-private rule missing: {output}"
    );
    assert!(
        output.contains("husker:isolation-dns") && output.contains("10.0.0.53"),
        "private resolver DNS carve-out missing: {output}"
    );
    assert!(
        !output.contains("1.1.1.1"),
        "public resolver must not get a carve-out: {output}"
    );
    assert!(
        output.contains("husker:isolation-host-guard"),
        "host-guard input rule missing: {output}"
    );
    assert!(
        output.contains("type filter hook input"),
        "isolation must add an input chain: {output}"
    );

    // Ordering within the forward chain: the DNS carve-out and the deny must
    // both appear before the broad bridge accept, or they are dead rules.
    let dns_at = output.find("husker:isolation-dns").expect("dns rule");
    let deny_at = output
        .find("husker:isolation-deny-private")
        .expect("deny rule");
    let accept_at = output.find("husker:bridge-fwd-out").expect("accept rule");
    assert!(
        dns_at < deny_at && deny_at < accept_at,
        "order must be dns < deny < accept; got dns={dns_at} deny={deny_at} accept={accept_at}\n{output}"
    );

    // cleanup_nat removes the whole table, isolation rules included.
    husker_net::cleanup_nat(bridge).await.expect("cleanup");
    assert!(
        !nft_table_exists(bridge),
        "table should be gone after cleanup"
    );
}

/// Isolation off (the upstream default) must not add any deny/guard rules.
#[tokio::test]
#[ignore]
async fn no_isolation_leaves_forward_open() {
    let bridge = "huskeriso1";
    let _ = husker_net::cleanup_nat(bridge).await;

    husker_net::init_nat(bridge, "192.0.2.0/24", "eth0", None)
        .await
        .expect("init_nat without isolation");

    let output = nft_table_output(bridge);
    assert!(
        !output.contains("isolation"),
        "no isolation rules expected: {output}"
    );
    assert!(
        !output.contains("type filter hook input"),
        "no input chain without isolation: {output}"
    );

    husker_net::cleanup_nat(bridge).await.expect("cleanup");
}
