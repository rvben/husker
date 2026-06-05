//! E2E tests for bridge networking on real Linux.
//!
//! These tests create actual kernel resources (bridges, TAPs, nftables rules)
//! and must be run as root on Linux. They are ignored by default — run with:
//!
//!   cargo test -p husker-net --test e2e_bridge -- --ignored --test-threads=1
//!
//! `--test-threads=1` is required because tests share the global `husker`
//! nftables table.
//!
//! Each test cleans up after itself. Unique interface names per test prevent
//! bridge/TAP interference.

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

fn nft_table_exists() -> bool {
    Command::new("nft")
        .args(["list", "table", "ip", "husker"])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn nft_table_output() -> String {
    cmd_output("nft", &["list", "table", "ip", "husker"])
}

// ── Bridge lifecycle ─────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn bridge_create_and_delete() {
    let bridge = "huskertest0";

    // Clean up from any prior failed run
    let _ = husker_net::delete_bridge(bridge).await;

    // Create bridge
    husker_net::create_bridge(bridge, Ipv4Addr::new(10, 99, 0, 1), 24)
        .await
        .expect("create_bridge should succeed");

    // Verify: interface exists, is up, has correct address
    assert!(interface_exists(bridge), "bridge interface should exist");
    assert!(
        interface_has_address(bridge, "10.99.0.1/24"),
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
    husker_net::create_bridge(bridge, Ipv4Addr::new(10, 99, 1, 1), 24)
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

    husker_net::create_bridge(bridge, Ipv4Addr::new(10, 99, 2, 1), 24)
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
    // Clean up from prior runs
    let _ = husker_net::cleanup_nat().await;

    // Initialize NAT with test bridge
    husker_net::init_nat("huskertest0", "10.99.0.0/24", "eth0")
        .await
        .expect("init_nat should succeed");

    assert!(nft_table_exists(), "husker nftables table should exist");
    assert!(ip_forward_enabled(), "init_nat should enable IP forwarding");

    let output = nft_table_output();
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
    husker_net::cleanup_nat().await.expect("cleanup_nat");
    assert!(
        !nft_table_exists(),
        "husker table should be gone after cleanup"
    );
}

// ── Port forwarding ──────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn port_forward_add_and_remove() {
    let _ = husker_net::cleanup_nat().await;

    // Init NAT first (creates the table and chains)
    husker_net::init_nat("huskertest0", "10.99.0.0/24", "eth0")
        .await
        .expect("init_nat");

    // Add a port forward
    husker_net::add_port_forward(8080, Ipv4Addr::new(10, 99, 0, 2), 80, "huskertst1")
        .await
        .expect("add_port_forward");

    let output = nft_table_output();
    assert!(output.contains("dnat"), "should have DNAT rule: {output}");
    assert!(
        output.contains("husker-pf:huskertst1:8080"),
        "DNAT should have comment tag"
    );

    // Add a second port forward
    husker_net::add_port_forward(9090, Ipv4Addr::new(10, 99, 0, 3), 443, "huskertst2")
        .await
        .expect("add_port_forward 2");

    // Remove first port forward
    husker_net::remove_port_forward(8080, "huskertst1")
        .await
        .expect("remove_port_forward");

    let output = nft_table_output();
    assert!(
        !output.contains("husker-pf:huskertst1:8080"),
        "first port forward should be removed"
    );
    assert!(
        output.contains("husker-pf:huskertst2:9090"),
        "second port forward should remain"
    );

    // Remove all port forwards for huskertst2
    husker_net::remove_all_port_forwards("huskertst2")
        .await
        .expect("remove_all_port_forwards");

    let output = nft_table_output();
    assert!(
        !output.contains("husker-pf:huskertst2"),
        "all huskertst2 port forwards should be removed"
    );

    // Cleanup
    husker_net::cleanup_nat().await.expect("cleanup_nat");
}

// ── Full lifecycle simulation ────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn full_lifecycle_bridge_tap_nat() {
    let bridge = "huskertst8";

    // Cleanup from prior runs
    let _ = husker_net::cleanup_nat().await;
    let _ = husker_net::delete_tap("huskertst9").await;
    let _ = husker_net::delete_tap("hskts10").await;
    let _ = husker_net::delete_bridge(bridge).await;

    // 1. Create allocator
    let alloc = husker_net::IpAllocator::new(Ipv4Addr::new(10, 99, 3, 0), 24);
    let gateway = alloc.gateway();
    let prefix_len = alloc.prefix_len();
    assert_eq!(gateway, Ipv4Addr::new(10, 99, 3, 1));

    // 2. Create bridge
    husker_net::create_bridge(bridge, gateway, prefix_len)
        .await
        .expect("create_bridge");
    assert!(interface_exists(bridge));
    assert!(interface_has_address(bridge, "10.99.3.1/24"));

    // 3. Init NAT
    husker_net::init_nat(bridge, "10.99.3.0/24", "eth0")
        .await
        .expect("init_nat");

    // 4. Simulate creating VM 1
    let vm1_ip = alloc.allocate().expect("allocate vm1");
    assert_eq!(vm1_ip, Ipv4Addr::new(10, 99, 3, 2));

    let tap1 = "huskertst9";
    husker_net::create_tap(tap1).await.expect("create_tap vm1");
    husker_net::attach_to_bridge(tap1, bridge)
        .await
        .expect("attach vm1");

    // Verify kernel args would be correct
    let netmask = husker_net::prefix_len_to_netmask(prefix_len);
    let kernel_ip = format!("ip={vm1_ip}::{gateway}:{netmask}::eth0:off");
    assert_eq!(kernel_ip, "ip=10.99.3.2::10.99.3.1:255.255.255.0::eth0:off");

    // 5. Simulate creating VM 2
    let vm2_ip = alloc.allocate().expect("allocate vm2");
    assert_eq!(vm2_ip, Ipv4Addr::new(10, 99, 3, 3));

    let tap2 = "hskts10";
    husker_net::create_tap(tap2).await.expect("create_tap vm2");
    husker_net::attach_to_bridge(tap2, bridge)
        .await
        .expect("attach vm2");

    // Both TAPs attached
    assert!(interface_has_master(tap1, bridge));
    assert!(interface_has_master(tap2, bridge));

    // 6. Add port forwards
    husker_net::add_port_forward(2222, vm1_ip, 22, tap1)
        .await
        .expect("add pf vm1");
    husker_net::add_port_forward(2223, vm2_ip, 22, tap2)
        .await
        .expect("add pf vm2");

    let nft_out = nft_table_output();
    assert!(nft_out.contains("husker-pf:huskertst9:2222"));
    assert!(nft_out.contains("husker-pf:hskts10:2223"));

    // 7. Destroy VM 1
    husker_net::remove_all_port_forwards(tap1)
        .await
        .expect("remove pf vm1");
    husker_net::delete_tap(tap1).await.expect("delete tap vm1");
    alloc.release(vm1_ip).expect("release vm1 ip");

    // VM 2 still intact
    assert!(interface_has_master(tap2, bridge));
    let nft_out = nft_table_output();
    assert!(!nft_out.contains("husker-pf:huskertst9:2222"));
    assert!(nft_out.contains("husker-pf:hskts10:2223"));

    // 8. Allocate new VM — should reuse VM 1's IP
    let vm3_ip = alloc.allocate().expect("allocate vm3");
    assert_eq!(vm3_ip, vm1_ip, "should reuse released IP");

    // 9. Destroy VM 2 and cleanup
    husker_net::remove_all_port_forwards(tap2)
        .await
        .expect("remove pf vm2");
    husker_net::delete_tap(tap2).await.expect("delete tap vm2");
    alloc.release(vm2_ip).expect("release vm2 ip");
    alloc.release(vm3_ip).expect("release vm3 ip");

    // 10. Daemon shutdown
    husker_net::cleanup_nat().await.expect("cleanup_nat");
    husker_net::delete_bridge(bridge)
        .await
        .expect("delete_bridge");

    // Everything should be clean
    assert!(!interface_exists(bridge));
    assert!(!interface_exists(tap1));
    assert!(!interface_exists(tap2));
    assert!(!nft_table_exists());
}

// ── init_nat idempotency ─────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn init_nat_is_idempotent() {
    let _ = husker_net::cleanup_nat().await;

    // First init
    husker_net::init_nat("huskertest0", "10.99.0.0/24", "eth0")
        .await
        .expect("first init_nat");

    // Second init (should not error — deletes and recreates)
    husker_net::init_nat("huskertest0", "10.99.0.0/24", "eth0")
        .await
        .expect("second init_nat should also succeed");

    // Should still have exactly the right rules (no duplicates)
    let output = nft_table_output();
    let masq_count = output.matches("husker:bridge-masq").count();
    assert_eq!(
        masq_count, 1,
        "should have exactly one masquerade rule, got {masq_count}"
    );

    husker_net::cleanup_nat().await.expect("cleanup");
}
