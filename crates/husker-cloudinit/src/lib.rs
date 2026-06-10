//! cloud-init NoCloud seed generation for husker cloud-image VMs.
//!
//! Produces a vfat image labeled `CIDATA` containing `meta-data`, `user-data`
//! (`#cloud-config` that installs and starts the embedded husker guest agent),
//! and a static `network-config`. cloud-init's NoCloud datasource reads it from
//! the attached disk on first boot.

use std::io::Write;
use std::net::Ipv4Addr;

#[derive(Debug, thiserror::Error)]
pub enum CloudInitError {
    #[error("seed image IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("fatfs error: {0}")]
    Fat(String),
    #[error("guest agent binary is empty (the daemon was built without an embedded agent)")]
    EmptyAgent,
}

/// Static guest network, rendered into cloud-init network-config v2.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
    pub dns: Vec<String>,
}

/// Everything needed to render a NoCloud seed. `agent` is the guest-agent binary
/// (x86_64-musl), delivered base64-encoded inside user-data.
#[derive(Debug)]
pub struct SeedSpec<'a> {
    pub agent: &'a [u8],
    pub hostname: String,
    pub instance_id: String,
    /// SSH public keys to authorize for the default user. Empty omits the block.
    pub ssh_authorized_keys: Vec<String>,
    pub network: NetworkConfig,
}

/// Build a NoCloud `cidata` vfat image (bytes) from `spec`.
pub fn build_seed(spec: &SeedSpec) -> Result<Vec<u8>, CloudInitError> {
    if spec.agent.is_empty() {
        return Err(CloudInitError::EmptyAgent);
    }
    let meta_data = format!(
        "instance-id: {}\nlocal-hostname: {}\n",
        spec.instance_id, spec.hostname
    );
    let user_data = render_user_data(spec);
    let network_config = render_network_config(&spec.network);

    let payload = meta_data.len() + user_data.len() + network_config.len();
    let size = ((payload + 1024 * 1024) as u64)
        .next_multiple_of(512)
        .max(1024 * 1024);
    let mut buf = vec![0u8; size as usize];

    {
        let cursor = std::io::Cursor::new(&mut buf[..]);
        fatfs::format_volume(
            cursor,
            fatfs::FormatVolumeOptions::new().volume_label(*b"CIDATA     "),
        )
        .map_err(|e| CloudInitError::Fat(e.to_string()))?;
    }
    {
        let cursor = std::io::Cursor::new(&mut buf[..]);
        let fs = fatfs::FileSystem::new(cursor, fatfs::FsOptions::new())
            .map_err(|e| CloudInitError::Fat(e.to_string()))?;
        let root = fs.root_dir();
        for (name, data) in [
            ("meta-data", meta_data.as_bytes()),
            ("user-data", user_data.as_bytes()),
            ("network-config", network_config.as_bytes()),
        ] {
            let mut f = root
                .create_file(name)
                .map_err(|e| CloudInitError::Fat(e.to_string()))?;
            f.truncate()
                .map_err(|e| CloudInitError::Fat(e.to_string()))?;
            f.write_all(data)?;
            f.flush()?;
        }
    }
    Ok(buf)
}

fn render_user_data(spec: &SeedSpec) -> String {
    let agent_b64 = husker_agent_proto::base64_encode(spec.agent);
    let mut s = String::from("#cloud-config\n");
    s.push_str("write_files:\n");
    s.push_str("  - path: /usr/local/bin/husker-agent\n");
    s.push_str("    encoding: b64\n");
    s.push_str("    permissions: '0755'\n");
    s.push_str("    content: ");
    s.push_str(&agent_b64);
    s.push('\n');
    s.push_str("  - path: /etc/systemd/system/husker-agent.service\n");
    s.push_str("    permissions: '0644'\n");
    s.push_str("    content: |\n");
    for line in [
        "[Unit]",
        "Description=husker guest agent",
        "After=network.target",
        "[Service]",
        "ExecStart=/usr/local/bin/husker-agent",
        "Restart=always",
        "RestartSec=1",
        "[Install]",
        "WantedBy=multi-user.target",
    ] {
        s.push_str("      ");
        s.push_str(line);
        s.push('\n');
    }
    if !spec.ssh_authorized_keys.is_empty() {
        s.push_str("ssh_authorized_keys:\n");
        for key in &spec.ssh_authorized_keys {
            s.push_str("  - ");
            s.push_str(key);
            s.push('\n');
        }
    }
    s.push_str("runcmd:\n");
    s.push_str("  - modprobe vmw_vsock_virtio_transport || true\n");
    s.push_str("  - systemctl daemon-reload\n");
    s.push_str("  - systemctl enable --now husker-agent.service\n");
    s
}

fn render_network_config(net: &NetworkConfig) -> String {
    let mut s = String::from("version: 2\n");
    s.push_str("ethernets:\n");
    s.push_str("  primary:\n");
    s.push_str("    match:\n");
    s.push_str("      driver: virtio_net\n");
    s.push_str(&format!("    addresses: [{}/{}]\n", net.ip, net.prefix_len));
    s.push_str(&format!(
        "    routes:\n      - to: default\n        via: {}\n",
        net.gateway
    ));
    if !net.dns.is_empty() {
        s.push_str("    nameservers:\n      addresses: [");
        s.push_str(&net.dns.join(", "));
        s.push_str("]\n");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn sample_spec(agent: &[u8]) -> SeedSpec<'_> {
        SeedSpec {
            agent,
            hostname: "cloudvm".into(),
            instance_id: "cloudvm".into(),
            ssh_authorized_keys: vec![],
            network: NetworkConfig {
                ip: "192.0.2.2".parse().unwrap(),
                prefix_len: 24,
                gateway: "192.0.2.1".parse().unwrap(),
                dns: vec!["192.0.2.1".into()],
            },
        }
    }

    fn read_seed_file(image: &[u8], name: &str) -> Vec<u8> {
        let cursor = std::io::Cursor::new(image.to_vec());
        let fs = fatfs::FileSystem::new(cursor, fatfs::FsOptions::new()).unwrap();
        let mut f = fs.root_dir().open_file(name).unwrap();
        let mut out = Vec::new();
        f.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn seed_is_a_cidata_volume_with_the_three_files() {
        let image = build_seed(&sample_spec(b"AGENTBYTES")).unwrap();
        let cursor = std::io::Cursor::new(image.clone());
        let fs = fatfs::FileSystem::new(cursor, fatfs::FsOptions::new()).unwrap();
        let label = fs.volume_label();
        assert!(label.eq_ignore_ascii_case("cidata"), "label was {label:?}");
        for name in ["meta-data", "user-data", "network-config"] {
            assert!(fs.root_dir().open_file(name).is_ok(), "missing {name}");
        }
    }

    #[test]
    fn meta_data_has_instance_id_and_hostname() {
        let image = build_seed(&sample_spec(b"x")).unwrap();
        let md = String::from_utf8(read_seed_file(&image, "meta-data")).unwrap();
        assert!(md.contains("instance-id: cloudvm"), "{md}");
        assert!(md.contains("local-hostname: cloudvm"), "{md}");
    }

    #[test]
    fn user_data_embeds_agent_base64_and_starts_it() {
        let agent = b"\x7fELF-not-really-but-bytes";
        let image = build_seed(&sample_spec(agent)).unwrap();
        let ud = String::from_utf8(read_seed_file(&image, "user-data")).unwrap();
        assert!(
            ud.starts_with("#cloud-config"),
            "must be a cloud-config doc"
        );
        let b64 = husker_agent_proto::base64_encode(agent);
        assert!(ud.contains(&b64), "agent base64 not embedded");
        assert!(
            ud.contains("/usr/local/bin/husker-agent"),
            "agent path missing"
        );
        assert!(ud.contains("husker-agent.service"), "systemd unit missing");
        assert!(
            ud.contains("systemctl enable --now husker-agent.service"),
            "agent not enabled"
        );
    }

    #[test]
    fn network_config_has_static_ip_gateway_dns() {
        let image = build_seed(&sample_spec(b"x")).unwrap();
        let nc = String::from_utf8(read_seed_file(&image, "network-config")).unwrap();
        assert!(nc.contains("version: 2"), "{nc}");
        assert!(nc.contains("192.0.2.2/24"), "static address missing: {nc}");
        assert!(nc.contains("192.0.2.1"), "gateway/dns missing: {nc}");
    }

    #[test]
    fn ssh_keys_included_only_when_present() {
        let none = build_seed(&sample_spec(b"x")).unwrap();
        let ud = String::from_utf8(read_seed_file(&none, "user-data")).unwrap();
        assert!(
            !ud.contains("ssh_authorized_keys"),
            "should omit ssh block when empty"
        );
        let mut spec = sample_spec(b"x");
        spec.ssh_authorized_keys = vec!["ssh-ed25519 AAAA... user@host".into()];
        let img = build_seed(&spec).unwrap();
        let ud2 = String::from_utf8(read_seed_file(&img, "user-data")).unwrap();
        assert!(ud2.contains("ssh_authorized_keys"), "ssh block missing");
        assert!(ud2.contains("ssh-ed25519 AAAA"), "key missing");
    }

    #[test]
    fn build_seed_rejects_empty_agent() {
        let err = build_seed(&sample_spec(b"")).unwrap_err();
        assert!(matches!(err, CloudInitError::EmptyAgent), "got {err:?}");
    }
}
