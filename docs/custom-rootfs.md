# Custom Guest Rootfs Requirements

This document describes the non-obvious contract a custom rootfs image must satisfy to work with husker. The requirements below apply to **Linux (Firecracker)** guests. macOS (Apple VZ) guests use NAT and the VZ-supplied init path; most of this doc does not apply there.

The reference implementations are `guest/build-rootfs.sh` (Alpine/BusyBox) and `guest/build-k3s-rootfs.sh` (Ubuntu 22.04/systemd via debootstrap). Read those alongside this document.

---

## Checklist

- [ ] vsock modules loaded before the agent starts
- [ ] virtio-net modules loaded before networking starts
- [ ] `husker-net.sh` (or equivalent) configures eth0 from the `ip=` kernel cmdline token
- [ ] systemd-resolved disabled/masked (does not clobber injected `/etc/resolv.conf`)
- [ ] husker-agent installed at `/usr/local/bin/husker-agent` and started after vsock modules load
- [ ] Data directory hosted on XFS or btrfs for copy-on-write clones

---

## 1. Kernel modules

The default husker kernel is a from-source build with all virtio and vsock drivers compiled in (not loadable modules). No `insmod` steps are needed when booting the default kernel: vsock, virtio-net, virtio-blk, and virtio-balloon are all available at boot without an initramfs.

The checklist items above (`vsock modules loaded`, `virtio-net modules loaded`) still apply if you boot a **legacy modular kernel** such as Alpine's `linux-virt` package - see the legacy path below.

### Legacy path: modular kernel (e.g. Alpine linux-virt)

If you use a modular kernel, vsock and virtio-net are loadable modules. The modules live in the initramfs at `lib/modules/<kver>/*.ko`. After `switch_root`, the initramfs init script copies them flat into `/lib/modules/` on the rootfs. The rootfs init must load them before anything that depends on them.

**Required load order:**

```
# vsock stack - must be loaded before the guest agent starts
insmod /lib/modules/vsock.ko
insmod /lib/modules/vmw_vsock_virtio_transport_common.ko
insmod /lib/modules/vmw_vsock_virtio_transport.ko

# network stack - must be loaded before eth0 comes up
insmod /lib/modules/af_packet.ko       # raw sockets; required for DHCP fallback
insmod /lib/modules/failover.ko
insmod /lib/modules/net_failover.ko
insmod /lib/modules/virtio_net.ko
```

Order within each stack matters (dependency chain). If vsock modules are absent or loaded after the agent binary starts, the agent cannot bind `AF_VSOCK` port 52 and `husker exec` will fail.

**Extracting modules from the initramfs:**

```sh
# Decompress and extract just the modules tree (x86_64/Firecracker name;
# the aarch64/macOS image is initramfs-virt.gz)
zcat /var/lib/husker/kernels/initramfs-x86_64-virt.gz | cpio -idmu 'lib/modules/*'
# Results in lib/modules/<kver>/*.ko in the current directory
```

**Alpine baseline** (`guest/inittab`): the BusyBox `::sysinit:` lines load all modules directly via `insmod /lib/modules/<name>.ko` before invoking `husker-net.sh` and the agent.

**systemd rootfs** (e.g. Ubuntu): create an early oneshot service that runs `Before=network-pre.target` and before the husker-agent service, with no `After=` dependencies that require the network.

Example `husker-modules.service`:
```ini
[Unit]
Description=Load husker guest kernel modules
DefaultDependencies=no
Before=network-pre.target
Before=husker-agent.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/husker-load-modules.sh

[Install]
WantedBy=basic.target
```

Where `husker-load-modules.sh` contains the `insmod` lines above.

---

## 2. Networking

husker does not run a DHCP server on the bridge. On Linux (Firecracker), it passes a static IP assignment on the kernel cmdline:

```
ip=<client>::<gateway>:<netmask>::eth0:off
```

Example: `ip=172.20.0.2::172.20.0.1:255.255.255.0::eth0:off`

Fields (colon-separated): `client:server:gateway:netmask:host:iface:autoconf`. The `server` and `host` fields are empty; `autoconf` is `off`.

The kernel does NOT apply this automatically (the kernel's built-in `ip=` autoconfiguration is not used by husker's kernel build). The rootfs init must parse `/proc/cmdline` and configure the interface itself.

The Alpine baseline ships `guest/husker-net.sh` (`/usr/local/sbin/husker-net.sh` inside the rootfs) which does this: reads the `ip=` token, converts the dotted-decimal netmask to a prefix length, and calls `ip addr add` / `ip route add`. It falls back to `udhcpc` when no `ip=` token is found.

**systemd rootfs:** use a oneshot service that calls `husker-net.sh` (or equivalent) and runs `Before=network.target After=husker-modules.service`. Alternatively, write a `systemd-networkd` config with `[Match] Name=eth0` and `[Network] DHCP=no`, parsing the cmdline address in a drop-in `ExecStartPre` script.

**resolv.conf:** husker injects `/etc/resolv.conf` into each VM's rootfs clone before boot (`inject_resolv_conf` in `husker-core`, Linux-only). It also symlinks `/etc/systemd/system/systemd-resolved.service` to `/dev/null` to prevent it from recreating a stub-resolv.conf symlink on first boot. DNS is handled; you do not need to configure it. Do not let a post-boot service overwrite `/etc/resolv.conf`.

For Ubuntu/systemd rootfs, explicitly disable and mask systemd-resolved during image build:
```sh
systemctl disable systemd-resolved.service
systemctl mask systemd-resolved.service
```
See `guest/build-k3s-rootfs.sh` for the exact commands.

---

## 3. Guest agent

The husker guest agent is a musl-statically-linked binary that listens on vsock port **52** (`AGENT_VSOCK_PORT` in `crates/husker-agent-proto/src/lib.rs`). It must be running for `husker exec`, `husker shell`, and userdata execution to work.

**Build:** `make build-agent` (x86_64 musl) or `make build-agent-aarch64` (aarch64 musl). The resulting binary at `target/<arch>-unknown-linux-musl/agent/husker-agent` is fully static and has no glibc dependency.

**Install:** copy to `/usr/local/bin/husker-agent` inside the rootfs (mode `0755`).

**Start:** the agent must be started **after** the vsock modules are loaded and must be restarted if it exits. On Alpine/BusyBox, the `::respawn:` directive in inittab handles this. On systemd:

```ini
[Unit]
Description=Husker Guest Agent
After=husker-modules.service
ConditionVirtualization=vm

[Service]
Type=simple
ExecStart=/usr/local/bin/husker-agent
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
```

The agent crash-loops if vsock modules are not loaded when it starts, which prevents `husker exec` from ever connecting. Load order is the most common failure mode when porting a new rootfs.

**Protocol:** length-prefixed JSON (4-byte big-endian length + JSON body), with binary payloads base64-encoded in the JSON. This is an internal protocol between husker and the agent; you do not need to implement it.

---

## 4. Host data directory filesystem

husker clones each VM's rootfs via reflink (copy-on-write) when the underlying filesystem supports it. It uses `reflink_or_copy` from the `reflink-copy` crate: on XFS (default, reflinks enabled) or btrfs this is instant regardless of image size; on ext4 or any other non-reflink filesystem it falls back to a full byte copy.

When the fallback occurs, husker logs a **one-time warning** (at most once per daemon process):

> "rootfs clone fell back to a full byte copy: the data directory's filesystem does not support reflink (copy-on-write), so every microVM pays a full copy of the rootfs image. Host the data directory on XFS or btrfs for instant clones."

**Recommendation:** host `/var/lib/husker` (the default data dir; configurable via `HUSKER_DATA_DIR` or `data_dir` in `config.toml`) on XFS or btrfs. XFS has reflinks enabled by default since RHEL 8 / `mkfs.xfs` defaults. If you see the warning in `husker daemon` output, the data dir is on a non-reflink filesystem and VM creation is slow.

---

## Platform note: macOS (Apple Virtualization.framework)

On macOS, husker uses `VZNATNetworkDeviceAttachment` for networking - the guest gets DHCP from VZ directly, no TAP device or bridge. The `ip=` cmdline token is not set. The kernel args are `console=hvc0 root=/dev/vda rw init=/sbin/init`. The module loading and static IP requirements above do not apply to macOS/VZ guests.

For macOS/VZ, an initramfs is loaded automatically from `~/.local/share/husker/kernels/initramfs-virt.gz` when present. With the default husker kernel (all drivers built in) no initramfs is required. The initramfs is only needed when booting a legacy modular kernel such as Alpine `linux-virt`.
