# macOS guests

On an Apple Silicon Mac, husker runs macOS itself as a guest through Apple
Virtualization.framework (the same mechanism behind `VZMacOSInstaller` and
`VZMacOSBootLoader`). A macOS guest is a full VM with its own disk, auxiliary
storage, hardware model and machine identifier, and husker reaches it over
vsock with the same guest agent it uses for Linux guests.

Requirements:

- An Apple Silicon Mac. Intel Macs cannot run macOS guests.
- A husker binary signed with the `com.apple.security.virtualization`
  entitlement. `make install`, the Homebrew formula and the PyPI wheel are
  signed. A plain `cargo build` is not, so re-sign it with
  `codesign --entitlements husker.entitlements -s - --force <binary>`.
- Disk space: the restore image (IPSW) is about 25 GB and is only needed
  during the install. An installed image takes as much as the guest has
  written, about 26 GB for a fresh macOS 27 install (the default 64G disk is sparse).
  Each VM's disk and auxiliary storage are APFS clones, so they cost nothing
  until the guest writes to them. Downloading to another disk with
  `--download-dir` keeps the IPSW off the internal disk entirely.

## 1. Install an image

```bash
husker macos install sonoma
```

With no `--ipsw`, husker asks Virtualization.framework for the latest macOS
release this Mac supports, downloads it to
`<data_dir>/macos/.downloads/<build>.ipsw` and runs Apple's installer. The
download is refused up front when the disk does not have room for it. A
restore image the install downloads is deleted once the install succeeds;
pass `--keep-ipsw` to keep it for further installs. One already in the
download directory is reused and left in place. Pass `--ipsw <file>` to install
from a restore image you already have; husker reads it in place and never
deletes it. Other options:

| Flag | Default | Meaning |
|------|---------|---------|
| `--download-dir` | `<data_dir>/macos/.downloads` | Where to download the restore image, e.g. an external disk |
| `--keep-ipsw` | off | Keep the downloaded restore image after a successful install |
| `--disk-size` | `64G` | Size of the guest's (sparse) system disk |
| `--cpus` | 4 | vCPUs for the installer VM (the default is raised to the image's minimum; a lower explicit value is rejected) |
| `--memory` | 8192 | MiB of memory for the installer VM (the default is raised to the image's minimum; a lower explicit value is rejected) |

The image is a bundle directory under `<data_dir>/macos/<name>/` holding
`disk.img`, `aux.img`, `hardware-model.bin`, `machine-identifier.bin` and a
`bundle.json` manifest. The install runs in a hidden staging directory, so an
interrupted install leaves no half-built image under the name. A staging
directory left by a killed install is cleared by the next install of the same
name.
`husker macos list` shows the installed images.

## 2. Provision the guest agent

```bash
sudo husker macos provision ~/.local/share/husker/macos/sonoma
```

A freshly installed macOS has no way for husker to reach it. Provisioning
mounts the image's disk on the host and writes three things into its Data
volume:

- `/usr/local/libexec/husker`: this husker binary, which runs inside the guest
  as `husker guest-agent`;
- `/Library/LaunchDaemons/dev.husker.guest-agent.plist`: a root LaunchDaemon
  that starts the agent at boot and restarts it if it exits;
- `/private/var/db/.AppleSetupDone`: skips Setup Assistant, so the headless
  guest boots straight to a running system.

It needs root because those files must be root-owned inside the guest. Pass
the bundle's directory path, not its name: `sudo` can change `HOME`, and with
it the data directory a bare name resolves against. `husker macos install`
prints the exact command.

Provision once per image. Every VM booted from it inherits the agent. The
agent is a copy of the provisioning husker binary, so re-run `provision` after
upgrading husker; VMs created before that keep the agent they were cloned with.
Interrupting a provision (Ctrl-C, SIGTERM or SIGHUP) stops it at the next
safe point: the guest disk is detached and the image stays marked
unprovisioned. A second signal, or SIGKILL, ends it at once and may leave the
disk attached: find it with `hdiutil info` and run
`sudo hdiutil detach <disk>` before provisioning again.
Provisioning and VM creation exclude each other: provisioning fails with a
conflict while a VM is cloning the image, and `husker run --macos` fails with
`image_busy` while the image is being provisioned.

## 3. Run VMs

```bash
husker run --macos sonoma --name mac1
husker exec mac1 -- sw_vers
husker shell mac1
husker cp ./script.sh mac1:/tmp/script.sh
husker stop mac1
husker destroy mac1 --yes
```

`--macos` takes an image name or a bundle directory path. Each VM gets
copy-on-write clones of the image's disk and auxiliary storage plus a freshly
generated machine identifier, so the image stays a pristine template and VMs
started from one image never share mutable state. The vCPU and memory
defaults are 4 and 8192 MiB, raised to the image's minimums. Asking for less
than the minimum is rejected rather than silently raised.

Networking is VZ shared NAT. The guest takes a DHCP address, and husker
learns it from the agent (`husker info mac1` shows `guest_ip` once it is
reported). The first boot of a VM takes longer than a Linux microVM;
`exec` waits up to 8 minutes for the agent.

## Limitations

- Commands run as root. Skipping Setup Assistant means the guest has no user
  account; create one with `sysadminctl` through `husker exec` if you need it.
- Not combinable with `--macos`: `--cloud-image`, a kernel, rootfs or initrd,
  `--volume`, `--mount`, `--disk-size` and SSH keys. Pools, snapshots, fork and
  idle suspend are not available on the Apple VZ backend.
- A macOS guest has no serial console, so `husker logs --source serial` is
  empty. Inside the guest the agent logs to `/var/log/husker-guest-agent.log`.
- Virtualization.framework runs at most two macOS VMs at a time on one Mac
  (Apple's licence terms). A third `husker run --macos` fails with "The
  maximum supported number of active virtual machines has been reached" and
  leaves nothing behind.
