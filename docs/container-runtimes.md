# Docker and container runtimes

Husker's default modules-free kernel supports Docker, containerd, runc, and
other conventional OCI runtimes inside a guest. This is nested containers, not
nested virtualization: Firecracker, QEMU, or Apple VZ provides the VM boundary,
and the guest kernel provides container namespaces and cgroups.

## Choosing between Husker jobs and nested Docker

Use `husker job <oci-image>` when one OCI image already contains the command you
want to run. Husker imports the image into a bootable rootfs and gives the job a
dedicated VM without starting a container daemon.

Use Docker inside a VM when the workload itself needs Docker-compatible APIs,
builds container images, launches multiple containers, or tests Compose and
container networking.

## Example

The baseline rootfs is intentionally small, so grow the disposable VM disk and
allocate more than the 128 MiB lightweight-job default:

```bash
husker run alpine:latest \
  --name docker-host \
  --cpus 2 \
  --memory 1024 \
  --disk-size 4G

husker exec docker-host -- apk add --no-cache docker
husker shell docker-host

# Inside the VM:
dockerd >/var/log/dockerd.log 2>&1 &
docker run --rm alpine:latest echo container-ok
```

For a persistent daemon, configure the guest's init system to supervise
`dockerd`. The stock Alpine rootfs uses BusyBox init; imported distro images may
use OpenRC or systemd.

## Kernel contract

The authoritative built-in option set is
[`guest/container-kernel.config`](../guest/container-kernel.config). The kernel
builder applies the fragment after removing modular `defconfig` entries, runs
`olddefconfig`, and fails if Linux drops any requested option because of a
missing dependency or renamed symbol.

The running configuration is available at `/proc/config.gz`. Docker's upstream
[`check-config.sh`](https://github.com/moby/moby/blob/master/contrib/check-config.sh)
can inspect it directly:

```sh
curl -fsSL https://raw.githubusercontent.com/moby/moby/master/contrib/check-config.sh \
  | sh
```

The release kernel supports both nftables and legacy iptables compatibility.
Current Alpine Docker packages use the iptables-nft frontend by default; no
alternatives switch or `dockerd --iptables=false` workaround is required.

## Custom and Kubernetes kernels

Custom kernels must provide the same container-runtime feature set or Docker
may fail in stages: nftables/bridge omissions prevent `dockerd` from starting,
while missing cgroup BPF allows the daemon to start but makes runc fail every
container creation.

`make build-k3s-kernel` layers
[`guest/k3s-kernel.config`](../guest/k3s-kernel.config) over the default kernel
for kube-proxy IPVS and flannel VXLAN support. It uses the same pinned kernel,
virtio drivers, Docker feature set, validation, and architecture handling as
the release image builder.
