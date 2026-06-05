# Reference image boot verification (macOS / Apple VZ)

Run this before cutting v0.1.0. Requires a booted macOS arm64 machine with
husker installed (`make install`).

## 1. Build fresh reference images

    make build-kernel-image ARCH=aarch64
    make build-initramfs
    make build-rootfs ARCH=aarch64

The initramfs is required: Alpine's `linux-virt` kernel ships `virtio_blk`
as a loadable module, so without an initrd to load it the kernel panics
with `Unable to mount root fs on /dev/vda`.

Confirm the paths:

    ls -lh ~/.local/share/husker/kernels/Image-virt
    ls -lh ~/.local/share/husker/kernels/initramfs-virt.gz
    ls -lh ~/.local/share/husker/images/alpine-aarch64.ext4

## 2. Start the daemon in the foreground

    husker daemon --listen 127.0.0.1:7777

Leave this running; use a second shell for the next steps.

## 3. Boot a VM

    husker run ~/.local/share/husker/images/alpine-aarch64.ext4 \
        --name boot-check \
        --initrd ~/.local/share/husker/kernels/initramfs-virt.gz \
        --cpus 2 --memory 512

Expected: `Created VM: boot-check`, state `Running` within ~2s.

## 4. Confirm the guest agent came up

    husker exec boot-check -- /bin/echo hello

Expected stdout: `hello`, exit code 0. If this fails, the agent isn't
responding on vsock port 52. Check `husker logs boot-check -n 50` for
inittab / agent startup errors.

## 5. Verify a round-trip file copy

    echo 'round-trip' > /tmp/rt.txt
    husker cp /tmp/rt.txt boot-check:/tmp/rt.txt
    husker exec boot-check -- /bin/cat /tmp/rt.txt

Expected: prints `round-trip`.

## 6. Clean up

    husker destroy boot-check

## Pass criteria

All five steps succeed on a clean macOS machine where
`~/.local/share/husker/` started empty. Failure in any step blocks v0.1.0 —
do not proceed to Phase 2.
