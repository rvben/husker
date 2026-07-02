# ADR-0004: Apple VZ Disk Attachment Caching/Sync Modes

- Status: Accepted
- Date: 2026-07-02

## Context

On macOS the Apple Virtualization.framework backend attaches VM disks via
`VZDiskImageStorageDeviceAttachment`. The convenience 3-argument initializer
(`initWithURL_readOnly_error`) uses default caching and synchronization modes.
With sparse raw images on APFS, those defaults corrupt re-reads: the guest boots
fine, then 30-150s later evicted pages re-read as zeros - random segfaults, sshd
goes deaf, agent exec returns EIO - while the host file stays intact. Root-causing
this cost roughly a day (fixed in commit `fe241cf`).

## Decision

- Always attach VZ disk images with the explicit initializer
  `initWithURL_readOnly_cachingMode_synchronizationMode_error`, using `Cached`
  caching and `Fsync` synchronization.
- Never use the 3-argument initializer for a VZ disk attachment.

## Consequences

- Stable re-reads of sparse raw images on APFS.
- The attachment call is more verbose but correctness-critical; any new disk
  attachment path must follow it.
