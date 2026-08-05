# Changelog

All notable changes to this project are documented in this file.

## [0.4.42](https://github.com/rvben/husker/compare/v0.4.41...v0.4.42) - 2026-08-05

### Fixed

- **images**: publish rootfs images on every release, not only monthly ([0e89ae7](https://github.com/rvben/husker/commit/0e89ae7ea801295e988982580aee5aadf57e57d4))
- **oci**: accept the oci:// scheme husker reports in an image's source_path ([667ae3b](https://github.com/rvben/husker/commit/667ae3b98a4e167ac45072ef2c551082fa5f2a42))
- **cli**: refuse host-local commands run against a remote context ([593c0ef](https://github.com/rvben/husker/commit/593c0efb196be36fe99b364db9f3e457ee6da91a))

## [0.4.41](https://github.com/rvben/husker/compare/v0.4.40...v0.4.41) - 2026-08-05

### Added

- **doctor**: report the sha256 and protocol of the embedded guest agent ([7ba562d](https://github.com/rvben/husker/commit/7ba562d45902b202edaeb99db8c4c3d8fc9397f5))
- **vm**: refresh the guest agent in each VM's rootfs clone at create ([9997e92](https://github.com/rvben/husker/commit/9997e922a01c07e9225d01eba7443645bdab7fc6))

### Fixed

- **proxy**: drain queued connections the reactor has not observed ([2ef3a54](https://github.com/rvben/husker/commit/2ef3a549ef69956d406add973d9716736f2fbff0))

## [0.4.40](https://github.com/rvben/husker/compare/v0.4.39...v0.4.40) - 2026-08-05

### Added

- **agent**: serve byte ranges from files/read ([d1dfed0](https://github.com/rvben/husker/commit/d1dfed0ebc0ff153e15678ce812e62637bf71da8))

### Fixed

- **cli**: keep an --out pattern containing a space as one pattern ([d4ec59e](https://github.com/rvben/husker/commit/d4ec59e9baae9e0a8e91816df3de6b8338e61eb8))
- **agent**: detect a file replaced mid-transfer by its modification time ([f715c68](https://github.com/rvben/husker/commit/f715c68ae46e7a09c262c32c8885cc2b5cf872f6))
- **agent**: refuse a positional read a guest cannot serve, and honour an offset without a length ([dec19ea](https://github.com/rvben/husker/commit/dec19eada4636d2a3eb599710c148e9216527da6))
- **cli**: retrieve --out artifacts larger than one read response ([a630263](https://github.com/rvben/husker/commit/a630263834e54df356285c35bcc93ada07f97b48))

## [0.4.39](https://github.com/rvben/husker/compare/v0.4.38...v0.4.39) - 2026-07-23

### Added

- **cp**: chunk large file copies past the write-size limit ([d5c566b](https://github.com/rvben/husker/commit/d5c566bfd89d552d6703498267f476b038555bdf))

### Fixed

- **agent**: flush file writes before responding so chunked appends land ([91908b0](https://github.com/rvben/husker/commit/91908b0bca6bd27cbc8617d0776e39b194df18a0))
- **api**: make the file-write size error actionable for cp callers ([af0db4a](https://github.com/rvben/husker/commit/af0db4adea8148b1e7cd47a8c91d4a7b38e1e120))
- **cli**: correct the port-forward --bind help for Linux ([6a5cd6b](https://github.com/rvben/husker/commit/6a5cd6b8bd83471642678012aa9ad793bf4f5d89))

## [0.4.38](https://github.com/rvben/husker/compare/v0.4.37...v0.4.38) - 2026-07-21

### Added

- **net**: add guest_isolation to deny NAT guests LAN and host access ([631c201](https://github.com/rvben/husker/commit/631c201462eba3e4b7af9789ed5aaf35c1338459))
- **net**: add --net none for a guest with no network at all ([08fefda](https://github.com/rvben/husker/commit/08fefda903a561dd41568196d7e60b26a0c1cecf))

## [0.4.37](https://github.com/rvben/husker/compare/v0.4.36...v0.4.37) - 2026-07-20

### Fixed

- **cli**: drop useless borrow in error print ([45a1fba](https://github.com/rvben/husker/commit/45a1fbaa0e87b78379e34a8e300fdf6b2acaef08))
- **agent**: drop stale mut on vsock listener ([1c8b09c](https://github.com/rvben/husker/commit/1c8b09c5a40e5695bb6321313d10de1d272aac59))
- **deps**: adapt to reqwest 0.13 and ruzstd 0.8 API changes ([46419f0](https://github.com/rvben/husker/commit/46419f08ef3f406ff3e0c18ed7501a16f4667c12))

### Performance

- **boot**: suppress legacy hardware probes on the guest kernel cmdline ([e8a9c71](https://github.com/rvben/husker/commit/e8a9c71a11556dea544e1f1c5b3ee84f74ab68b2))

## [0.4.36](https://github.com/rvben/husker/compare/v0.4.35...v0.4.36) - 2026-07-08

### Added

- **core**: apply `--disk-size` to plain-rootfs VMs (offline `resize2fs` after clone; previously cloud-image only) and give imported OCI images a 512 MiB growth-headroom floor so package installs no longer die on ENOSPC ([f27a7e3](https://github.com/rvben/husker/commit/f27a7e38863f1f836b44ce28d49ab4d426196268))

### Fixed

- **net**: resolve the guest NAT uplink from the IPv4 default route (`host_interface = "auto"`, the new default) instead of pinning a hardcoded interface name; daemon startup, `config check`, and `doctor` now warn when the uplink is missing, down, or not the default-route device ([777edd3](https://github.com/rvben/husker/commit/777edd3921b45bff26b053988b550a1442efe84a))
- **husker**: `--out` glob patterns now expand inside the guest against the files the command produced (previously passed to tar as quoted literals, silently matching nothing), and a retrieval that matches nothing is always reported ([cd39f14](https://github.com/rvben/husker/commit/cd39f147fd6fbad6924fd3af1a24007b7eb940ab))

## [0.4.35](https://github.com/rvben/husker/compare/v0.4.34...v0.4.35) - 2026-07-03

### Breaking Changes

- **api**: the REST error envelope's identifier field is renamed `code` -> `kind`, unifying it with the CLI error output and the clispec contract ([4e97136](https://github.com/rvben/husker/commit/4e97136caadaff189e70557565ce5ec275984b16))

### Added

- **state**: versioned schema migrations layered over the idempotent baseline schema ([c1709cf](https://github.com/rvben/husker/commit/c1709cfb8e04314f6b8ffe90a2ecd3a5dd0f3c80))

## [0.4.34](https://github.com/rvben/husker/compare/v0.4.33...v0.4.34) - 2026-07-03

### Added

- **core**: reclaim host resources from crashed VMs ([c3819fb](https://github.com/rvben/husker/commit/c3819fbd79a640a57b442c157c2aac40975aed7e))
- **agent-proto**: report and check guest agent protocol version ([4483b88](https://github.com/rvben/husker/commit/4483b88b40f306a594cb32ee72b074ce1047cb5c))

### Fixed

- **install**: give native Windows a clear WSL2 message ([c9e23b6](https://github.com/rvben/husker/commit/c9e23b654a58abd7415c902f8a8acfd86e18d154))

### Performance

- **core**: release the fork source lock after the disk phase ([6b0296a](https://github.com/rvben/husker/commit/6b0296af4fc833f2d8c71bb8f897462f3b2148ae))

## [0.4.33](https://github.com/rvben/husker/compare/v0.4.32...v0.4.33) - 2026-07-02

### Added

- **api**: add max-VMs admission control to bound host resource use ([82145eb](https://github.com/rvben/husker/commit/82145eb0fea8151de555bc78de183426cd037a26))
- **vmm**: instrument Firecracker/QEMU teardown with tracing ([51125de](https://github.com/rvben/husker/commit/51125de68ed4418f95f62a9999228f7166d28dca))
- **cli**: shell completions, all-or-nothing image pull, daemon_reachable flag ([a4cf7b6](https://github.com/rvben/husker/commit/a4cf7b64b9c59e6fa8927bb159d2eea28455a91c))
- **state**: add clear_vm_guest_ip to null a VM's persisted IP ([7ca858b](https://github.com/rvben/husker/commit/7ca858b1792d31cae141ddf776eee9c3a2abfe47))
- **husker**: reconcile leaked host resources on daemon startup ([11a8a8d](https://github.com/rvben/husker/commit/11a8a8d3607119218cae3b7f1a7e5e627b6a75a0))
- **cli**: accept --cpus and --vcpus interchangeably ([05006ec](https://github.com/rvben/husker/commit/05006ec4e9a78be24bb9ac1b9fb0c01b23d166dd))
- **api**: expose idle-policy metrics on /v1/metrics ([85820b9](https://github.com/rvben/husker/commit/85820b93f90801c998babaebacd2e7638f902fce))
- **cli**: add --idle/--idle-timeout/--suspend-ttl/--no-auto-resume flags and profile fields ([541495b](https://github.com/rvben/husker/commit/541495b07bf2aa721fcde930ea4249b440644576))
- **api**: plumb idle-policy fields through create request and VM response; gate non-firecracker ([c3fe90b](https://github.com/rvben/husker/commit/c3fe90b4f38960c878f55fc8591bc7b84e1af501))
- **core**: skip DNAT for suspended VMs at startup and re-install resume listeners ([c601fbe](https://github.com/rvben/husker/commit/c601fbe397a13b261970e68a81bac66b44367e66))
- **core**: add idle policy loop with in-lock re-check; wire spawn into daemon ([729a144](https://github.com/rvben/husker/commit/729a14406748af2cb87a8b10bc15100a79d4a04a))
- **core**: centralize sleep/wake network transition, suspended_at, and idle-timer reset ([e7ee177](https://github.com/rvben/husker/commit/e7ee17783ec7dcfc9bd3a228bc294acb48a4c1ff))
- **core**: auto-resume and pin active on agent_connect via session-guarded connection ([98fd753](https://github.com/rvben/husker/commit/98fd753a9c6c572505dc61ad132032b0823121da))
- **core**: generalize port_proxy to Linux with resume dialer and guarded relays ([2070fbf](https://github.com/rvben/husker/commit/2070fbf972bb4147c2ed635200ed37ff3fe2d728))
- **net**: add traffic counter to DNAT rules and a counter reader ([30569e9](https://github.com/rvben/husker/commit/30569e90acafa74069f32874ab1141bba2d7048c))
- **core**: add active-session refcount, RAII guard, and idle metrics ([051d6e1](https://github.com/rvben/husker/commit/051d6e15070f2aa7b55909fcd28c343caf9251d0))
- **cli**: add [idle_policy] config section and env overrides ([1fbfc21](https://github.com/rvben/husker/commit/1fbfc21882ce18fe76bf8401a0c0d306d409bf78))
- **core**: add pure evaluate_policy idle decision function ([112e5ea](https://github.com/rvben/husker/commit/112e5ea3905072a7f9716a11d9f8a0fcf527cfae))
- **state**: add idle-policy columns, setters, and fork-lineage query ([02ca610](https://github.com/rvben/husker/commit/02ca6102a4b9a791243d38f16827bb4369210ffc))

### Fixed

- **api**: make /v1/health probe the VMM backend and reflect it in status ([7bb64ef](https://github.com/rvben/husker/commit/7bb64efc0f4267240b02bf21e0eeaee12a727e9e))
- **core**: reclaim a crashed standalone VM's IP and port forwards ([ea50370](https://github.com/rvben/husker/commit/ea50370cfd2dc0b966350aeeab648cd1e3b8ba54))
- **husker**: verify the Firecracker download against a pinned checksum ([acfc52e](https://github.com/rvben/husker/commit/acfc52e40fe7ba99772d72f95bc6a5866a59c461))
- **core**: bound concurrent relay tasks in the macOS port-forward proxy ([8103181](https://github.com/rvben/husker/commit/8103181ae781ac953f8a332ef88fa4b7218f0018))
- **agent**: cap captured exec output instead of discarding it on overflow ([86d1373](https://github.com/rvben/husker/commit/86d1373845a33a93324bc25d53a9bb7639337649))
- **api**: deny-by-default auth, constant-time token compare, bounded shutdown ([8c30d1c](https://github.com/rvben/husker/commit/8c30d1c163824f7b564d7cc47f716f9a678e23c1))
- **husker**: harden daemon startup, remote-bind auth, and destructive-op gates ([02c368e](https://github.com/rvben/husker/commit/02c368e3fdc05b575dfe3a58a7a43ee9b5d97305))
- **core**: validate fork name and agent-reported guest IP ([6263d09](https://github.com/rvben/husker/commit/6263d0913126ba5cc8cb513579131e4a0f28672c))
- **core**: gate idle test helpers behind linux-net so make test-macos is dead-code-clean ([396814a](https://github.com/rvben/husker/commit/396814ac991c822d2755e5d4d4020e5469eb6792))
- **core**: log idle-loop action failures, drop dead getter, reject idle flags with --pool ([2d36e26](https://github.com/rvben/husker/commit/2d36e261e4059543427b78a795d5e98ed45a61e6))
- **husker**: gate idle-policy loop spawn behind linux-net feature ([ac56e8f](https://github.com/rvben/husker/commit/ac56e8ffe9916ee9faa0a27e2da66e8396832e0e))
- **core**: gate resume network transition to suspended arm; dedup connect-resume metric ([291a396](https://github.com/rvben/husker/commit/291a3965e6b6f8d8fda679f77650761e2d9a6eb0))

### Performance

- **state**: pool SQLite connections instead of one shared mutex ([33a8177](https://github.com/rvben/husker/commit/33a817782d9d72be6b7e6320059158ac8d9d9d85))
- **core**: refresh VMs concurrently in list_vms_refreshed ([0726af6](https://github.com/rvben/husker/commit/0726af645dc8758e88734b31ed421ab8668b9e34))
- **state**: index port_forwards.vm_id and vms.service_id ([04bd3a0](https://github.com/rvben/husker/commit/04bd3a058972dfed4d3bcd0d9f73b39b3a7c0a49))


## [0.4.32](https://github.com/rvben/husker/compare/v0.4.31...v0.4.32) - 2026-07-01

### Fixed

- **core**: `husker doctor`'s `cgroup limits` readiness check now reads the daemon cgroup's `cgroup.controllers` instead of `cgroup.subtree_control`. Once `resource_limits` is enabled, `init()` moves the daemon into a `supervisor` leaf whose `subtree_control` is empty, which made the check falsely report the memory/cpu controllers as not delegated even while limits were being enforced ([18d0e60](https://github.com/rvben/husker/commit/18d0e60))


## [0.4.31](https://github.com/rvben/husker/compare/v0.4.30...v0.4.31) - 2026-07-01

### Added

- **vmm**: opt-in per-VM cgroup v2 resource limits on Linux (Firecracker and QEMU). Set `resource_limits = true` (default off, `HUSKER_RESOURCE_LIMITS`) to cap each VM's memory at `mem_size_mib + memory_overhead_mib` (default 256 MiB margin) with `memory.swap.max=0` and `memory.oom.group=1`, so a runaway guest OOMs in its own cgroup instead of the host; enable `cpu_limit` to also cap CPU at the VM's vCPU count. The daemon builds a delegated cgroup topology at startup (requires `Delegate=yes` on the unit) and fails closed if limits are requested but unavailable; each VMM process is placed in its own `vm-<id>` cgroup and reaped on exit, destroy, or create-time failure. `husker doctor` reports a `cgroup limits` readiness check ([b27a4a7](https://github.com/rvben/husker/commit/b27a4a7))


## [0.4.30](https://github.com/rvben/husker/compare/v0.4.29...v0.4.30) - 2026-07-01

### Added

- **api**: add an optional bearer token for the metrics listener (`metrics_token` / `HUSKER_METRICS_TOKEN`); when set, `/v1/metrics` requires `Authorization: Bearer` - defense in depth alongside a host firewall, independent of `api_token`. Unset keeps it unauthenticated ([ee96382](https://github.com/rvben/husker/commit/ee96382))


## [0.4.29](https://github.com/rvben/husker/compare/v0.4.28...v0.4.29) - 2026-07-01

### Added

- **api**: add an optional unauthenticated metrics listener (`metrics_listen` / `HUSKER_METRICS_LISTEN`) that serves ONLY GET /v1/metrics on a separate bind, so Prometheus can scrape without the API token while the main API stays authenticated/loopback ([6b99f7f](https://github.com/rvben/husker/commit/6b99f7f))


## [0.4.28](https://github.com/rvben/husker/compare/v0.4.27...v0.4.28) - 2026-07-01

### Added

- **core**: surface each `husker doctor` check in GET /v1/metrics as a `husker_diagnostic_check_status{check="..."}` gauge (0=ok, 1=warn, 2=fail), served from a 60s TTL cache shared with /v1/diagnostics ([ed78900](https://github.com/rvben/husker/commit/ed78900))


## [0.4.27](https://github.com/rvben/husker/compare/v0.4.26...v0.4.27) - 2026-07-01

### Added

- **core**: enrich `husker doctor` / GET /v1/diagnostics with host preflight checks (embedded agent, default boot images, state-dir free space, vhost_vsock, guest NAT egress, macOS backend) ([fbaf5a4](https://github.com/rvben/husker/commit/fbaf5a4265d2b4bfbaf12de4d934869a720d4ad2))

### Fixed

- **api**: GET /v1/diagnostics now reports the storage-mount check (it previously ignored the storage_volume config flag) ([fbaf5a4](https://github.com/rvben/husker/commit/fbaf5a4265d2b4bfbaf12de4d934869a720d4ad2))


## [0.4.26](https://github.com/rvben/husker/compare/v0.4.25...v0.4.26) - 2026-07-01

### Fixed

- **husker**: insert setup-storage config keys before the first TOML table ([093e5b0](https://github.com/rvben/husker/commit/093e5b0fc42b5ede4600b1b5882656da3934b8e3))

## [0.4.25](https://github.com/rvben/husker/compare/v0.4.24...v0.4.25) - 2026-07-01

### Added

- **husker**: add setup storage command to generate the migration script ([d0ccb97](https://github.com/rvben/husker/commit/d0ccb97ef233f477fdb09510e69748c6d4a65fe7))
- **husker**: validate and build the setup-storage plan from host facts ([9f869f3](https://github.com/rvben/husker/commit/9f869f3c46ac0e44ca989163cbfcdb9827de11e2))
- **husker**: render the setup-storage migration script from a template ([f2b35f2](https://github.com/rvben/husker/commit/f2b35f2010876ffe5263e4598c4642595ca72ef1))
- **husker**: add storage-setup plan types and systemd/fstab renderers ([602cd4e](https://github.com/rvben/husker/commit/602cd4e35223e8f20b26af8b73ea06c1ba4b892a))
- **husker**: add doctor command for host diagnostics ([b49fb9c](https://github.com/rvben/husker/commit/b49fb9c206026ee1e0a812831bd1b8381c8aa4af))
- **api**: add GET /v1/diagnostics host health endpoint ([947a074](https://github.com/rvben/husker/commit/947a074ac5222eb1f7ff234e2bdd70f761cd33ef))
- **husker**: guard daemon startup with flock and storage mount sentinel ([d4ed055](https://github.com/rvben/husker/commit/d4ed055c15212a567bea1d30bbed6ef7ea4d1bf4))
- **husker**: add daemon flock and storage mount-guard helpers ([35c027c](https://github.com/rvben/husker/commit/35c027ce567a64320c8fc05ff798a387a7dc0848))
- **husker**: add state_dir and storage_volume config with env overrides ([0f8b69f](https://github.com/rvben/husker/commit/0f8b69fc91fe8bb389c8d16808dc2235bb696b36))
- **core**: add host diagnostics model and build_diagnostics ([26c37ae](https://github.com/rvben/husker/commit/26c37ae33eb42c6978d6b92775fbc7c8a5042727))
- **storage**: add state_dir to StorageConfig with db/runtime/lock paths ([b5efaf9](https://github.com/rvben/husker/commit/b5efaf9f35ea3cc57bbfc7ec0bd50eb9113f4be4))
- **storage**: add empirical reflink probe for diagnostics ([6305155](https://github.com/rvben/husker/commit/630515553a6e87198c43ed500287266a747795d1))

### Fixed

- **husker**: treat ssh-tunneled contexts as remote in doctor and setup storage ([c7d36ad](https://github.com/rvben/husker/commit/c7d36ad113cf1e196155b8cceccc234abd04691f))
- **husker**: reject sub-minimum loopback size at generate time; e2e uses 1G ([9e0573e](https://github.com/rvben/husker/commit/9e0573e689d2d4e3cfc96a225d9a8a5c2b7022cf))
- **husker**: restore the DB in setup-storage rollback and derive api_addr from api_url ([1837c59](https://github.com/rvben/husker/commit/1837c59ed00d636c55e5600d8cc3000a35b4805a))
- **husker**: make setup-storage fstab target overridable so the e2e never touches real /etc/fstab ([b522dba](https://github.com/rvben/husker/commit/b522dba82aea7bf14caaa270c84a2c1f572b0fea))
- **husker**: exit gracefully on setup-storage --out write errors ([72f2b25](https://github.com/rvben/husker/commit/72f2b252596a700adf08604e21850ca296a4e409))
- **husker**: make the setup-storage verify failure-safe and simplify flush ([bb19bba](https://github.com/rvben/husker/commit/bb19bba8cf171dfac7d81fb548607e0096f35ad5))
- **api**: document /v1/diagnostics in OpenAPI and surface diagnostics probe panics ([28bd200](https://github.com/rvben/husker/commit/28bd200167786061025475b4198716c17936e108))

## [0.4.24](https://github.com/rvben/husker/compare/v0.4.23...v0.4.24) - 2026-06-28

### Added

- **husker-vmm**: send graceful flush before destroy_vm ([d941604](https://github.com/rvben/husker/commit/d94160412afc3f8fab43d7ef17d376de991ea057))
- **husker-agent**: auto-mount /dev/vdb at /data in the supervisor ([f33fb45](https://github.com/rvben/husker/commit/f33fb45d02d07e22cdeff4d4984931b750000af9))
- **husker-agent**: handle Shutdown request with sync and volume unmount ([4c80118](https://github.com/rvben/husker/commit/4c801183da93d604b0af47a4951b8d67794b6d0d))
- **husker-agent-proto**: add Shutdown request and ShuttingDown response ([1095580](https://github.com/rvben/husker/commit/10955801762469ae88087219040882e489ed24fb))

### Fixed

- **husker-vmm**: bound the whole shutdown-ack read so a guest hung in sync cannot block destroy (codex review) ([4474611](https://github.com/rvben/husker/commit/4474611fc0510c8ab7350e3dbc5d12c8e434002a))
- **husker-vmm**: wait for the sync ack (bounded) so large volume flushes complete before kill (codex review) ([7b7c30b](https://github.com/rvben/husker/commit/7b7c30b5e74b75163fc5bba7d91e2fab719be88a))
- **husker-vmm**: bound the whole graceful-flush attempt so a wedged VM cannot delay destroy (codex review) ([dc944c5](https://github.com/rvben/husker/commit/dc944c5bc2bc4e25d17591a84b454fc1949b4209))

## [0.4.23](https://github.com/rvben/husker/compare/v0.4.22...v0.4.23) - 2026-06-28

### Added

- **husker**: expose daemon profiles via GET /v1/profiles and husker profile list ([42d20af](https://github.com/rvben/husker/commit/42d20afd82dc6655ac83c80f2a106a522713304c))
- **husker**: add configurable daemon-level default memory and vCPU count ([e629283](https://github.com/rvben/husker/commit/e62928372d36f4da05953e317eb75f24b5dfcd59))

### Fixed

- **profiles**: distinguish daemon offline from daemon with zero profiles ([56e94e7](https://github.com/rvben/husker/commit/56e94e70c06a24059fe314501f9d4079317401c5))
- **husker**: surface auth/server errors from profiles fetch; annotate profile list in schema ([85ff808](https://github.com/rvben/husker/commit/85ff8082b8b277844eaa5212bec2bc8f90e80384))
- **husker-core**: apply daemon default resources on all non-linux-net create paths ([21b2260](https://github.com/rvben/husker/commit/21b226000117797b79a2f71217832620e491bc32))
- **profiles**: track merged-winner origin to fix daemon vs local path resolution ([8d5407c](https://github.com/rvben/husker/commit/8d5407cb0e9e917210973cc1304b7a515903ef5b))
- **husker**: two P2 correctness fixes for daemon profiles and snapshot restore ([b420ebb](https://github.com/rvben/husker/commit/b420ebb413c31e0e8183ee9cb9e41a2eab0e422f))

## [0.4.22](https://github.com/rvben/husker/compare/v0.4.21...v0.4.22) - 2026-06-27

### Fixed

- **husker-core**: auto-select qemu when host bind-mounts are present ([5123a19](https://github.com/rvben/husker/commit/5123a194134f2a8eae230e54aab8212077e6cfef))
- **guest**: symlink cat in initramfs so the virtiofs share-mount runs ([eeee01c](https://github.com/rvben/husker/commit/eeee01c390f772f6cfc38a4e14c1beb9cc16b94b))

## [0.4.21](https://github.com/rvben/husker/compare/v0.4.20...v0.4.21) - 2026-06-27

### Added

- **husker-vmm**: auto-select qemu when host shares present and vmm unset ([9f578c4](https://github.com/rvben/husker/commit/9f578c4ca346b14dcb0bb94912d5f570edb7be8d))
- **husker-api**: mounts request field + host-path allowlist + cmdline injection ([77cf44c](https://github.com/rvben/husker/commit/77cf44c8a5ef06c877622b0f1e99c7bb2dc01e87))
- **husker-agent**: mount virtiofs host shares from cmdline ([4b35149](https://github.com/rvben/husker/commit/4b35149d8ee3f5553c9bfe1d18b7bc6103ad3df0))
- **husker-vmm**: virtiofsd + vhost-user-fs device per host share ([403f186](https://github.com/rvben/husker/commit/403f1869fdd463de908e74ba1ec97295969b1d44))
- **husker-vmm**: qemu shared memory-backend when host shares present ([464a2fe](https://github.com/rvben/husker/commit/464a2fe02a19af4c9b590f771d14ddd337cfdb91))
- **husker-vmm**: firecracker rejects --mount host shares ([e2c4ce3](https://github.com/rvben/husker/commit/e2c4ce3bb1fa456c89dd8a62db6567b35fb0f2ed))
- **husker**: --mount flag + profile mounts ([af7f8c0](https://github.com/rvben/husker/commit/af7f8c060a8d3043f9af34f466c8662107431e01))
- **husker-vmm**: add HostShare + VmConfig.host_shares ([af847e6](https://github.com/rvben/husker/commit/af847e6f2bece5518bb1cb4018647d13ea5cba6e))

### Fixed

- **guest**: build a PVH-enabled microVM kernel so QEMU can direct-boot it ([7888b3a](https://github.com/rvben/husker/commit/7888b3a9765edc793bc1b5e1c612c6d5313b6663))
- **husker-core**: set mounts on CreateVmRequest literals in tests ([6439605](https://github.com/rvben/husker/commit/6439605f865f29df68ab4004fd20e929d9af382a))
- **husker**: propagate allowed_mount_host_paths to Config and ApiPolicy ([27b0441](https://github.com/rvben/husker/commit/27b044162f6de769b037f6c6dcd905cd5b90af91))

## [0.4.20](https://github.com/rvben/husker/compare/v0.4.19...v0.4.20) - 2026-06-25

### Fixed

- **net**: seed the in-memory IP allocator from persisted VMs at startup. The allocator reset to empty on every daemon restart, so it could re-hand-out an IP still recorded for an existing VM (bridge IP conflict) and fail to release a pre-restart IP. It now reserves existing VMs' addresses on startup, like the CID allocator. Also surface nftables port-forward cleanup failures at `warn` instead of swallowing them. ([379bab6](https://github.com/rvben/husker/commit/379bab6e77be7da0d931cf4bcc4ae9500eadd854))
- **vmm**: remove the boot and serial log files when a restore/fork times out waiting for the Firecracker socket (previously two files leaked per failed restore), and bound the vsock CONNECT handshake with a 10s timeout so a stuck VMM cannot hang an exec/shell request indefinitely. ([983e0f4](https://github.com/rvben/husker/commit/983e0f4d70279e7d4708d0d73df8ff5d20e2d992))
- **agent**: kill the interactive shell process when the client disconnects mid-session (it was orphaned in the guest), and report a failed file-mode change instead of returning success - an executable userdata script could otherwise be silently written non-executable. ([c33c3c9](https://github.com/rvben/husker/commit/c33c3c9ee18f3e57e026d0319652604f5655e749))

## [0.4.19](https://github.com/rvben/husker/compare/v0.4.18...v0.4.19) - 2026-06-25

### Fixed

- **api**: require an API token for volume create/delete. `/v1/volumes` was missing from the protected-route allowlist, so a daemon started with `--api-token` still accepted unauthenticated `POST /v1/volumes` and `DELETE /v1/volumes/{name}` (the latter destroys a persistent volume). ([5024ed2](https://github.com/rvben/husker/commit/5024ed2d5219aba433fedd8e10c5d136c907018d))
- **state**: surface real database-migration errors instead of swallowing them. The idempotent `ADD COLUMN` migrations discarded every error to ignore the expected duplicate-column case, which also hid genuine I/O or corruption failures behind a later cryptic "no such column" on the first query. ([a5e0de0](https://github.com/rvben/husker/commit/a5e0de00761aa763d865d66f565c243d0f4c2269))
- **storage**: harden the volume/clone/qcow2 paths. `qcow2_virtual_size` no longer blocks the async executor, volume images are created with `O_EXCL` so concurrent builders cannot corrupt each other, and a failed clone removes only a partial destination (never a pre-existing file). ([bb6c0a2](https://github.com/rvben/husker/commit/bb6c0a22c721080543f838f9adaf1052af3048a9))

## [0.4.18](https://github.com/rvben/husker/compare/v0.4.17...v0.4.18) - 2026-06-24

### Added

- **core**: hot pools - pre-warmed, suspended template VMs that `husker pool checkout` (and `run`/`job --pool`) fork into fresh, isolated VMs in about a second instead of a 6-8s cold boot, inheriting the template's warm guest state. A single template forks concurrently many times via Firecracker `vsock_override`. New `pool create/list/get/checkout/delete` (CLI + REST). ([b8df6f4](https://github.com/rvben/husker/commit/b8df6f40cba8a53892ce92003b602a037e057998))
- **cli**: `run --pool` / `job --pool` draw a VM from a hot pool for a sub-second pool-backed run or sandboxed job. ([5674e5b](https://github.com/rvben/husker/commit/5674e5bde630f7d872d7d1b118750e36f1d54a89))

### Fixed

- **vmm,net**: clean up qemu per-VM artifacts on a failed create, and log bridge/TAP/port-forward cleanup failures instead of swallowing them. ([eec7320](https://github.com/rvben/husker/commit/eec7320c7763757efc9d944b34e11c6e439c4f25))
- **core**: log rotation reads exactly the bytes to keep, fixing a rare truncation to fewer bytes than requested. ([161d9e2](https://github.com/rvben/husker/commit/161d9e2f202add092f86b38af52b38c03f3ae906))

## [0.4.17](https://github.com/rvben/husker/compare/v0.4.16...v0.4.17) - 2026-06-23

### Fixed

- **core**: reap an orphaned firecracker too, via one id-checked VMM reaper. Both backends orphan identically on an uncleaned daemon exit, so the startup reaper and the interrupted-suspend recovery now SIGKILL a surviving firecracker (not just qemu), gated on the VM id in the live process cmdline ([7721be0](https://github.com/rvben/husker/commit/7721be0e9158caccb399c8b06ae9076f3f3d6f5b))
- **core**: reap a firecracker orphaned by an interrupted suspend before recovery, so a later resume/fork cannot boot a second VMM against the same rootfs, vsock, CID, and TAP ([6b1b9e2](https://github.com/rvben/husker/commit/6b1b9e2f903e29def3fc20314f6f84dd3e8d25b2))

## [0.4.16](https://github.com/rvben/husker/compare/v0.4.15...v0.4.16) - 2026-06-23

### Fixed

- **deps**: bump quinn-proto to 0.11.15 (RUSTSEC-2026-0185) ([b7f0221](https://github.com/rvben/husker/commit/b7f0221aba27a0974f375f7f0f359544be1b4e85))
- **cli**: kill the ssh:// tunnel on process::exit so piped invocations don't hang ([c76e38a](https://github.com/rvben/husker/commit/c76e38a20412866073c2663ea85921713a3979ee))
- **core,vmm**: harden suspend/fork crash-safety and fork error handling ([05678e7](https://github.com/rvben/husker/commit/05678e7105b30f8eb2ba9f724a3426ef85abe647))

## [0.4.15] - 2026-06-15

### Added

- **`--secret` injects a stored secret into a command's environment.**
  `husker exec/job --secret NAME` (or `--secret ENVVAR=secret-name` to rename)
  exposes a secret from husker's encrypted store as an environment variable. The
  client sends only the secret name; the daemon (which holds the key) resolves it
  to plaintext and adds it to the exec environment, so the value never appears in
  argv, the host process table, or shell history. A secret overrides a plain
  `-e`/`--env-file` value on a key clash, the exec env allowlist is enforced
  against the resolved keys, and a missing secret fails before the VM is touched.
  This completes the secrets subsystem, which was previously encrypt-at-rest only
  with no guest injection.

### Fixed

- **Stale baked kernel modules are named in boot diagnostics.** A rootfs whose
  baked `.ko` files disagree with the running kernel (a kernel refresh
  invalidated them) brings up no vsock, so the only prior symptom was a generic
  "agent not ready" timeout. When the serial-console tail shows the ABI-mismatch
  signature, the boot-failure hint now says to rebuild the rootfs against the
  current kernel.

## [0.4.14] - 2026-06-14

A round of OCI/job usability fixes found while dogfooding the OCI-boot work.

### Added

- **`run`/`job` accept a catalog image name or an OCI reference, not just a
  path.** `husker job python:3.12-alpine -- ...` auto-imports the image on first
  use (cached afterwards), and `husker run myimg` resolves a catalog image by
  name - no need to know the on-disk catalog path. A bare unknown name now gives
  a clear error instead of a missing-file one.
- **`husker job <oci-image>` with no command runs the image default.** Like
  `docker run <image>`, omitting the command after `--` now runs the image's
  Entrypoint + Cmd instead of being a parse error; any args you pass are
  appended. A plain (non-OCI) rootfs with no default returns a clear error.
- **`--env-file <path>` for `run`, `job`, and `exec`.** Read environment
  variables from a `KEY=VALUE` file (repeatable) instead of `-e` flags that land
  in the host process table and shell history. Blank lines and `#` comments are
  skipped, a leading `export ` is tolerated, and a line without `=` fails loudly;
  an explicit `-e` overrides a file entry on a key collision.
- **Per-VM `--dns <ip>` and `--add-host name:ip` for `run` and `job`.** Override
  a single VM's DNS and `/etc/hosts` without the daemon-wide `dns_servers` change
  that affected every VM (including service runners). `--dns` replaces the VM's
  `/etc/resolv.conf` nameservers; `--add-host` merges entries into `/etc/hosts`
  idempotently. The `name:ip` split is on the first colon, so IPv6 values work.

### Fixed

- **Long execs honor `--timeout` and no longer lose their output.** Previously
  `--timeout` only bounded the daemon-side call while the guest agent capped
  every command at 600s and discarded the partial output on timeout. The timeout
  now propagates to the agent, and on timeout the command's output so far is
  returned with exit code 124 (the conventional timeout code) plus a note.
- **Boot and agent-readiness failures point at the guest serial log.** A VM that
  boots but whose guest never brings up the agent (and a `job` that times out
  waiting for boot) now include the tail of the guest serial console plus a
  `husker logs --source serial <name>` hint, instead of a bare "agent not ready".

### Changed

- **`husker image delete` is gated on confirmation like `husker destroy`:** it
  prompts on a TTY and requires `--yes` when stdin is not a TTY (and now accepts
  `--yes`, which it previously rejected).

## [0.4.13] - 2026-06-14

### Added

- **Boot and run any OCI/Docker image, not just busybox/alpine.** Images imported
  with `husker image import-oci` of any base (debian-slim, distroless, ...) now
  boot into the guest agent as PID 1 and run with the image's own environment: a
  bare `python3` resolves, `$PWD` matches the image's `WorkingDir`, and the network
  comes up with no `iproute2`/busybox in the rootfs (the agent loads the needed
  kernel modules and configures networking via netlink directly). Previously only
  busybox-init images booted; a debian-slim image panicked at `switch_root`.

### Fixed

- **`husker fork` works again.** Fork rebinds the guest NIC to a fresh host TAP on
  snapshot restore via Firecracker's `network_overrides` field, added in Firecracker
  1.12.0, but husker pinned 1.10.1, so fork failed with an opaque 400 and had never
  worked against the installed binary. The pinned Firecracker is bumped to 1.16.0,
  and a preflight now fails with a clear "requires Firecracker >= 1.12.0" message on
  older binaries.
- **Imported OCI VMs keep their configured DNS.** The agent supervisor no longer
  overwrites a `/etc/resolv.conf` the daemon seeded from its configured `dns_servers`.

### Changed

- Pinned Firecracker bumped from 1.10.1 to 1.16.0 (required for `husker fork`; no
  husker-used API field changed between the two versions).

## [0.4.12] - 2026-06-14

### Fixed

- **`husker service create` without explicit kernel/rootfs works again.** 0.4.11
  made the client omit unspecified image paths so the daemon resolves its own
  defaults, but `create_service` still required explicit kernel/rootfs and
  rejected the request before the daemon-side defaulting ran. It now resolves the
  daemon defaults in the service path too, matching `run`/`job`.

## [0.4.11] - 2026-06-14

### Added

- **macOS userspace port forwarding.** `husker port-forward` now works on macOS
  through a userspace GuestDialer proxy (no host nftables), with a `--bind` flag
  and a cross-platform `bind_addr` in the port-forward API.

### Fixed

- **Remote `run`/`job` over `ssh://` no longer send client-local image paths.**
  The client resolved default kernel/initrd/rootfs paths from its own filesystem
  and sent those absolute paths to the daemon, so a macOS client driving a Linux
  daemon asked it to boot `.../kernels/Image-virt` and an `initramfs-virt.gz` that
  do not exist there. The client now omits any path the user did not specify, and
  the daemon resolves them from its own configured defaults
  (`HuskerCore::with_default_images`). This also unifies initrd resolution to
  honor the daemon's default. `version`/`list` were unaffected (no files needed).
- **Port-forward removal is scoped to the owning VM**, with tightened conflict
  detection.

## [0.4.10] - 2026-06-13

### Fixed

- **`ssh://` daemon transport now works.** The tunnel set `ControlPersist`, which
  makes ssh background its master connection and exit the foreground process as
  soon as the forward is up; the readiness check read that exit as a failure and
  always aborted with "exited before it was ready", so `ssh://` (and any context
  pointing at one) never connected. The tunnel is now a dedicated foreground
  `ssh -N -L` that lives for the connection's lifetime, with its stdio quieted so
  a login banner/MOTD cannot corrupt command output.

## [0.4.9] - 2026-06-13

### Added

- **OCI-native sandbox images.** `husker image import-oci <ref>` imports a
  Docker/OCI image as a bootable rootfs (now including zstd-compressed layers).
  Imported images boot the guest agent as PID 1 - a minimal init/supervisor that
  mounts the pseudo-filesystems and device nodes, configures networking from the
  kernel `ip=`, and supervises the agent as a restartable child (an agent crash
  restarts the child instead of killing the VM). So any Dockerfile-defined
  toolchain becomes a sandbox. Validated end to end on Firecracker, with a gated
  boot e2e (`make test-oci-boot-e2e-gated`).
- **`husker job --sync-cwd` clean-room sandbox.** Syncs the git-aware working
  tree (tracked plus untracked-not-ignored files, build dirs excluded) into a
  throwaway VM and runs there, leaving the host untouched. `--out <path>` copies
  named artifacts back; `--write-back` applies the command's changes to the
  synced files (build pollution never returns).
- **`ssh://` daemon transport + capability-aware errors.** `--api-url
  ssh://[user@]host` reaches a remote daemon over an SSH tunnel (reusing your ssh
  config/keys, connection-multiplexed), so a macOS host can drive a remote Linux
  Firecracker daemon. `/v1/health` advertises the backend and its capability
  matrix; `fork`/`suspend`/`image import-oci` fail fast with a route hint when
  the targeted backend cannot run them.
- **Named contexts.** `husker context add/use/list/remove/show` saves named
  daemon targets (`http://` or `ssh://`) and switches between them; `-c/--context`
  (and `HUSKER_CONTEXT`) selects one per command.
- **Firecracker suspend/resume.** `husker suspend <vm>` captures a VM's full
  state (guest RAM + vCPU + devices) to a per-VM slot
  (`<data_dir>/suspend/<id>/{memory,vmstate,manifest.json}`) and frees the
  process; `husker resume <vm>` restores it in place with the same identity,
  networking, IP, and CID. Exposed via `POST /v1/vms/{name}/suspend` and the
  new `VmmBackend::snapshot_vm`/`restore_vm` methods (Firecracker `/snapshot/
  create` and `/snapshot/load`; QEMU and Apple VZ report unsupported). Adds a
  `suspended` VM state that survives daemon restarts; the rootfs and host
  networking are preserved across suspend so resume needs no disk copy or
  re-IP.

### Fixed

- **pause/resume against real Firecracker.** Firecracker's runtime VM-state
  endpoint is `PATCH /vm`, not `PUT /vm`; the previous `PUT` was rejected with
  HTTP 400, which broke `husker pause`/`husker resume` (and the new suspend,
  which pauses first) on real Firecracker.

## [0.4.8] - 2026-06-12

### Added

- **Cloud-image VMs on macOS (Apple Silicon).** `husker run --cloud-image
  ubuntu.img` now works on the Apple VZ backend: EFI boot with a per-VM
  variable store, automatic qcow2-to-raw conversion via `qemu-img`, a
  cloud-init seed with the embedded aarch64 agent and SSH keys, DHCP via the
  VZ NAT NIC, and agent-reported guest IPs. `--volume`, services, and
  `--balloon` with cloud images are rejected on macOS for now; Intel Macs are
  unsupported.
- **Memory balloon on Apple VZ.** `--balloon` attaches a virtio balloon
  device on macOS and `husker balloon <vm> <mib>` resizes it, at parity with
  the Firecracker and QEMU backends. Platform caveat: explicit targets
  reclaim memory, but memory freed inside the guest is not automatically
  returned to the host.
- **Modules-free microVM kernel.** Default images now ship a from-source
  Linux 6.12 kernel with every required driver built in (no loadable
  modules), built by `guest/build-microvm-kernel.sh`. Kernel/initramfs
  version pairing can no longer break, guests boot with or without an
  initramfs (`root=/dev/vda` is added automatically when no initrd is used),
  and agent-ready boot time on Firecracker drops about 3.5x (19.7s to 5.6s
  measured). The 128 MiB default VM memory is sufficient on all boot paths.
- **Guest agent memory self-limit.** The agent confines itself to a cgroup
  v2 leaf with a 128 MiB `memory.high` throttle at startup; exec, job, and
  userdata workloads are moved out of the leaf so they never inherit the
  limit.

### Fixed

- **Apple VZ disk attachments no longer corrupt sparse raw images on APFS.**
  All VZ disk images attach with explicit cached + fsync modes; the default
  modes returned zeros for evicted page re-reads, causing random guest
  failures 30-150s after boot.
- **`make update-rootfs` no longer fails silently.** The debugfs injection
  runs as a single session and verifies the injected files by reading them
  back and comparing against the sources.
- **Gated e2e suite runs on standard hosts.** `HUSKER_RUN_IGNORED_E2E=1`
  tests resolve fixtures via the production default-image paths (arch and
  data-dir aware, env-overridable), create and clean up their own VMs with
  self-healing pre-delete, and now exercise both Firecracker and Apple VZ.
- **The initramfs device wait is a real timeout.** The `/dev/vda` poll
  sleeps between iterations (5s budget) instead of busy-spinning, and a
  boot-critical module that is present but fails to load produces an
  explicit kernel/module mismatch warning.

## [0.4.7] - 2026-06-11

### Added

- **CLI Spec v0.2 compliance (24/24).** New `schema` subcommand emitting the
  clispec v0.2 contract (global args, typed command args, output fields,
  error kinds with exit codes, mutation markers), a three-valued
  `--output/-o` flag (auto/text/json) with auto-JSON when piped, structured
  error envelopes as the last line of stderr, `--yes` confirmation gates for
  destructive commands without a TTY, and `--limit/--offset/--fields` with
  item-envelope pagination on list commands.

## [0.4.6] - 2026-06-11

### Added

- **`husker volume get <name>`.** Volume details (name, size, backing file,
  creation time) as text or JSON, mirroring `secret get`. The CLI schema
  annotates it read-only with `status`/`action`/`volume` output fields.

### Fixed

- **Cloud-image and QEMU runs no longer require Firecracker on the client.**
  `husker run --cloud-image ...` (or `--vmm qemu`) failed client-side when the
  Firecracker binary was missing, even though the request is served by QEMU.
  The preflight now only runs for Firecracker-bound requests.
- **Volume-backed services are limited to one instance.** Creating or scaling
  a service with `--volume` and more than one instance is now rejected with a
  clear error. Volumes are exclusive-attach, so previously only the first
  replica could start while the reconciler retried the rest forever.

## [0.4.5] - 2026-06-10

### Added

- **Bridged LAN networking for cloud-image VMs (Linux).** With a host bridge
  configured (`lan_bridge` / `HUSKER_LAN_BRIDGE`), `husker run --cloud-image
  ... --net bridged` puts the VM's NIC directly on that bridge: the guest gets
  its address via the LAN's DHCP (cloud-init), making it a first-class LAN
  citizen. Bridged VMs reject port forwards (they are on the LAN already);
  microVMs stay NAT-only for now. `husker info` reports the network mode, and
  `config check` verifies the configured bridge exists.

### Fixed

- **Guest-initiated shutdown is now detected on macOS.** The Apple VZ backend
  queries the live virtual-machine state, so a guest that powers itself off
  shows `stopped` in `husker list`/`info` and `wait` fails fast, matching the
  Linux backends.

## [0.4.4] - 2026-06-10

### Added

- **Persistent volumes.** `husker volume create data --size 10G` makes a named,
  host-side ext4 disk; `--volume data` on `run`/`job`/`service create` attaches
  it as the VM's second disk (`/dev/vdb` in both boot modes). Volumes survive
  VM destruction, exactly one VM may hold a volume at a time, deletion is
  refused while attached (409), and the service reconciler reattaches the
  volume to replacement instances - stateful services on ephemeral VMs.
- Cloud-image VMs auto-mount an attached volume at `/data` via cloud-init
  (`nofail`); microVM guests mount `/dev/vdb` themselves.
- `husker volume list/delete`, volume display in `info`/`service get`, a
  `volume` profile key, and an `mkfs.ext4` check in `config check`.

## [0.4.3] - 2026-06-10

### Added

- **Cloud-image services.** `husker service create --cloud-image <name|path>`
  runs a self-healing pool of stock cloud-image VMs (with `--disk-size`), no
  custom rootfs needed. A guest that powers itself off is replaced by the
  reconciler; note that under QEMU a guest `reboot` reboots in place, so
  ephemeral-style instances should `poweroff`.
- **Opt-in memory balloon.** `--balloon` on `run`/`job`/`service create`
  attaches a virtio balloon; `husker balloon <vm> <mib>` resizes it at runtime
  (`amount` = MiB reclaimed from the guest, deflate with 0). Supported on
  Firecracker and QEMU; VMs created without the flag get a clear error. The
  microVM initramfs now ships `virtio_balloon` (included in the next images
  release; existing downloaded images need a refresh for ballooning microVMs).
- The service API/CLI surface (`service get`, responses) reports cloud image,
  disk size, and balloon settings; profiles gain a `balloon` key.

## [0.4.2] - 2026-06-10

### Added

- **`husker job` - one-shot VM jobs.** Boot a VM, run a single command, print
  its output, destroy the VM, and exit with the guest command's exit code:
  `husker job --cloud-image ubuntu-2404 -- sh -c 'make test'`. Progress lines
  go to stderr so stdout carries exactly the command's output; `--keep`
  preserves the VM for debugging, Ctrl-C cleans up, and `--output json` emits
  a single structured result.
- **Named VM profiles.** `[profiles.<name>]` sections in the config file
  (cloud_image/rootfs/kernel/initrd/cpus/memory/disk_size/ssh_keys/vmm/env)
  applied with `--profile <name>` on `run` and `job`; explicit flags always
  win. `husker config check` validates each profile.
- **Per-request exec timeouts.** `husker exec --timeout <secs>` (and the job
  default of 3600s) raise the command execution bound beyond the daemon's 30s
  default, clamped by the new `exec_timeout_max_secs` config option (default
  3600, env `HUSKER_EXEC_TIMEOUT_MAX_SECS`).
- **More `/v1/metrics` gauges:** `husker_build_info{version}`,
  `husker_vms_stopped`, `husker_vms_failed`, and per-service
  `husker_service_desired_instances` / `husker_service_current_instances`.

## [0.4.1] - 2026-06-10

### Fixed

- **Guest-initiated shutdown is now detected at runtime.** A guest that powers
  itself off or reboots (an ephemeral CI runner finishing its job, or `poweroff`
  inside a cloud VM) used to leave a defunct VM process and a stale `running`
  state forever; the service reconciler never replaced such instances, so a
  runner pool deadlocked after its first job. The reconciler now verifies each
  instance against the live process (reaping exited children) before deciding,
  and `husker list` / `info` / `wait` report `stopped` instead of lying -
  `wait` on a dead VM fails fast with a clear error rather than polling to its
  timeout. Linux backends (Firecracker/QEMU) only; Apple VZ does not yet detect
  self-terminated guests.

## [0.4.0] - 2026-06-10

### Added

- **Cloud-image boot (UEFI/OVMF).** `husker run --cloud-image <name|path>` boots a
  stock cloud image (e.g. Ubuntu 24.04 qcow2) as a full UEFI VM on the QEMU/KVM
  backend: copy-on-write qcow2 clone, optional `--disk-size 10G` grow (cloud-init
  expands the filesystem on first boot), per-VM OVMF variable store, and the
  image's own bootloader - no custom kernel or rootfs build required.
- **Self-contained cloud-init seed with the husker agent inside.** husker generates
  the NoCloud seed itself (new `husker-cloudinit` crate, no genisoimage/cloud-localds
  dependency) and injects the guest agent plus a static network config, so the whole
  existing control plane - `exec`, `cp`, `shell`, `wait`, `--userdata`, `logs`,
  services - works on cloud VMs unchanged over vsock. The agent is embedded in the
  daemon binary at build time (`make build-with-agent`; release Linux binaries ship
  with it).
- **SSH key injection.** Repeatable `husker run --ssh-key <path.pub>` authorizes
  keys for the image's default user via cloud-init (cloud-image VMs only).
- **Cloud images in the image catalog.** `husker image import <name> --source x.img
  --kind cloud-image` registers a qcow2 image (validated by magic bytes), and
  `--cloud-image <name>` resolves it by name; a direct path still works. Image
  listings and the API now report the image kind.
- **Boot-mode-aware readiness timeouts.** UEFI/cloud VMs boot slower than microVMs,
  so `husker wait`, the exec agent-connect default, and userdata execution now
  default to 180s for them (microVM defaults unchanged).
- **OVMF and disk-size configuration.** New `ovmf_code` / `ovmf_vars` /
  `default_disk_size` config options (env: `HUSKER_OVMF_CODE`, `HUSKER_OVMF_VARS`,
  `HUSKER_DEFAULT_DISK_SIZE`); `husker config check` verifies the OVMF firmware and
  `qemu-img` when relevant.
- `husker info` shows the VM's boot mode, kernel, and source image/rootfs; the
  VM API response carries `boot_mode`, `kernel_path`, and `rootfs_path`.

### Changed

- `kernel_path` / `rootfs_path` in the create-VM API are now optional (required
  only for direct-kernel boot). Cloud VMs persist the resolved source image path
  as provenance instead of fake kernel/rootfs values.

### Fixed

- SSH keys containing control characters are rejected when the seed is built
  (cloud-init YAML injection guard), and invalid keys submitted through the API
  return 400 instead of 500.

## [0.3.2] - 2026-06-09

### Added

- **Configurable CID base** (`cid_base` config / `HUSKER_CID_BASE` env, default 3).
  Two husker daemons on one host can now be given distinct bases so they hand out
  disjoint vsock CIDs and TAP device names, completing multi-daemon coexistence
  alongside the per-bridge nftables tables from 0.3.1.

### Fixed

- **Reap orphaned QEMU processes on daemon startup.** When a daemon exits without
  cleanup (SIGKILL/OOM), the VM processes it left behind are now killed on the
  next start - matched by the persisted pid plus a live `qemu-system` check, so a
  recycled PID is never touched - instead of lingering and holding their vsock CID.

### Changed

- Agent readiness in the QEMU end-to-end test is verified with a real ping/pong
  round trip; `LinuxVsockStream` forwards vectored writes to the inner stream.

## [0.3.1] - 2026-06-09

### Added

- **QEMU/KVM backend (Linux).** A second `VmmBackend` runs full VMs via
  `qemu-system` (q35, virtio-over-PCI, vhost-vsock) alongside Firecracker. Raw
  ext4 rootfs (`format=raw,if=virtio`); the guest kernel must support
  `CONFIG_VIRTIO_PCI`. `husker config check` verifies `qemu_bin`, `/dev/kvm`, and
  `/dev/vhost-vsock` when QEMU is selected.
- **Per-VM backend selection.** One daemon can run Firecracker microVMs and QEMU
  full VMs side by side. `husker run --vmm <firecracker|qemu>` chooses the backend
  per VM (default: the daemon's configured `vmm` / `HUSKER_VMM`); the chosen
  backend is recorded and reported by `husker list` and `husker info`.
- **`husker wait <name>`** blocks until a VM's guest agent is ready, backed by a
  fast `GET /v1/vms/{name}/ready` probe. Agent readiness is verified with a real
  ping/pong round trip and a bounded timeout, so `exec`/`shell` immediately after
  boot no longer race the agent bind.
- **`husker logs --source <serial|boot|userdata>`** selects the log stream
  (default `serial`; `--userdata` retained as an alias).

### Changed

- **nftables tables are namespaced per bridge** (`husker_<bridge>`), so two husker
  daemons on one host no longer clobber each other's NAT.
- On a failed VM boot, the error now includes the tail of the guest serial log and
  the backend boot log (e.g. a kernel panic such as `Cannot open root device`),
  instead of only a generic startup-timeout message. The backend process log is
  standardized as `{id}.boot.log`.

## [0.3.0] - 2026-06-09

### Added

- **Service reconciler.** `husker service` is now a real managed-workload
  primitive. A service carries a VM template, and the daemon keeps
  `desired_instances` VMs running, automatically replacing instances that stop or
  fail. Instances are ordinary VMs named `<service>-<N>` and work with
  `husker list`/`exec`/`logs`/`cp`.
  - `husker service create` takes a full instance template: `--image`/`--rootfs`,
    `--kernel`, `--initrd`, `--vcpus`, `--memory`, `--userdata`, `--env`
    (plus `--instances`, `--host-group`).
  - `husker service scale` (including scale-to-zero to pause a workload) and
    `husker service delete` now create and destroy the underlying VMs.
  - `husker service get` lists each instance's name, ordinal, and state;
    `husker service list` shows running/desired counts.
  - A periodic self-healing reconciler runs in the daemon, configurable via the new
    `[service]` config (`reconcile_interval_secs`, `enabled`) and the
    `HUSKER_SERVICE_RECONCILE_INTERVAL` / `HUSKER_SERVICE_RECONCILE_ENABLED`
    environment variables.
- **Machine-readable CLI contract.** `husker schema` emits the full
  command/argument/output-field/exit-code contract for agent introspection, with
  structured exit codes (1 general, 2 not-found, 3 conflict, 4 denied,
  5 daemon-unreachable; `exec`/`shell` pass through the guest exit code) and a
  stable `code` field in `--output json` errors.
- `husker exec` gains `--env KEY=VALUE` and `--connect-timeout`; `husker run`
  accepts a bare image name; userdata output is captured and viewable with
  `husker logs <vm> --userdata`.
- The guest configures `eth0` from the kernel `ip=` cmdline at boot, and the guest
  agent now reports a clear message when a vsock bind fails due to missing kernel
  modules.
- `husker` warns once when a rootfs clone falls back to a full copy because the
  filesystem lacks reflink/copy-on-write support.

### Fixed

- Serial-log error codes are preserved; the newly structured userdata error codes
  no longer overwrite them.

## [0.2.1] - 2026-06-08

### Fixed

- Destroying a VM that produced no serial output no longer logs a spurious
  "failed to remove serial log" warning during cleanup.

### Internal

- Stabilized the `run_userdata` integration tests under parallel (nextest)
  execution by serializing them across processes, so they no longer
  intermittently clobber a shared host path.

## [0.2.0] - 2026-06-05

### Changed (BREAKING)

- Renamed the project from `shuck` to `husker` (the old name collided with an
  existing shell linter). The binary, crates, Python package, env vars, and
  data directories all change. There is no automatic migration.

  One-time migration for existing installs:

      mv ~/.local/share/shuck ~/.local/share/husker
      mv ~/.config/shuck      ~/.config/husker
      sudo mv /var/lib/shuck  /var/lib/husker      # if used
      sudo mv /etc/shuck      /etc/husker          # if used
      # Linux host networking: drop stale kernel state
      sudo nft delete table ip shuck   # recreated on next run
      sudo ip link del shuck0          # old default bridge, if present
      # systemd: replace contrib/shuck.service with contrib/husker.service

  All `SHUCK_*` environment variables are now `HUSKER_*`.

## [0.1.4] - 2026-04-21

### Added

- `SHUCK_API_URL` environment variable for pointing CLI commands at a
  remote daemon without `--api-url` on every call.
- `shuck run` now logs which kernel, rootfs, and initrd were selected
  before it POSTs to the daemon, making first-run debugging easier.

### Fixed

- `SHUCK_DATA_DIR` now cascades to `default_kernel`, `default_rootfs`,
  and `default_initrd` unless those are set explicitly, so relocating
  the data dir no longer requires overriding four separate variables.
- Linux data dir falls back to the XDG data home (`~/.local/share/shuck`)
  when `/var/lib/shuck` is not writable, so `pip install --user`-style
  flows work without `sudo`.
- Daemon now resolves `firecracker_bin` from `{data_dir}/bin/` when it
  is neither absolute nor on `PATH`, so the auto-installed binary is
  picked up on first run.
- Daemon-connect errors now include the URL and a hint to start the
  daemon, instead of a bare hyper error.
- Exec requests issued right after `shuck run` retry against the guest
  agent with exponential backoff, eliminating the first-boot 503 race.
- Alpine rootfs no longer floods the serial log with `hvc0` open
  errors on Firecracker guests — the getty line now guards on
  `[ -c /dev/hvc0 ]`. Apple VZ guests still get their serial console.

## [0.1.3] - 2026-04-21

### Added

- POSIX installer script: `curl -sSfL https://raw.githubusercontent.com/rvben/shuck/main/install.sh | sh`. Verifies SHA-256, respects `SHUCK_VERSION` and `SHUCK_PREFIX`.
- Homebrew tap publishing: releases now push `rvben/homebrew-tap/Formula/shuck.rb` so `brew install rvben/tap/shuck` works.
- `shuck run` prompts on a TTY to download Firecracker when it's missing from `PATH`; non-interactive callers (CI, scripts) keep using `SHUCK_AUTO_INSTALL_FIRECRACKER=1`.
- `SECURITY.md`, `CONTRIBUTING.md`, issue and pull-request templates; README gains alternatives, security, and troubleshooting sections.

### Fixed

- Compile with `--no-default-features` on Linux: the daemon start path no longer reaches for the macOS-gated `shuck_vmm::apple_vz` module, so `make test-contracts` builds cleanly on Linux.
- Rust 1.95 compatibility: `openpty` winsize pointer uses `addr_of_mut!` to satisfy the `unnecessary_mut_passed` clippy lint without breaking BSD/macOS signatures.
- Graceful-shutdown CI drill: pre-builds the daemon outside the health-check window and pins `RUST_LOG` so the `shuck_api` shutdown log is captured.

## [0.1.2] - 2026-04-21

### Fixed

- `shuck images pull` now resolves the latest `images-YYYY-MM-DD` release via the GitHub API instead of `releases/latest/download`, which GitHub redirects to the highest semver tag and therefore skipped over the image releases once v0.1.1 shipped. Pinning `images_base_url` at a `.../releases/download/<tag>` URL still short-circuits the resolver.

## [0.1.1] - 2026-04-21

### Fixed

- `shuck images pull` (plural) now resolves — the `image` subcommand carries visible aliases `images` and `img`, matching the README and the wording used in `shuck run`'s missing-default-image error hints.

## [0.1.0] - 2026-04-20

First release where `pip install shuck && shuck run` works without bring-your-own kernel or rootfs.

### Added

- `shuck images pull` subcommand that fetches the latest signed kernel, initramfs, and rootfs from the `images-YYYY-MM-DD` GitHub Releases and verifies SHA-256 digests.
- `shuck run` now falls back to the pulled default rootfs, kernel, and initramfs when `--rootfs` is omitted, with actionable hints if they are missing.
- Firecracker auto-install on Linux when `firecracker` isn't on `PATH` — downloads the pinned release tarball into the data dir on first use.
- Arch-aware guest agent + rootfs build pipeline: `make build-agent-aarch64`, arch-suffixed initramfs, and a reproducible Alpine rootfs with `shuck-agent` baked in.
- `build-images.yml` workflow that builds and publishes the default image set monthly (or on manual dispatch).
- `default_rootfs`, `default_initrd`, and `images_base_url` Config fields with env-var overrides.
- API policy controls for exec/file operations (allowlists, denylists, timeouts, payload limits).
- Sensitive endpoint rate limiting and Prometheus-style metrics endpoint.
- Request correlation IDs (`x-request-id`) in API middleware/logs.
- Startup reconciliation for persisted Linux port forwards.
- Shared Firecracker vsock CONNECT handshake helper.
- CLI `--output json` mode for command responses.
- OpenAPI contract tests and perf baseline test.
- Core failure-injection lifecycle tests.
- CI lanes for contracts, coverage, perf baseline, graceful shutdown drill, and gated ignored e2e suites.
- Nightly quality workflow for chaos/perf/soak checks.
- Security, operations, ADR, compatibility, performance, testing, release, and debt register docs.

### Changed

- README quickstart rewritten around `pip install shuck` + `shuck images pull`; BYO kernel/rootfs moved to a secondary section.
- API error envelope standardized with machine-readable fields (`code`, `message`, `hint`, `details`) while retaining `error` alias.
- Log follow handling hardened for truncation/rotation behavior.
- `shuck doctor` strengthened to flag missing default images and kernel/initrd mismatches.
