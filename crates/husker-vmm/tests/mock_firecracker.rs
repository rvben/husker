//! Integration tests using a mock Firecracker HTTP API server on a Unix socket.
//!
//! This tests the HTTP client flow (request building, response parsing,
//! error handling) without needing a real Firecracker binary.

use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::sync::Mutex;

use husker_vmm::cgroup::CgroupSupervisor;
use husker_vmm::firecracker::FirecrackerBackend;
use husker_vmm::{VmConfig, VmmBackend, VmmError};

fn test_backend(
    bin: impl Into<std::path::PathBuf>,
    dir: impl Into<std::path::PathBuf>,
) -> FirecrackerBackend {
    FirecrackerBackend::new(bin, dir, std::sync::Arc::new(CgroupSupervisor::disabled()))
}

/// State tracked by the mock Firecracker API server.
#[derive(Default)]
struct MockState {
    calls: Vec<(String, String, String)>, // (method, path, body)
}

/// Spawn a mock Firecracker HTTP server on a Unix socket.
async fn spawn_mock_fc() -> (tempfile::TempDir, std::path::PathBuf, Arc<Mutex<MockState>>) {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("mock-fc.sock");

    let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
    let state = Arc::new(Mutex::new(MockState::default()));
    let state_clone = state.clone();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let state = state_clone.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let state = state.clone();
                let _ = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req: Request<hyper::body::Incoming>| {
                            let state = state.clone();
                            async move {
                                use http_body_util::BodyExt;
                                let method = req.method().to_string();
                                let path = req.uri().path().to_string();
                                let body_bytes = req.into_body().collect().await?.to_bytes();
                                let body = String::from_utf8_lossy(&body_bytes).to_string();

                                state.lock().await.calls.push((method, path, body));

                                Ok::<_, hyper::Error>(
                                    Response::builder()
                                        .status(204)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap(),
                                )
                            }
                        }),
                    )
                    .await;
            });
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    (dir, socket_path, state)
}

/// Spawn a mock Firecracker that returns errors with a body.
async fn spawn_error_fc() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("error-fc.sock");

    let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(|_req: Request<hyper::body::Incoming>| async {
                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(400)
                                    .body(Full::new(Bytes::from(
                                        r#"{"fault_message":"Invalid kernel path"}"#,
                                    )))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await;
            });
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    (dir, socket_path)
}

#[tokio::test]
async fn mock_fc_records_api_calls() {
    let (_dir, socket_path, state) = spawn_mock_fc().await;

    let connector = {
        let socket_path = socket_path.clone();
        tower::util::service_fn(move |_: hyper::Uri| {
            let path = socket_path.clone();
            Box::pin(async move {
                let stream = tokio::net::UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            })
        })
    };
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build::<_, Full<Bytes>>(connector);

    let body = serde_json::json!({"kernel_image_path": "/tmp/vmlinux"});
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let req = Request::builder()
        .method("PUT")
        .uri("http://localhost/boot-source")
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body_bytes)))
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), 204);

    let calls = state.lock().await;
    assert_eq!(calls.calls.len(), 1);
    assert_eq!(calls.calls[0].0, "PUT");
    assert_eq!(calls.calls[0].1, "/boot-source");
    assert!(calls.calls[0].2.contains("vmlinux"));
}

#[tokio::test]
async fn mock_fc_error_response_includes_body() {
    let (_dir, socket_path) = spawn_error_fc().await;

    let connector = {
        let socket_path = socket_path.clone();
        tower::util::service_fn(move |_: hyper::Uri| {
            let path = socket_path.clone();
            Box::pin(async move {
                let stream = tokio::net::UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            })
        })
    };
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build::<_, Full<Bytes>>(connector);

    let req = Request::builder()
        .method("PUT")
        .uri("http://localhost/boot-source")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), 400);

    use http_body_util::BodyExt;
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains("Invalid kernel path"),
        "error body should contain detail, got: {body_str}"
    );
}

#[tokio::test]
async fn create_vm_missing_binary() {
    let dir = tempfile::tempdir().unwrap();
    let backend = test_backend("/nonexistent/firecracker", dir.path());

    let id = uuid::Uuid::new_v4();
    let config = VmConfig {
        requested_id: Some(id),
        name: "test".into(),
        vcpu_count: 1,
        mem_size_mib: 128,
        kernel_path: "/tmp/vmlinux".into(),
        rootfs_path: "/tmp/rootfs.ext4".into(),
        kernel_args: None,
        initrd_path: None,
        vsock_cid: 3,
        tap_device: None,
        guest_mac: None,
        vmm: None,
        boot: husker_vmm::BootMode::DirectKernel,
        seed_path: None,
        balloon: false,
        volume_path: None,
        network_disabled: false,
        factory_recovery: false,
        host_shares: Vec::new(),
    };

    let err = backend
        .create_vm(backend.select_backend_for_config(&config).unwrap(), config)
        .await
        .unwrap_err();
    assert!(
        matches!(err, VmmError::ProcessError(ref msg) if msg.contains("spawn firecracker")),
        "expected ProcessError, got: {err}"
    );
    // The spawn failed, so the attempt never published an owner and its abort
    // is positive proof that nothing is left.
    backend.abort_create(id).await.unwrap();
}

/// Verify that the serial log file is cleaned up when create_vm fails
/// due to a missing Firecracker binary.
#[tokio::test]
async fn create_vm_failure_cleans_up_serial_log() {
    let dir = tempfile::tempdir().unwrap();
    let runtime_dir = dir.path().join("run");
    std::fs::create_dir_all(&runtime_dir).unwrap();

    let backend = test_backend("/nonexistent/firecracker", &runtime_dir);

    let config = VmConfig {
        requested_id: None,
        name: "orphan-test".into(),
        vcpu_count: 1,
        mem_size_mib: 128,
        kernel_path: "/tmp/vmlinux".into(),
        rootfs_path: "/tmp/rootfs.ext4".into(),
        kernel_args: None,
        initrd_path: None,
        vsock_cid: 3,
        tap_device: None,
        guest_mac: None,
        vmm: None,
        boot: husker_vmm::BootMode::DirectKernel,
        seed_path: None,
        balloon: false,
        volume_path: None,
        network_disabled: false,
        factory_recovery: false,
        host_shares: Vec::new(),
    };

    let _ = backend
        .create_vm(backend.select_backend_for_config(&config).unwrap(), config)
        .await
        .unwrap_err();

    // No .serial.log files should remain after a failed create
    let serial_logs: Vec<_> = std::fs::read_dir(&runtime_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension().is_some_and(|ext| ext == "log")
                && e.path()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .contains("serial")
        })
        .collect();
    assert!(
        serial_logs.is_empty(),
        "serial log files should be cleaned up on create_vm failure, found: {serial_logs:?}"
    );
}

/// Failed configuration retains a real child and artifacts for confirmed
/// destruction; a cleanup failure keeps that owner available for retry.
#[tokio::test]
async fn create_vm_api_failure_retains_child_and_files_until_confirmed_destroy() {
    let (dir, socket_path) = spawn_error_fc().await;

    let runtime_dir = dir.path().join("run");
    std::fs::create_dir_all(&runtime_dir).unwrap();

    // The wrapper exposes the rejecting mock API and execs a harmless sleeper,
    // so the tracked process has no unowned shell child.
    let wrapper_script = dir.path().join("fake-fc.sh");
    std::fs::write(
        &wrapper_script,
        format!(
            "#!/bin/sh\n\
             # Parse --api-sock argument\n\
             SOCK=\"\"\n\
             while [ $# -gt 0 ]; do\n\
               case \"$1\" in\n\
                 --api-sock) SOCK=\"$2\"; shift 2;;\n\
                 *) shift;;\n\
               esac\n\
             done\n\
             # Symlink the mock FC socket to the expected path\n\
             ln -sf {} \"$SOCK\"\n\
             # Keep running until killed\n\
             exec sleep 60\n",
            socket_path.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wrapper_script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let backend = test_backend(&wrapper_script, &runtime_dir);

    let id = uuid::Uuid::new_v4();
    let config = VmConfig {
        requested_id: Some(id),
        name: "api-fail-test".into(),
        vcpu_count: 1,
        mem_size_mib: 128,
        kernel_path: "/tmp/vmlinux".into(),
        rootfs_path: "/tmp/rootfs.ext4".into(),
        kernel_args: None,
        initrd_path: None,
        vsock_cid: 3,
        tap_device: None,
        guest_mac: None,
        vmm: None,
        boot: husker_vmm::BootMode::DirectKernel,
        seed_path: None,
        balloon: false,
        volume_path: None,
        network_disabled: false,
        factory_recovery: false,
        host_shares: Vec::new(),
    };

    let err = backend
        .create_vm(backend.select_backend_for_config(&config).unwrap(), config)
        .await
        .unwrap_err();
    // Firecracker API failures are wrapped in ProcessError with the original
    // API error message as the prefix (followed by any available diagnostic tails).
    assert!(
        matches!(err, VmmError::ProcessError(_)),
        "expected ProcessError, got: {err}"
    );
    // The original API error detail must appear in the message.
    assert!(
        err.to_string().contains("API error"),
        "ProcessError must contain original API error details, got: {err}"
    );

    let info = backend.vm_info(id).await.unwrap();
    assert_eq!(info.state, husker_vmm::VmState::Failed);
    assert!(info.pid.is_some());
    assert!(runtime_dir.join(format!("{id}.serial.log")).exists());
    assert!(runtime_dir.join(format!("{id}.boot.log")).exists());

    // Aborting the attempt must retain ownership if a runtime path cannot be
    // removed: an unproven cleanup is not proof of absence.
    let obstructed = runtime_dir.join(format!("{id}.vsock"));
    std::fs::create_dir(&obstructed).unwrap();
    assert!(backend.abort_create(id).await.is_err());
    assert!(backend.vm_info(id).await.is_ok());
    assert!(runtime_dir.join(format!("{id}.serial.log")).exists());
    std::fs::remove_dir(&obstructed).unwrap();
    backend.abort_create(id).await.unwrap();
    assert!(matches!(
        backend.vm_info(id).await,
        Err(VmmError::VmNotFound(_))
    ));
    assert!(std::fs::read_dir(&runtime_dir).unwrap().next().is_none());
    // A retried abort after confirmed destruction still proves absence.
    backend.abort_create(id).await.unwrap();
}

#[tokio::test]
async fn cancelled_boot_retains_spawned_child_for_confirmed_destroy() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let runtime_dir = dir.path().join("run");
    let wrapper = dir.path().join("sleeper.sh");
    std::fs::write(&wrapper, "#!/bin/sh\nexec sleep 60\n").unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let backend = Arc::new(test_backend(&wrapper, &runtime_dir));
    let id = uuid::Uuid::new_v4();
    let config = VmConfig {
        requested_id: Some(id),
        name: "cancelled-boot".into(),
        vcpu_count: 1,
        mem_size_mib: 128,
        kernel_path: "/tmp/vmlinux".into(),
        rootfs_path: "/tmp/rootfs.ext4".into(),
        kernel_args: None,
        initrd_path: None,
        vsock_cid: 3,
        tap_device: None,
        guest_mac: None,
        vmm: None,
        boot: husker_vmm::BootMode::DirectKernel,
        seed_path: None,
        balloon: false,
        volume_path: None,
        network_disabled: false,
        factory_recovery: false,
        host_shares: Vec::new(),
    };
    let worker_backend = backend.clone();
    let creation = tokio::spawn(async move {
        worker_backend
            .create_vm(
                worker_backend.select_backend_for_config(&config).unwrap(),
                config,
            )
            .await
    });
    let owned = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if let Ok(info) = backend.vm_info(id).await {
                break info;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(owned.state, husker_vmm::VmState::Creating);
    assert!(owned.pid.is_some());
    creation.abort();
    assert!(creation.await.unwrap_err().is_cancelled());
    assert_eq!(backend.vm_info(id).await.unwrap().pid, owned.pid);
    assert!(runtime_dir.join(format!("{id}.serial.log")).exists());
    backend.destroy_vm(id).await.unwrap();
    assert!(matches!(
        backend.vm_info(id).await,
        Err(VmmError::VmNotFound(_))
    ));
    assert!(std::fs::read_dir(&runtime_dir).unwrap().next().is_none());
}

#[tokio::test]
async fn restore_failure_and_cancellation_retain_child_until_cleanup_retry() {
    use husker_vmm::{RestoreTarget, SnapshotPaths, VmState};
    use std::os::unix::fs::PermissionsExt;
    for cancel in [false, true] {
        let (_mock_dir, mock_socket) = spawn_error_fc().await;
        let dir = tempfile::tempdir().unwrap();
        let runtime = dir.path().join("run");
        let wrapper = dir.path().join("restore-sleeper.sh");
        let expose_api = if cancel {
            String::new()
        } else {
            format!(
                "while [ $# -gt 0 ]; do\ncase \"$1\" in\n--api-sock) socket=\"$2\"; shift 2;;\n*) shift;;\nesac\ndone\nln -s '{}' \"$socket\"\n",
                mock_socket.display()
            )
        };
        std::fs::write(&wrapper, format!("#!/bin/sh\n{expose_api}exec sleep 60\n")).unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
        let backend = Arc::new(test_backend(&wrapper, &runtime));
        let id = uuid::Uuid::new_v4();
        let worker = backend.clone();
        let snapshot = SnapshotPaths::in_dir(dir.path().join("snapshot"));
        let restore = tokio::spawn(async move {
            worker
                .restore_vm(
                    &snapshot,
                    RestoreTarget::Resume {
                        id,
                        name: "restore-ownership".into(),
                        vcpu_count: 1,
                        mem_size_mib: 128,
                        vsock_cid: 3,
                    },
                )
                .await
        });
        if cancel {
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                loop {
                    if let Ok(info) = backend.vm_info(id).await {
                        assert_eq!(info.state, VmState::Creating);
                        assert!(info.pid.is_some());
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            restore.abort();
            assert!(restore.await.unwrap_err().is_cancelled());
        } else {
            let error = tokio::time::timeout(std::time::Duration::from_secs(3), restore)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
            assert!(error.to_string().contains("API error"));
            assert_eq!(backend.vm_info(id).await.unwrap().state, VmState::Failed);
        }
        let owned = backend.vm_info(id).await.unwrap();
        assert!(owned.pid.is_some());
        // A second restore must not overwrite this child or truncate its logs.
        let serial = runtime.join(format!("{id}.serial.log"));
        std::fs::write(&serial, b"retained diagnostics").unwrap();
        assert!(
            backend
                .restore_vm(
                    &SnapshotPaths::in_dir(dir.path().join("other")),
                    RestoreTarget::Resume {
                        id,
                        name: "duplicate".into(),
                        vcpu_count: 1,
                        mem_size_mib: 128,
                        vsock_cid: 4,
                    }
                )
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&serial).unwrap(), b"retained diagnostics");
        assert_eq!(backend.vm_info(id).await.unwrap().pid, owned.pid);
        let obstruction = runtime.join(format!("{id}.vsock"));
        std::fs::create_dir(&obstruction).unwrap();
        assert!(backend.destroy_vm(id).await.is_err());
        assert!(backend.vm_info(id).await.is_ok());
        assert!(serial.exists());
        std::fs::remove_dir(&obstruction).unwrap();
        backend.destroy_vm(id).await.unwrap();
        assert!(matches!(
            backend.vm_info(id).await,
            Err(VmmError::VmNotFound(_))
        ));
        assert!(std::fs::read_dir(&runtime).unwrap().next().is_none());
    }
}
