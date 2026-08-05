//! Reading a file out of a guest VM, in as many requests as it takes.
//!
//! The daemon bounds a single `files/read` response by `max_file_read_bytes`
//! (1 MiB by default), so a file above that size cannot be returned whole. This
//! module asks for it a slice at a time and reassembles it on the host, which is
//! what makes `husker cp vm:path local` and `husker job --out` work on real
//! build artifacts rather than only on small ones.
//!
//! The single rule that keeps reassembly honest: a slice is only a slice if the
//! guest said so. An agent too old for ranged reads ignores `offset`/`len` and
//! answers every request with the start of the file, so a host that assumed its
//! range was honoured would concatenate the same first chunk N times and produce
//! a file of exactly the right length and entirely wrong contents. Such an agent
//! is identified by the absence of `total_size` in its response, and its answer
//! is taken as the complete file (which it is - a legacy agent returns the whole
//! file or fails) rather than as chunk one of several.

use anyhow::Result;

use crate::{ApiFailure, api_error, api_request, with_api_auth};

/// Bytes requested per `files/read` request. The daemon rejects a response
/// larger than `ApiPolicy::max_file_read_bytes` (1 MiB by default) and does not
/// expose that limit to clients through any endpoint, so this is a fixed size
/// comfortably under the default rather than a value probed from the daemon. A
/// file at or under this size still arrives in a single request.
pub(crate) const GUEST_READ_CHUNK_BYTES: u64 = 512 * 1024;

/// Confirm a connected guest agent's reported protocol version can serve a byte
/// range, which reading a file larger than one response depends on. An agent
/// older than [`husker_agent_proto::MIN_PROTOCOL_VERSION_FOR_RANGED_READ`] has
/// no code path for `offset` at all and answers from the start of the file
/// whatever it is asked, so it can only ever deliver a file small enough to fit
/// in one response. Says plainly that the VM's image predates ranged reads,
/// since the fix is to rebuild the image rather than to retry.
pub(crate) fn check_ranged_read_capable(guest_protocol_version: u32) -> Result<(), String> {
    let required = husker_agent_proto::MIN_PROTOCOL_VERSION_FOR_RANGED_READ;
    if guest_protocol_version >= required {
        Ok(())
    } else {
        Err(format!(
            "the file is too large for a single read and this VM's guest agent cannot serve a \
             byte range: it reports protocol version {guest_protocol_version}, but ranged reads \
             require version {required} or newer. The VM's image predates ranged reads in \
             husker-agent; rebuild or re-import the image with a current husker-agent."
        ))
    }
}

/// The result of trying to read a guest file: the bytes, or the reason there are
/// none. Kept distinct from the enclosing `Result`, which is reserved for
/// failures to reach the daemon at all, so that a caller can tell "the daemon
/// answered and said no" from "there was no daemon to ask" - and so the latter
/// still reaches the top-level handler that maps it to the daemon-unreachable
/// exit code.
pub(crate) enum GuestFile {
    /// The complete file.
    Read(Vec<u8>),
    /// The file could not be produced, for the reason carried here. The message
    /// is the daemon's own wherever the daemon supplied one, because a
    /// substituted message is how a real failure gets reported as an absence.
    Failed(ApiFailure),
}

/// Read `path` out of VM `vm` in full, as a sequence of ranged requests when it
/// is larger than one response can carry.
///
/// `Err` means the daemon could not be reached. A daemon that answers with a
/// failure, a guest that cannot serve the file, and a transfer that cannot be
/// completed correctly all come back as [`GuestFile::Failed`] carrying the
/// reason, so no caller has to infer one.
pub(crate) async fn read_guest_file(
    client: &reqwest::Client,
    api_url: &str,
    api_token: Option<&str>,
    vm: &str,
    path: &str,
) -> Result<GuestFile> {
    let mut buf: Vec<u8> = Vec::new();
    // What the first response said about the file, re-checked against every
    // later one: a file rewritten underneath a multi-request transfer would
    // otherwise be reassembled from two different versions of itself. Size
    // alone would miss a replacement of the same length, so the modification
    // time is carried too, and the outer Option is "no response seen yet" so an
    // absent time is never read as an unchanged one.
    let mut expected: Option<(u64, Option<u64>)> = None;

    loop {
        let offset = buf.len() as u64;
        let resp = api_request(
            with_api_auth(
                client.post(format!("{api_url}/v1/vms/{vm}/files/read")),
                api_token,
            )
            .json(&serde_json::json!({
                "path": path,
                "offset": offset,
                "len": GUEST_READ_CHUNK_BYTES,
            })),
        )
        .await?;

        if !resp.status().is_success() {
            let too_large = resp.status() == reqwest::StatusCode::PAYLOAD_TOO_LARGE;
            let failure = api_error(resp, &format!("VM '{vm}'")).await;
            // A bounded request that came back "too large" means the range was
            // not applied. Ask the guest which of the two reasons it is, so the
            // user is told to rebuild a stale image or to raise a policy that
            // sits below one chunk, rather than being left to guess.
            let failure = if too_large && buf.is_empty() {
                explain_oversized_read(client, api_url, api_token, vm, failure).await?
            } else {
                failure
            };
            return Ok(GuestFile::Failed(failure));
        }

        let body: serde_json::Value = resp.json().await?;
        let chunk = match husker_agent_proto::base64_decode(body["data"].as_str().unwrap_or("")) {
            Ok(bytes) => bytes,
            Err(e) => {
                return Ok(GuestFile::Failed(
                    format!("reading {path} from VM '{vm}': invalid base64 in response: {e}")
                        .into(),
                ));
            }
        };
        // Absent rather than zero when the agent predates ranged reads. Reading
        // it as a size would make every such file look empty.
        let total = body["total_size"].as_u64();
        let modified = body["modified_nanos"].as_u64();
        buf.extend_from_slice(&chunk);

        let Some(total) = total else {
            // A legacy agent ignored the range and returned the whole file (it
            // has no other behaviour: anything past its own ceiling is an
            // error, which is handled above). One response is the whole file.
            return Ok(GuestFile::Read(buf));
        };

        match expected {
            None => expected = Some((total, modified)),
            Some((first_total, first_modified)) => {
                // Named separately because the two say different things to
                // whoever reads the error: a size change is a file still being
                // written, a time change at the same size is a file replaced.
                let changed = if first_total != total {
                    Some(format!(
                        "it was {first_total} bytes when the transfer started and is {total} now"
                    ))
                } else if first_modified != modified {
                    Some(
                        "its contents were replaced by the same number of bytes, which its \
                         modification time records even though its size did not change"
                            .to_string(),
                    )
                } else {
                    None
                };
                if let Some(detail) = changed {
                    return Ok(GuestFile::Failed(
                        format!(
                            "reading {path} from VM '{vm}': the file changed while it was being \
                             transferred ({detail}). The copy would have been assembled from two \
                             different versions of the file, so none of it was kept."
                        )
                        .into(),
                    ));
                }
            }
        }

        if buf.len() as u64 >= total {
            buf.truncate(total as usize);
            return Ok(GuestFile::Read(buf));
        }
        if chunk.is_empty() {
            // Short of the reported size with nothing further on offer: looping
            // again would ask the identical question forever.
            return Ok(GuestFile::Failed(
                format!(
                    "reading {path} from VM '{vm}': the guest returned no data at offset \
                     {offset} of a {total}-byte file, so the transfer cannot finish."
                )
                .into(),
            ));
        }
    }
}

/// Turn a "payload too large" refusal of an already-ranged read into the reason
/// it happened, by asking the guest for its protocol version. Either the agent
/// is too old to honour a range (so it returned the whole oversized file), or it
/// honoured the range and the daemon's policy is set below a single chunk. The
/// original failure is returned unchanged if the guest cannot be asked.
async fn explain_oversized_read(
    client: &reqwest::Client,
    api_url: &str,
    api_token: Option<&str>,
    vm: &str,
    failure: ApiFailure,
) -> Result<ApiFailure> {
    let resp = api_request(with_api_auth(
        client.get(format!("{api_url}/v1/vms/{vm}/guest-info")),
        api_token,
    ))
    .await?;
    if !resp.status().is_success() {
        return Ok(failure);
    }
    let info: serde_json::Value = resp.json().await?;
    let version = info["protocol_version"].as_u64().unwrap_or(0) as u32;
    Ok(match check_ranged_read_capable(version) {
        Err(message) => ApiFailure { message, ..failure },
        Ok(()) => ApiFailure {
            hint: Some(format!(
                "husker reads a guest file {GUEST_READ_CHUNK_BYTES} bytes at a time, so the \
                 daemon's max_file_read_bytes policy is below a single chunk; raise it to at \
                 least {GUEST_READ_CHUNK_BYTES}"
            )),
            ..failure
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::extract::Json as ExtractJson;
    use axum::http::StatusCode;
    use axum::routing::{get, post};
    use axum::{Json, Router};

    #[test]
    fn ranged_read_is_refused_below_the_protocol_that_introduced_it() {
        let required = husker_agent_proto::MIN_PROTOCOL_VERSION_FOR_RANGED_READ;
        assert!(check_ranged_read_capable(required).is_ok());
        assert!(check_ranged_read_capable(required + 1).is_ok());
        let err = check_ranged_read_capable(required - 1)
            .expect_err("an agent below the ranged-read protocol must be refused");
        assert!(
            err.contains(&required.to_string()) && err.contains("rebuild"),
            "the message must name the required version and the fix, got: {err}"
        );
    }

    async fn serve_stub(app: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), handle)
    }

    /// A stub `files/read` that serves `content` honouring `offset`/`len`,
    /// counting the requests so a test can prove chunking actually happened.
    fn ranged_file_route(content: Vec<u8>, calls: Arc<AtomicUsize>) -> Router {
        Router::new().route(
            "/v1/vms/{name}/files/read",
            post(move |ExtractJson(req): ExtractJson<serde_json::Value>| {
                let content = content.clone();
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let offset = req["offset"].as_u64().unwrap_or(0) as usize;
                    let len = req["len"].as_u64().unwrap_or(u64::MAX) as usize;
                    let start = offset.min(content.len());
                    let end = start.saturating_add(len).min(content.len());
                    let slice = &content[start..end];
                    Json(serde_json::json!({
                        "data": husker_agent_proto::base64_encode(slice),
                        "size": slice.len(),
                        "total_size": content.len(),
                    }))
                }
            }),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_file_larger_than_one_chunk_is_reassembled_from_several() {
        // Deliberately not a multiple of the chunk size, so a final short chunk
        // is exercised, and byte-varying so a repeated first chunk could not
        // pass as the whole file.
        let content: Vec<u8> = (0..(GUEST_READ_CHUNK_BYTES as usize * 2 + 1234))
            .map(|i| (i % 251) as u8)
            .collect();
        let calls = Arc::new(AtomicUsize::new(0));
        let (api_url, server) = serve_stub(ranged_file_route(content.clone(), calls.clone())).await;

        let client = reqwest::Client::new();
        let got = read_guest_file(&client, &api_url, None, "vm-x", "/artifact.bin")
            .await
            .expect("the stub daemon is reachable");

        match got {
            GuestFile::Read(bytes) => assert_eq!(bytes, content, "reassembled bytes must match"),
            GuestFile::Failed(f) => panic!("expected the file, got failure: {}", f.message),
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "two full chunks plus the remainder"
        );
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_file_within_one_chunk_still_takes_a_single_request() {
        let content = b"small".to_vec();
        let calls = Arc::new(AtomicUsize::new(0));
        let (api_url, server) = serve_stub(ranged_file_route(content.clone(), calls.clone())).await;

        let client = reqwest::Client::new();
        let got = read_guest_file(&client, &api_url, None, "vm-x", "/small.txt")
            .await
            .unwrap();

        match got {
            GuestFile::Read(bytes) => assert_eq!(bytes, content),
            GuestFile::Failed(f) => panic!("expected the file, got failure: {}", f.message),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_legacy_agent_answer_is_taken_as_the_whole_file_not_as_chunk_one() {
        // No total_size, and the range ignored: exactly what an agent predating
        // ranged reads does. Treating it as the first of several chunks would
        // loop, re-requesting the same bytes and concatenating them.
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_route = calls.clone();
        let app = Router::new().route(
            "/v1/vms/{name}/files/read",
            post(move || {
                let calls = calls_route.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!({
                        "data": husker_agent_proto::base64_encode(b"legacy contents"),
                        "size": 15,
                    }))
                }
            }),
        );
        let (api_url, server) = serve_stub(app).await;

        let client = reqwest::Client::new();
        let got = read_guest_file(&client, &api_url, None, "vm-x", "/f")
            .await
            .unwrap();

        match got {
            GuestFile::Read(bytes) => assert_eq!(bytes, b"legacy contents"),
            GuestFile::Failed(f) => panic!("expected the file, got failure: {}", f.message),
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a legacy answer must not be re-requested"
        );
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_file_rewritten_mid_transfer_fails_instead_of_mixing_versions() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_route = calls.clone();
        let chunk = GUEST_READ_CHUNK_BYTES as usize;
        let app = Router::new().route(
            "/v1/vms/{name}/files/read",
            post(move || {
                let calls = calls_route.clone();
                async move {
                    let n = calls.fetch_add(1, Ordering::SeqCst);
                    // The second response claims a different file size.
                    let total = if n == 0 { chunk * 3 } else { chunk * 5 };
                    Json(serde_json::json!({
                        "data": husker_agent_proto::base64_encode(&vec![b'x'; chunk]),
                        "size": chunk,
                        "total_size": total,
                    }))
                }
            }),
        );
        let (api_url, server) = serve_stub(app).await;

        let client = reqwest::Client::new();
        let got = read_guest_file(&client, &api_url, None, "vm-x", "/moving.bin")
            .await
            .unwrap();

        match got {
            GuestFile::Read(_) => panic!("a file that changed size must not be reported as read"),
            GuestFile::Failed(f) => assert!(
                f.message.contains("changed while it was being transferred"),
                "got: {}",
                f.message
            ),
        }
        server.abort();
    }

    /// The size check alone cannot see a file whose replacement happens to be
    /// the same length, and that is the case that corrupts silently: every
    /// chunk is a valid read, the total matches, and the reassembled file is
    /// half of one version and half of another. The modification time is what
    /// makes the replacement visible.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_file_replaced_by_one_of_the_same_size_fails_rather_than_mixing_versions() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_route = calls.clone();
        let chunk = GUEST_READ_CHUNK_BYTES as usize;
        let app = Router::new().route(
            "/v1/vms/{name}/files/read",
            post(move || {
                let calls = calls_route.clone();
                async move {
                    let n = calls.fetch_add(1, Ordering::SeqCst);
                    // Same size throughout; only the contents and the
                    // modification time differ from the second response on.
                    let (byte, modified) = if n == 0 {
                        (b'a', 1_700_000_000_000_000_000u64)
                    } else {
                        (b'b', 1_700_000_009_000_000_000u64)
                    };
                    Json(serde_json::json!({
                        "data": husker_agent_proto::base64_encode(&vec![byte; chunk]),
                        "size": chunk,
                        "total_size": chunk * 3,
                        "modified_nanos": modified,
                    }))
                }
            }),
        );
        let (api_url, server) = serve_stub(app).await;

        let client = reqwest::Client::new();
        let got = read_guest_file(&client, &api_url, None, "vm-x", "/replaced.bin")
            .await
            .unwrap();

        match got {
            GuestFile::Read(_) => {
                panic!("a file replaced mid-transfer must not be reported as read")
            }
            GuestFile::Failed(f) => {
                assert!(
                    f.message.contains("changed while it was being transferred"),
                    "got: {}",
                    f.message
                );
                assert!(
                    f.message.contains("its size did not change"),
                    "the reason must name what changed, not just that something did: {}",
                    f.message
                );
            }
        }
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stalled_transfer_fails_rather_than_looping_forever() {
        // Claims a large file but never returns any bytes for it.
        let app = Router::new().route(
            "/v1/vms/{name}/files/read",
            post(|| async {
                Json(serde_json::json!({ "data": "", "size": 0, "total_size": 4096 }))
            }),
        );
        let (api_url, server) = serve_stub(app).await;

        let client = reqwest::Client::new();
        let got = read_guest_file(&client, &api_url, None, "vm-x", "/stalled.bin")
            .await
            .unwrap();

        match got {
            GuestFile::Read(_) => panic!("an unfinishable transfer must not report success"),
            GuestFile::Failed(f) => {
                assert!(f.message.contains("cannot finish"), "got: {}", f.message)
            }
        }
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn too_large_against_a_legacy_agent_names_the_stale_image() {
        let app = Router::new()
            .route(
                "/v1/vms/{name}/files/read",
                post(|| async {
                    (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        Json(serde_json::json!({
                            "kind": "read_file_too_large",
                            "message": "file exceeds max read size",
                        })),
                    )
                }),
            )
            .route(
                "/v1/vms/{name}/guest-info",
                get(|| async { Json(serde_json::json!({ "protocol_version": 2 })) }),
            );
        let (api_url, server) = serve_stub(app).await;

        let client = reqwest::Client::new();
        let got = read_guest_file(&client, &api_url, None, "vm-x", "/big.bin")
            .await
            .unwrap();

        match got {
            GuestFile::Read(_) => panic!("a refused read must not report success"),
            GuestFile::Failed(f) => assert!(
                f.message.contains("predates ranged reads"),
                "the stale image must be named, got: {}",
                f.message
            ),
        }
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn too_large_against_a_current_agent_points_at_the_policy() {
        let app = Router::new()
            .route(
                "/v1/vms/{name}/files/read",
                post(|| async {
                    (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        Json(serde_json::json!({
                            "kind": "read_file_too_large",
                            "message": "file exceeds max read size",
                        })),
                    )
                }),
            )
            .route(
                "/v1/vms/{name}/guest-info",
                get(|| async {
                    Json(serde_json::json!({
                        "protocol_version": husker_agent_proto::PROTOCOL_VERSION,
                    }))
                }),
            );
        let (api_url, server) = serve_stub(app).await;

        let client = reqwest::Client::new();
        let got = read_guest_file(&client, &api_url, None, "vm-x", "/big.bin")
            .await
            .unwrap();

        match got {
            GuestFile::Read(_) => panic!("a refused read must not report success"),
            GuestFile::Failed(f) => {
                assert!(
                    f.message.contains("max read size"),
                    "the daemon's own message must survive, got: {}",
                    f.message
                );
                assert!(
                    f.hint.as_deref().unwrap_or_default().contains("policy"),
                    "the policy must be named as the fix, got: {:?}",
                    f.hint
                );
            }
        }
        server.abort();
    }
}
