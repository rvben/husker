//! Authorize transport peers BEFORE reading any privileged agent request.
//! Guest-local vsock loopback is not a trusted management connection.
use std::io;

/// VMADDR_CID_HOST = 2. Guest loopback may report CID_LOCAL (1) or the guest's
/// own CID; neither is authorized. There is no permissive fallback for VMMs
/// reporting another identity. Verify the tested VMM/kernel pair live.
pub const fn authorized_vsock_cid(cid: u32) -> bool {
    cid == 2
}

/// Unix sockets are a development transport, restricted to the agent's own
/// effective UID. Failure to obtain kernel peer credentials is a denial.
pub fn authorize_unix_peer(stream: &tokio::net::UnixStream, allowed_uid: u32) -> io::Result<()> {
    if stream.peer_cred()?.uid() == allowed_uid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Unix peer UID differs from agent UID",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_vmm_host_is_authorized() {
        assert!(authorized_vsock_cid(2));
        for cid in [0, 1, 3, 4, 52, 1024, u32::MAX] {
            assert!(!authorized_vsock_cid(cid), "CID {cid}");
        }
    }

    #[tokio::test]
    async fn unix_kernel_peer_credentials_fail_closed_for_other_uid() {
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let uid = unsafe { libc::geteuid() };
        authorize_unix_peer(&server, uid).unwrap();
        let foreign_uid = if uid == 0 { 1000 } else { 0 };
        assert_eq!(
            authorize_unix_peer(&server, foreign_uid)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(client);
    }
}
