//! Userspace TCP port-forward proxy for backends without host nftables (macOS/VZ).
//!
//! A `PortProxy` binds a host TCP listener per forward and relays each accepted
//! connection to the guest through a `GuestDialer`. The dialer is the seam that
//! isolates the data path: `DirectIpDialer` connects to `guest_ip:guest_port`
//! over the VZ NAT today; a vsock-relay dialer can replace it (Approach B)
//! without touching the accept loop.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use uuid::Uuid;

/// Connects a host-side accept loop to a service inside the guest.
pub trait GuestDialer: Clone + Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static;
    fn dial(
        &self,
        guest_ip: Ipv4Addr,
        guest_port: u16,
    ) -> impl std::future::Future<Output = io::Result<Self::Stream>> + Send;
}

/// Approach A: dial the guest directly over its NAT IP.
#[derive(Clone, Default)]
pub struct DirectIpDialer;

impl GuestDialer for DirectIpDialer {
    type Stream = TcpStream;
    async fn dial(&self, guest_ip: Ipv4Addr, guest_port: u16) -> io::Result<TcpStream> {
        TcpStream::connect(SocketAddr::new(IpAddr::V4(guest_ip), guest_port)).await
    }
}

/// The dialer the daemon uses today. Swapping this alias to a vsock-relay
/// dialer is the only change needed to move to Approach B.
pub type ActiveDialer = DirectIpDialer;

/// One active forward's accept loop. Aborting on drop tears the listener down.
struct Forward {
    handle: JoinHandle<()>,
}

impl Drop for Forward {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Per-VM set of active userspace forwards.
pub struct PortProxy<D: GuestDialer> {
    dialer: D,
    forwards: Mutex<HashMap<Uuid, HashMap<u16, Forward>>>,
}

impl<D: GuestDialer> PortProxy<D> {
    pub fn new(dialer: D) -> Self {
        Self {
            dialer,
            forwards: Mutex::new(HashMap::new()),
        }
    }

    /// Bind a host listener and start relaying. Returns the bound host port
    /// (equal to `host_port` unless `host_port == 0`, which asks the OS to pick).
    pub async fn add(
        &self,
        vm_id: Uuid,
        bind_addr: IpAddr,
        host_port: u16,
        guest_ip: Ipv4Addr,
        guest_port: u16,
    ) -> io::Result<u16> {
        let listener = TcpListener::bind(SocketAddr::new(bind_addr, host_port)).await?;
        let bound = listener.local_addr()?.port();
        let dialer = self.dialer.clone();
        let handle = tokio::spawn(accept_loop(listener, dialer, guest_ip, guest_port));
        self.forwards
            .lock()
            .expect("port proxy mutex poisoned")
            .entry(vm_id)
            .or_default()
            .insert(bound, Forward { handle });
        Ok(bound)
    }

    /// Stop and remove one forward. No-op if absent.
    pub fn stop(&self, vm_id: Uuid, host_port: u16) {
        if let Some(map) = self
            .forwards
            .lock()
            .expect("port proxy mutex poisoned")
            .get_mut(&vm_id)
        {
            map.remove(&host_port); // Drop aborts the task.
        }
    }

    /// Stop and remove all forwards for a VM. No-op if absent.
    pub fn stop_all(&self, vm_id: Uuid) {
        self.forwards
            .lock()
            .expect("port proxy mutex poisoned")
            .remove(&vm_id); // Drop aborts every task.
    }
}

async fn accept_loop<D: GuestDialer>(
    listener: TcpListener,
    dialer: D,
    guest_ip: Ipv4Addr,
    guest_port: u16,
) {
    loop {
        let (mut inbound, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "port-forward accept failed; stopping listener");
                return;
            }
        };
        // Clone the dialer INTO the task so the returned future owns its
        // captures and is `'static` for tokio::spawn.
        let dialer = dialer.clone();
        tokio::spawn(async move {
            match dialer.dial(guest_ip, guest_port).await {
                Ok(mut upstream) => {
                    debug!(%peer, %guest_ip, guest_port, "port-forward connection open");
                    if let Err(e) = tokio::io::copy_bidirectional(&mut inbound, &mut upstream).await
                    {
                        debug!(%peer, error = %e, "port-forward connection closed with error");
                    }
                }
                Err(e) => {
                    warn!(%peer, %guest_ip, guest_port, error = %e, "port-forward dial failed");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A fake "guest": a loopback echo server. Returns its port.
    async fn spawn_echo() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn proxy_relays_bytes_to_guest() {
        let guest_port = spawn_echo().await;
        let proxy = PortProxy::new(DirectIpDialer);
        let vm = Uuid::new_v4();
        let host_port = proxy
            .add(
                vm,
                "127.0.0.1".parse().unwrap(),
                0,
                Ipv4Addr::LOCALHOST,
                guest_port,
            )
            .await
            .unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", host_port)).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn duplicate_host_port_is_conflict() {
        let proxy = PortProxy::new(DirectIpDialer);
        let vm = Uuid::new_v4();
        let port = proxy
            .add(vm, "127.0.0.1".parse().unwrap(), 0, Ipv4Addr::LOCALHOST, 9)
            .await
            .unwrap();
        let err = proxy
            .add(
                vm,
                "127.0.0.1".parse().unwrap(),
                port,
                Ipv4Addr::LOCALHOST,
                9,
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    }

    #[tokio::test]
    async fn stop_all_aborts_listeners() {
        let proxy = PortProxy::new(DirectIpDialer);
        let vm = Uuid::new_v4();
        let port = proxy
            .add(vm, "127.0.0.1".parse().unwrap(), 0, Ipv4Addr::LOCALHOST, 9)
            .await
            .unwrap();
        proxy.stop_all(vm);
        // The task abort is async: the listener socket frees once the runtime
        // drops the cancelled accept loop. Poll briefly for the port to free.
        let mut freed = false;
        for _ in 0..50 {
            if TcpListener::bind(("127.0.0.1", port)).await.is_ok() {
                freed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(freed, "port should be free after stop_all");
    }
}
