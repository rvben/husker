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
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use uuid::Uuid;

#[cfg(feature = "linux-net")]
use crate::ActiveSessionGuard;

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

/// The dialer the daemon uses today on macOS/VZ (no host nftables, so forwards
/// are userspace-proxied). Swapping this alias to a vsock-relay dialer is the
/// only change needed to move to Approach B.
#[cfg(not(feature = "linux-net"))]
pub type ActiveDialer = DirectIpDialer;

/// Wraps an inner dialer with an async "resume the VM first" hook. Implements
/// `GuestDialer` so `PortProxy` calls it transparently: the resume hook is not
/// a `PortProxy` concern (`PortProxy` is generic over `GuestDialer` and cannot
/// see a hook that lives on a concrete dialer). `resume` runs inside `dial()`,
/// before delegating to the inner dialer, so every accepted connection wakes
/// the captured VM (idempotently) before its bytes are relayed.
#[cfg(feature = "linux-net")]
#[derive(Clone)]
pub struct ResumeDialer<D, F> {
    inner: D,
    vm_name: String,
    resume: F,
}

#[cfg(feature = "linux-net")]
impl<D, F, Fut> ResumeDialer<D, F>
where
    D: GuestDialer,
    F: Fn(String) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = io::Result<()>> + Send,
{
    pub fn new(inner: D, vm_name: String, resume: F) -> Self {
        Self {
            inner,
            vm_name,
            resume,
        }
    }
}

#[cfg(feature = "linux-net")]
impl<D, F, Fut> GuestDialer for ResumeDialer<D, F>
where
    D: GuestDialer,
    F: Fn(String) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = io::Result<()>> + Send,
{
    type Stream = D::Stream;

    async fn dial(&self, guest_ip: Ipv4Addr, guest_port: u16) -> io::Result<Self::Stream> {
        (self.resume)(self.vm_name.clone()).await?; // idempotent wake
        self.inner.dial(guest_ip, guest_port).await
    }
}

/// Spawns a guarded relay for one connection drained synchronously from the
/// OS backlog (see `PortProxy::drain_and_close`). Boxed because `Forward`
/// itself is not generic over `GuestDialer`; the closure captures a concrete
/// dialer, the guest target, and the shared session map. Only the Linux
/// resume-listener path drains queued connections on suspend; the macOS
/// plain-forward path (`PortProxy::add`) has no equivalent teardown step.
#[cfg(feature = "linux-net")]
type DrainRelay = Box<dyn Fn(TcpStream, SocketAddr) + Send + Sync>;

/// One active forward's accept loop. Aborting on drop frees the bound host port
/// once every clone of `listener` (this one, and the accept loop's) is gone.
/// Already-accepted relay connections run in their own detached tasks and
/// drain naturally when either side closes - which, for a destroyed VM whose
/// guest is gone, happens immediately.
struct Forward {
    handle: JoinHandle<()>,
    /// Kept alive so `drain_and_close` can poll it synchronously for queued
    /// connections before closing it; only the Linux resume-listener path
    /// (`add_guarded`) reads this, since only it drains on suspend.
    #[cfg(feature = "linux-net")]
    listener: Arc<TcpListener>,
    /// `Some` for forwards created via `add_guarded`, which drains queued
    /// connections through a guarded relay on `drain_and_close`.
    #[cfg(feature = "linux-net")]
    drain_relay: Option<DrainRelay>,
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
    #[cfg(not(feature = "linux-net"))]
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
        let handle = tokio::spawn(accept_loop(
            Arc::new(listener),
            dialer,
            guest_ip,
            guest_port,
        ));
        self.forwards
            .lock()
            .entry(vm_id)
            .or_default()
            .insert(bound, Forward { handle });
        Ok(bound)
    }

    /// Like `add`, but each accepted connection first mints an
    /// `ActiveSessionGuard` (kept for the connection's lifetime) before
    /// awaiting the dialer - which, for a `ResumeDialer`, transparently
    /// resumes the VM. The accept loop spawns a task per connection
    /// immediately so a slow resume never blocks accepting the next one.
    #[cfg(feature = "linux-net")]
    pub async fn add_guarded(
        &self,
        vm_id: Uuid,
        bind_addr: IpAddr,
        host_port: u16,
        guest_ip: Ipv4Addr,
        guest_port: u16,
        sessions: Arc<Mutex<HashMap<Uuid, u64>>>,
    ) -> io::Result<u16> {
        let listener = TcpListener::bind(SocketAddr::new(bind_addr, host_port)).await?;
        let bound = listener.local_addr()?.port();
        let listener = Arc::new(listener);
        let dialer = self.dialer.clone();
        let handle = tokio::spawn(guarded_accept_loop(
            Arc::clone(&listener),
            dialer.clone(),
            guest_ip,
            guest_port,
            vm_id,
            Arc::clone(&sessions),
        ));
        let drain_relay: DrainRelay = Box::new(move |inbound, peer| {
            spawn_guarded_relay(
                inbound,
                peer,
                dialer.clone(),
                guest_ip,
                guest_port,
                vm_id,
                Arc::clone(&sessions),
            );
        });
        self.forwards.lock().entry(vm_id).or_default().insert(
            bound,
            Forward {
                handle,
                listener,
                drain_relay: Some(drain_relay),
            },
        );
        Ok(bound)
    }

    /// Drain up to 128 already-queued connections from `vm_id`'s forwards'
    /// OS backlog into guarded relays, then close their listeners. Used when
    /// suspending a VM: a connection that raced the accept loop right before
    /// teardown still gets serviced instead of being reset. Non-blocking:
    /// polling the listener never awaits, so in-flight relay tasks are never
    /// waited on.
    #[cfg(feature = "linux-net")]
    pub fn drain_and_close(&self, vm_id: Uuid) {
        const DRAIN_CAP: usize = 128;
        let Some(map) = self.forwards.lock().remove(&vm_id) else {
            return;
        };
        for forward in map.into_values() {
            if let Some(relay) = &forward.drain_relay {
                for _ in 0..DRAIN_CAP {
                    match try_accept_now(&forward.listener) {
                        Ok(Some((inbound, peer))) => relay(inbound, peer),
                        Ok(None) => break,
                        Err(e) => {
                            warn!(error = %e, "drain accept failed; stopping drain");
                            break;
                        }
                    }
                }
            }
            // `forward` drops here: `Forward::drop` aborts the accept-loop
            // task, and the listener closes once every `Arc<TcpListener>`
            // clone (ours here, and the aborted task's) is gone.
        }
    }

    /// Stop and remove one forward. No-op if absent.
    #[cfg(not(feature = "linux-net"))]
    pub fn stop(&self, vm_id: Uuid, host_port: u16) {
        if let Some(map) = self.forwards.lock().get_mut(&vm_id) {
            map.remove(&host_port); // Drop aborts the task.
        }
    }

    /// Stop and remove all forwards for a VM. No-op if absent.
    #[cfg(not(feature = "linux-net"))]
    pub fn stop_all(&self, vm_id: Uuid) {
        self.forwards.lock().remove(&vm_id); // Drop aborts every task.
    }
}

/// Type-erased handle to a `PortProxy`, so `HuskerCore` can store one keyed by
/// VM id without naming the concrete `PortProxy<ResumeDialer<D, F>>` type: `F`
/// is an anonymous closure type generated at the call site that constructs
/// the resume hook, and closure types cannot be named in a struct field.
#[cfg(feature = "linux-net")]
pub trait ResumeListenerHandle: Send + Sync {
    /// Drain queued connections then close the listener (see `PortProxy::drain_and_close`).
    fn drain_and_close(&self, vm_id: Uuid);
}

#[cfg(feature = "linux-net")]
impl<D: GuestDialer> ResumeListenerHandle for PortProxy<D> {
    fn drain_and_close(&self, vm_id: Uuid) {
        PortProxy::drain_and_close(self, vm_id);
    }
}

/// Poll `listener` once with a no-op waker: `Ok(Some(_))` if a connection was
/// already queued, `Ok(None)` if the backlog is empty right now. Used by
/// `PortProxy::drain_and_close` to drain synchronously without an executor
/// (tokio's `TcpListener` has no `try_accept`, only `poll_accept`).
#[cfg(feature = "linux-net")]
fn try_accept_now(listener: &TcpListener) -> io::Result<Option<(TcpStream, SocketAddr)>> {
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match listener.poll_accept(&mut cx) {
        std::task::Poll::Ready(Ok(pair)) => Ok(Some(pair)),
        std::task::Poll::Ready(Err(e)) => Err(e),
        std::task::Poll::Pending => Ok(None),
    }
}

#[cfg(not(feature = "linux-net"))]
/// Upper bound on concurrent relay tasks per forward. A client that opens many
/// connections and lets them idle cannot spawn unbounded relay tasks; once the
/// cap is reached the accept loop applies backpressure (new connections wait in
/// the kernel backlog) until an existing relay finishes.
const MAX_CONCURRENT_RELAYS: usize = 512;

#[cfg(not(feature = "linux-net"))]
async fn accept_loop<D: GuestDialer>(
    listener: Arc<TcpListener>,
    dialer: D,
    guest_ip: Ipv4Addr,
    guest_port: u16,
) {
    let relay_slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_RELAYS));
    loop {
        let (mut inbound, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "port-forward accept failed; stopping listener");
                return;
            }
        };
        // Wait for a relay slot before taking on the connection. The permit is
        // held for the connection's lifetime and released when the relay task ends.
        let permit = match Arc::clone(&relay_slots).acquire_owned().await {
            Ok(p) => p,
            Err(_) => return, // semaphore closed: proxy shutting down
        };
        // Clone the dialer INTO the task so the returned future owns its
        // captures and is `'static` for tokio::spawn.
        let dialer = dialer.clone();
        tokio::spawn(async move {
            let _permit = permit;
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

/// Like `accept_loop`, but each accepted connection is relayed through
/// `spawn_guarded_relay` so it holds an `ActiveSessionGuard` for `vm_id` and
/// goes through `dialer.dial()` (a `ResumeDialer` resumes the VM there)
/// rather than being dialed directly in the loop.
#[cfg(feature = "linux-net")]
async fn guarded_accept_loop<D: GuestDialer>(
    listener: Arc<TcpListener>,
    dialer: D,
    guest_ip: Ipv4Addr,
    guest_port: u16,
    vm_id: Uuid,
    sessions: Arc<Mutex<HashMap<Uuid, u64>>>,
) {
    loop {
        let (inbound, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "guarded port-forward accept failed; stopping listener");
                return;
            }
        };
        spawn_guarded_relay(
            inbound,
            peer,
            dialer.clone(),
            guest_ip,
            guest_port,
            vm_id,
            Arc::clone(&sessions),
        );
    }
}

/// Mint an `ActiveSessionGuard` for `vm_id`, then dial and relay one
/// connection in its own task. The guard is held for the connection's full
/// lifetime - including the dialer's resume hook - and drops when the
/// connection closes, releasing the VM's active-session pin.
#[cfg(feature = "linux-net")]
fn spawn_guarded_relay<D: GuestDialer>(
    mut inbound: TcpStream,
    peer: SocketAddr,
    dialer: D,
    guest_ip: Ipv4Addr,
    guest_port: u16,
    vm_id: Uuid,
    sessions: Arc<Mutex<HashMap<Uuid, u64>>>,
) {
    tokio::spawn(async move {
        *sessions.lock().entry(vm_id).or_insert(0) += 1;
        let _guard = ActiveSessionGuard::from_parts(Arc::clone(&sessions), vm_id);
        match dialer.dial(guest_ip, guest_port).await {
            Ok(mut upstream) => {
                debug!(%peer, %guest_ip, guest_port, "guarded port-forward connection open");
                if let Err(e) = tokio::io::copy_bidirectional(&mut inbound, &mut upstream).await {
                    debug!(%peer, error = %e, "guarded port-forward connection closed with error");
                }
            }
            Err(e) => {
                warn!(%peer, %guest_ip, guest_port, error = %e, "guarded port-forward dial failed");
            }
        }
    });
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

    #[cfg(not(feature = "linux-net"))]
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

    #[cfg(not(feature = "linux-net"))]
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

    #[cfg(not(feature = "linux-net"))]
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

    #[cfg(feature = "linux-net")]
    #[tokio::test]
    async fn resume_hook_fires_before_dial_and_guard_is_held() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let guest_port = spawn_echo().await;
        let resumed = Arc::new(AtomicUsize::new(0));
        let sessions = Arc::new(Mutex::new(std::collections::HashMap::<Uuid, u64>::new()));
        let vm = Uuid::new_v4();

        let r = Arc::clone(&resumed);
        let dialer = ResumeDialer::new(DirectIpDialer, "vm".to_string(), move |_name| {
            let r = Arc::clone(&r);
            async move {
                r.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        });
        let proxy = PortProxy::new(dialer);
        let host_port = proxy
            .add_guarded(
                vm,
                "127.0.0.1".parse().unwrap(),
                0,
                Ipv4Addr::LOCALHOST,
                guest_port,
                Arc::clone(&sessions),
            )
            .await
            .unwrap();

        let mut c = TcpStream::connect(("127.0.0.1", host_port)).await.unwrap();
        c.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        assert_eq!(resumed.load(Ordering::SeqCst), 1);
        // The relay holds a guard for the VM while the connection is open.
        assert!(*sessions.lock().get(&vm).unwrap_or(&0) >= 1);
    }

    #[cfg(feature = "linux-net")]
    #[tokio::test]
    async fn drain_and_close_relays_pending_connection_then_frees_port() {
        let guest_port = spawn_echo().await;
        let sessions = Arc::new(Mutex::new(std::collections::HashMap::<Uuid, u64>::new()));
        let vm = Uuid::new_v4();
        let proxy = PortProxy::new(DirectIpDialer);
        let host_port = proxy
            .add_guarded(
                vm,
                "127.0.0.1".parse().unwrap(),
                0,
                Ipv4Addr::LOCALHOST,
                guest_port,
                Arc::clone(&sessions),
            )
            .await
            .unwrap();

        // Connect, then close the forward immediately: whichever of the
        // background accept loop or drain_and_close's own try_accept picks
        // this connection up, it must still be relayed correctly.
        let mut client = TcpStream::connect(("127.0.0.1", host_port)).await.unwrap();
        proxy.drain_and_close(vm);
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        let mut freed = false;
        for _ in 0..50 {
            if TcpListener::bind(("127.0.0.1", host_port)).await.is_ok() {
                freed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(freed, "port should be free after drain_and_close");
    }
}
