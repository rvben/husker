//! HTTP clients for the downloads the CLI performs on the host: image
//! releases, the Firecracker binary and macOS restore images.

use std::time::Duration;

use anyhow::{Context, Result};

/// Identifies husker to the GitHub API, which rejects requests that carry no
/// User-Agent, and to every other download host.
const USER_AGENT: &str = concat!("husker/", env!("CARGO_PKG_VERSION"));

/// Deadlines for a download.
///
/// There is deliberately no total request timeout: a rootfs or a restore
/// image is hundreds of megabytes or more and its transfer time depends on
/// the link, so only a stall is an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpTimeouts {
    /// Longest wait for a connection to the host.
    pub connect: Duration,
    /// Longest wait for the response headers, and after them for each read of
    /// the body. A peer that stops sending for this long ends the request.
    pub read: Duration,
}

impl Default for HttpTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(30),
            read: Duration::from_secs(60),
        }
    }
}

/// Build a client that applies `timeouts` to every request it makes.
pub fn client(timeouts: HttpTimeouts) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(timeouts.connect)
        .read_timeout(timeouts.read)
        .build()
        .context("building http client")
}
