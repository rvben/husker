//! Layout of a bounded serial log, shared by the capture that writes it and
//! the readers that follow it across compactions.
//!
//! A log that overflowed its cap starts with a marker line counting every byte
//! of guest output dropped before the retained content, so a reader that knows
//! how much guest output it has already shown can find its place again.

use std::io;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncReadExt, AsyncSeekExt};

const DISCARD_MARKER_PREFIX: &str = "[husker: earlier serial output discarded: ";
const DISCARD_MARKER_SUFFIX: &str = " bytes]\n";
/// The longest marker (a 20-digit count), which a compaction reserves up front.
pub(crate) const DISCARD_MARKER_MAX: usize =
    DISCARD_MARKER_PREFIX.len() + 20 + DISCARD_MARKER_SUFFIX.len();

pub(crate) fn discard_marker(discarded: u64) -> Vec<u8> {
    format!("{DISCARD_MARKER_PREFIX}{discarded}{DISCARD_MARKER_SUFFIX}").into_bytes()
}

/// Where a compaction writes the replacement log before renaming it over
/// `log`. A crash mid-compaction leaves this file behind, so whoever removes
/// the log removes it too.
pub fn compaction_staging_path(log: &Path) -> PathBuf {
    let mut staging = log.as_os_str().to_owned();
    staging.push(".compact");
    staging.into()
}

/// Where a log's retained content sits in the guest's output stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialLogOrigin {
    /// Guest output bytes dropped before the first retained byte.
    pub discarded: u64,
    /// File offset of the first retained byte (the marker's length).
    pub content_offset: u64,
}

impl SerialLogOrigin {
    /// From a log's leading bytes (at least `DISCARD_MARKER_MAX` of them when
    /// the file is that long). `None` means the log starts like a marker that
    /// does not parse, so no position in it can be trusted.
    pub fn parse(head: &[u8]) -> Option<Self> {
        let Some(rest) = head.strip_prefix(DISCARD_MARKER_PREFIX.as_bytes()) else {
            return Some(Self {
                discarded: 0,
                content_offset: 0,
            });
        };
        let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        if !rest[digits..].starts_with(DISCARD_MARKER_SUFFIX.as_bytes()) {
            return None;
        }
        let discarded = std::str::from_utf8(&rest[..digits]).ok()?.parse().ok()?;
        Some(Self {
            discarded,
            content_offset: (DISCARD_MARKER_PREFIX.len() + digits + DISCARD_MARKER_SUFFIX.len())
                as u64,
        })
    }
}

/// One open of a serial log. Every read goes through the same file, so a
/// compaction that lands meanwhile (an atomic rename) cannot tear what is read.
struct Snapshot {
    file: tokio::fs::File,
    origin: SerialLogOrigin,
    inode: u64,
    len: u64,
}

impl Snapshot {
    /// `None` while the log starts with a marker that does not parse.
    async fn open(path: &Path) -> io::Result<Option<Self>> {
        use std::os::unix::fs::MetadataExt;
        let mut file = tokio::fs::File::open(path).await?;
        let metadata = file.metadata().await?;
        let mut head = Vec::with_capacity(DISCARD_MARKER_MAX);
        (&mut file)
            .take(DISCARD_MARKER_MAX as u64)
            .read_to_end(&mut head)
            .await?;
        Ok(SerialLogOrigin::parse(&head).map(|origin| Self {
            file,
            origin,
            inode: metadata.ino(),
            len: metadata.len(),
        }))
    }

    /// Stream position just past the last byte the file held when opened.
    fn end(&self) -> u64 {
        self.origin.discarded + self.len.saturating_sub(self.origin.content_offset)
    }

    /// Up to `len` file bytes from `offset`.
    async fn read_at(&mut self, offset: u64, len: u64) -> io::Result<Vec<u8>> {
        self.file.seek(io::SeekFrom::Start(offset)).await?;
        let mut bytes = Vec::new();
        (&mut self.file).take(len).read_to_end(&mut bytes).await?;
        Ok(bytes)
    }

    /// File bytes from `offset` to the current end.
    async fn read_from_offset(&mut self, offset: u64) -> io::Result<Vec<u8>> {
        self.file.seek(io::SeekFrom::Start(offset)).await?;
        let mut bytes = Vec::new();
        self.file.read_to_end(&mut bytes).await?;
        Ok(bytes)
    }
}

/// How many of the last shown bytes a poll checks are still in place.
const ANCHOR_BYTES: usize = 32;

/// Follows a serial log across compactions by tracking how much of the
/// guest's output stream it has shown, rather than a file offset that a
/// compaction invalidates.
pub struct SerialFollower {
    position: u64,
    inode: u64,
    discarded: u64,
    /// The last shown bytes, which must still precede `position` in the log.
    anchor: Vec<u8>,
}

impl SerialFollower {
    /// Start following at the log's current end. Also returns its last
    /// `preload` bytes as stored (the marker included when within reach) and
    /// whether older bytes were left out.
    pub async fn start(path: &Path, preload: u64) -> io::Result<(Self, Vec<u8>, bool)> {
        let Some(mut snapshot) = Snapshot::open(path).await? else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serial log starts with a malformed discard marker",
            ));
        };
        let offset = snapshot.len.saturating_sub(preload);
        let bytes = snapshot.read_from_offset(offset).await?;
        let read_to = offset + bytes.len() as u64;
        let mut follower = Self {
            position: snapshot.origin.discarded
                + read_to.saturating_sub(snapshot.origin.content_offset),
            inode: snapshot.inode,
            discarded: snapshot.origin.discarded,
            anchor: Vec::new(),
        };
        let content_from = snapshot.origin.content_offset.saturating_sub(offset) as usize;
        follower.remember(&bytes[content_from.min(bytes.len())..]);
        Ok((follower, bytes, offset > 0))
    }

    fn remember(&mut self, shown: &[u8]) {
        self.anchor.extend_from_slice(shown);
        let excess = self.anchor.len().saturating_sub(ANCHOR_BYTES);
        self.anchor.drain(..excess);
    }

    /// Output appended since the previous call, with an inline notice when
    /// the log restarted or output was discarded before it could be shown.
    /// `None` once the log no longer exists.
    pub async fn poll(&mut self, path: &Path) -> io::Result<Option<Vec<u8>>> {
        let mut snapshot = match Snapshot::open(path).await {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => return Ok(Some(Vec::new())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let origin = snapshot.origin;
        // A compaction always discards more, and keeps the bytes just shown
        // unless it discarded past them. Anything else is a new boot's log,
        // even one that reused the old file's inode.
        let mut restarted = snapshot.end() < self.position
            || (snapshot.inode != self.inode && origin.discarded <= self.discarded);
        let anchor_len = self.anchor.len() as u64;
        if !restarted && anchor_len > 0 && self.position >= origin.discarded + anchor_len {
            let offset = origin.content_offset + (self.position - origin.discarded);
            let found = snapshot.read_at(offset - anchor_len, anchor_len).await?;
            restarted = found != self.anchor;
        }
        let mut output = Vec::new();
        if restarted {
            output.extend_from_slice(b"\n[... serial log restarted ...]\n");
            self.position = 0;
            self.anchor.clear();
        }
        if self.position < origin.discarded {
            let missed = origin.discarded - self.position;
            output.extend_from_slice(
                format!("\n[... {missed} serial bytes discarded before they were shown ...]\n")
                    .as_bytes(),
            );
            self.position = origin.discarded;
            self.anchor.clear();
        }
        self.inode = snapshot.inode;
        self.discarded = origin.discarded;
        let offset = origin.content_offset + (self.position - origin.discarded);
        let bytes = snapshot.read_from_offset(offset).await?;
        self.position += bytes.len() as u64;
        self.remember(&bytes);
        output.extend_from_slice(&bytes);
        Ok(Some(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_marker_round_trips_its_count_and_length() {
        for discarded in [0, 7, 4_194_304, u64::MAX] {
            let mut log = discard_marker(discarded);
            let marker_len = log.len();
            assert!(marker_len <= DISCARD_MARKER_MAX);
            log.extend_from_slice(b"retained output\n");
            assert_eq!(
                SerialLogOrigin::parse(&log),
                Some(SerialLogOrigin {
                    discarded,
                    content_offset: marker_len as u64,
                })
            );
        }
    }

    #[test]
    fn an_unmarked_log_starts_at_the_beginning_of_the_output() {
        for head in [
            &b""[..],
            b"Linux version 6.1\n",
            b"[husker: other notice]\n",
        ] {
            assert_eq!(
                SerialLogOrigin::parse(head),
                Some(SerialLogOrigin {
                    discarded: 0,
                    content_offset: 0,
                })
            );
        }
    }

    #[test]
    fn a_malformed_marker_is_not_trusted() {
        for head in [
            &b"[husker: earlier serial output discarded: "[..],
            b"[husker: earlier serial output discarded: 12",
            b"[husker: earlier serial output discarded: x bytes]\n",
            b"[husker: earlier serial output discarded: 99999999999999999999999 bytes]\n",
        ] {
            assert_eq!(SerialLogOrigin::parse(head), None, "{head:?}");
        }
    }
}
