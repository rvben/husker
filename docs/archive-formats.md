# Archive formats

Husker uses `tar-codec` 0.0.15 to read Firecracker downloads and guest job
outputs. Archive writers and OCI layer application continue to use `tar`.

## Firecracker downloads

The download must match the existing architecture-specific SHA-256 pin before
it is decoded. The compressed download and decompressed tar are each limited
to 64 MiB. GNU and pax archives containing regular files and directories are
accepted. Exactly one nonempty regular file with the expected executable name
must be present. Links, unsafe paths, duplicate executables, malformed later
members, damaged gzip trailers, and data after the archive are errors.

The complete archive is validated before installation. The executable is
written to a temporary file in the destination directory, made executable,
then renamed over the destination. A rejected download leaves the previous
executable intact.

## Guest job outputs

`husker job --out` and write-back outputs accept GNU and pax archives. Paths
remain relative to the destination. Structural tar validation and gzip trailer
validation finish before files are extracted. Invalid paths now fail retrieval
instead of being silently skipped. Unknown pax vendor extensions are rejected
by the decoder's default policy.

The guest output command clears `TAR_OPTIONS` and disables AppleDouble metadata.
On bsdtar it also disables extended attributes, ACLs, and file flags, so macOS
outputs do not require enabling unknown vendor records in the decoder. GNU and
BusyBox tar keep their portable default output formats.

Extraction uses tar-codec's capability-relative filesystem operations.
Contained symbolic links and archive-local hard links are supported, including
guest tar's hard-link deduplication. Existing symbolic-link targets may be used
only when resolution stays beneath the destination. Special files are rejected.
Regular-file contents may overwrite existing outputs. Executable intent is
preserved, with modes normalized through the host umask; archived ownership,
special mode bits, and timestamps are not restored.

The destination must not be modified concurrently during extraction. This is an
overlay operation: a filesystem or link-policy failure during extraction may
leave earlier outputs in place. It is not a transaction over the working tree.
Payload validation streams data rather than retaining expanded files in memory;
the compressed output archive is already held by the guest transfer code.

## OCI layers

OCI layer application is a separate compatibility boundary. It streams gzip
or zstd layers, charges decompressed bytes to one image-wide budget, preserves
permissions, and interprets whiteouts and opaque directories. It also handles
links across a layered filesystem. Generic tar-codec extraction does not apply
these overlay semantics.

OCI remains on its existing reader and confinement checks. Any future reader
replacement must preserve the shared budget, permission behavior, link
resolution, and whiteout ordering, and be exercised against real image layers
and their pax metadata. Replacing its unpack loop with generic extraction would
not establish that compatibility.
