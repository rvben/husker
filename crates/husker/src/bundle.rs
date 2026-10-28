use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result, ensure};
use husker_agent_proto::frozen_bundle::{FrozenBundle, MAX_BUNDLE_BYTES};

use crate::cli::{BundleAction, OutputFormat};
use crate::cli_contract::structured_output;

pub(crate) fn run(action: BundleAction, output: OutputFormat) -> Result<()> {
    let (command, bundle) = match action {
        BundleAction::Freeze {
            source,
            destination,
        } => {
            let source = source
                .canonicalize()
                .context("resolving source directory")?;
            let parent = destination
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."))
                .canonicalize()
                .context("resolving bundle destination parent")?;
            ensure!(
                !parent.starts_with(&source),
                "bundle destination must be outside the source directory"
            );
            let name = destination
                .file_name()
                .and_then(|name| name.to_str())
                .context("bundle destination requires a UTF-8 filename")?;
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
                .open(&source)
                .context("opening source directory")?;
            let bundle =
                FrozenBundle::freeze_directory(&directory).context("freezing source inputs")?;
            let parent = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
                .open(parent)
                .context("opening destination directory")?;
            bundle
                .write_new_file(&parent, name)
                .context("writing new frozen bundle")?;
            ("bundle freeze", bundle)
        }
        BundleAction::Verify {
            bundle,
            digest,
            size,
        } => {
            ensure!(size <= MAX_BUNDLE_BYTES as u64, "bundle exceeds 32 MiB");
            let mut file: File = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(bundle)
                .context("opening frozen bundle")?;
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_file() && metadata.len() == size,
                "bundle must be a regular file of the expected size"
            );
            let mut bytes = Vec::with_capacity(size as usize);
            (&mut file).take(size + 1).read_to_end(&mut bytes)?;
            ("bundle verify", FrozenBundle::decode(bytes, &digest, size)?)
        }
    };
    let result = structured_output(
        command,
        &serde_json::json!({
            "status": "ok", "version": 1, "digest": bundle.digest(),
            "size_bytes": bundle.bytes().len(), "file_count": bundle.files().len(),
        }),
    )?;
    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        println!(
            "{} ({} bytes, {} files, frozen bundle v1)",
            bundle.digest(),
            bundle.bytes().len(),
            bundle.files().len()
        );
    }
    Ok(())
}
