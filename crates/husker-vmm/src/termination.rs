//! Bounded, confirmed process termination. The caller retains its instance on
//! error or future cancellation; a failed kill is never a cleanup receipt.
use crate::VmmError;

pub(crate) async fn terminate_child(
    child: &mut tokio::process::Child,
    label: &str,
) -> Result<(), VmmError> {
    if child
        .try_wait()
        .map_err(|error| {
            VmmError::ProcessError(format!("inspect {label} before destruction: {error}"))
        })?
        .is_some()
    {
        return Ok(());
    }
    // Tokio kill waits for process exit. A timeout keeps the owned child handle
    // in the instance map so a later cleanup pass can recheck and retry.
    tokio::time::timeout(std::time::Duration::from_secs(5), child.kill())
        .await
        .map_err(|_| {
            VmmError::ProcessError(format!("{label} termination not confirmed within 5s"))
        })?
        .map_err(|error| VmmError::ProcessError(format!("terminate {label}: {error}")))?;
    if child
        .try_wait()
        .map_err(|error| VmmError::ProcessError(format!("confirm {label} exit: {error}")))?
        .is_none()
    {
        return Err(VmmError::ProcessError(format!(
            "{label} remains live after destruction"
        )));
    }
    Ok(())
}

pub(crate) async fn remove_runtime_file(path: &std::path::Path) -> Result<(), VmmError> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(VmmError::ProcessError(format!(
            "remove runtime file {}: {error}",
            path.display()
        ))),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn termination_confirms_live_and_already_exited_children() {
        let mut live = tokio::process::Command::new("/bin/sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        terminate_child(&mut live, "test sleeper").await.unwrap();
        assert!(live.try_wait().unwrap().is_some());
        terminate_child(&mut live, "test sleeper replay")
            .await
            .unwrap();
        let mut exited = tokio::process::Command::new("/usr/bin/true")
            .spawn()
            .unwrap();
        exited.wait().await.unwrap();
        terminate_child(&mut exited, "test exited").await.unwrap();
    }

    #[tokio::test]
    async fn runtime_cleanup_failure_is_explicit_and_retryable() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("runtime");
        tokio::fs::create_dir(&path).await.unwrap();
        assert!(remove_runtime_file(&path).await.is_err());
        assert!(path.is_dir());
        tokio::fs::remove_dir(&path).await.unwrap();
        remove_runtime_file(&path).await.unwrap();
        tokio::fs::write(&path, b"socket placeholder")
            .await
            .unwrap();
        remove_runtime_file(&path).await.unwrap();
        assert!(!path.exists());
    }
}
