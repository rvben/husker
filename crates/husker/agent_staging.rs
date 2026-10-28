//! Generated Cargo output must not inherit immutable input permissions.
pub fn stage_agent(destination: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    // Cargo owns OUT_DIR and serializes this build script. Compile-time readers
    // run only after success, so replacing this generated file is safe.
    match std::fs::remove_file(destination) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    std::fs::write(destination, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn staging_replaces_readonly_output_and_preserves_immutable_input() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("pinned-input");
        let destination = dir.path().join("generated-agent.bin");
        std::fs::write(&source, b"pinned bytes").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o400)).unwrap();
        std::fs::copy(&source, &destination).unwrap();
        assert!(destination.metadata().unwrap().permissions().readonly());
        stage_agent(&destination, &std::fs::read(&source).unwrap()).unwrap();
        stage_agent(&destination, b"replacement").unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"replacement");
        stage_agent(&destination, b"").unwrap();
        assert!(std::fs::read(destination).unwrap().is_empty());
        assert_eq!(std::fs::read(&source).unwrap(), b"pinned bytes");
        assert!(source.metadata().unwrap().permissions().readonly());
    }
}
