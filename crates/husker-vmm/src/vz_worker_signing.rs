//! Read-only macOS static-code validation; never executes the inspected file.
use std::ffi::{c_char, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use crate::VmmError;

type Ref = *const c_void;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecStaticCodeCreateWithPath(path: Ref, flags: u32, code: *mut Ref) -> i32;
    fn SecStaticCodeCheckValidity(code: Ref, flags: u32, requirement: Ref) -> i32;
    fn SecCodeCopySigningInformation(code: Ref, flags: u32, information: *mut Ref) -> i32;
    static kSecCodeInfoEntitlementsDict: Ref;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: Ref,
        buffer: *const u8,
        length: isize,
        is_directory: u8,
    ) -> Ref;
    fn CFStringCreateWithCString(allocator: Ref, text: *const c_char, encoding: u32) -> Ref;
    fn CFRelease(value: Ref);
    fn CFGetTypeID(value: Ref) -> usize;
    fn CFDictionaryGetTypeID() -> usize;
    fn CFBooleanGetTypeID() -> usize;
    fn CFDictionaryGetValue(dictionary: Ref, key: Ref) -> Ref;
    fn CFBooleanGetValue(boolean: Ref) -> u8;
}

struct OwnedRef(Ref);
impl Drop for OwnedRef {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}

fn failure(message: impl std::fmt::Display) -> VmmError {
    VmmError::InvalidConfig(format!("VZ worker code signing: {message}"))
}

pub(crate) fn verify(path: &Path) -> Result<(), VmmError> {
    let bytes = path.as_os_str().as_bytes();
    let length = isize::try_from(bytes.len()).map_err(failure)?;
    // SDK contracts: Create/Copy return retained CF objects; dictionary values
    // are borrowed. Check runtime CF types before passing them to typed APIs.
    // No kSecCSAllowNetworkAccess and no signing mutation or process launch.
    unsafe {
        let url = OwnedRef(CFURLCreateFromFileSystemRepresentation(
            ptr::null(),
            bytes.as_ptr(),
            length,
            0,
        ));
        if url.0.is_null() {
            return Err(failure("cannot represent executable path"));
        }
        let mut code = OwnedRef(ptr::null());
        let status = SecStaticCodeCreateWithPath(url.0, 0, &mut code.0);
        if status != 0 || code.0.is_null() {
            return Err(failure(format!("static code unavailable ({status})")));
        }
        // kSecCSCheckAllArchitectures | kSecCSStrictValidate. Ad-hoc signatures
        // are accepted; a trusted publisher identity is not asserted here.
        let status = SecStaticCodeCheckValidity(code.0, (1 << 0) | (1 << 4), ptr::null());
        if status != 0 {
            return Err(failure(format!("signature validation failed ({status})")));
        }
        let mut information = OwnedRef(ptr::null());
        let status = SecCodeCopySigningInformation(code.0, 1 << 1, &mut information.0);
        if status != 0
            || information.0.is_null()
            || CFGetTypeID(information.0) != CFDictionaryGetTypeID()
        {
            return Err(failure(format!(
                "signing information unavailable ({status})"
            )));
        }
        let entitlements = CFDictionaryGetValue(information.0, kSecCodeInfoEntitlementsDict);
        if entitlements.is_null() || CFGetTypeID(entitlements) != CFDictionaryGetTypeID() {
            return Err(failure("entitlements dictionary unavailable"));
        }
        let key = OwnedRef(CFStringCreateWithCString(
            ptr::null(),
            c"com.apple.security.virtualization".as_ptr(),
            0x0800_0100,
        ));
        if key.0.is_null() {
            return Err(failure("entitlement key unavailable"));
        }
        let value = CFDictionaryGetValue(entitlements, key.0);
        if value.is_null()
            || CFGetTypeID(value) != CFBooleanGetTypeID()
            || CFBooleanGetValue(value) == 0
        {
            return Err(failure(
                "com.apple.security.virtualization must be boolean true",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_fixture_and_missing_path_are_rejected_without_execution() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("never-launched-fixture");
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
        assert!(verify(&path).is_err());
        assert!(verify(&dir.path().join("absent")).is_err());
    }

    #[tokio::test]
    async fn signed_fixture_requires_boolean_entitlement_and_intact_signature() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Stdio;
        use std::time::Duration;
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("never-executed-mach-o");
        let entitlements = dir.path().join("entitlements.plist");
        std::fs::copy("/bin/sleep", &executable).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Copy and locally re-sign a fixture. The inspected Mach-O is never run.
        for (value, accepted) in [
            ("<false/>", false),
            ("<string>true</string>", false),
            ("<true/>", true),
        ] {
            std::fs::write(&entitlements, format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>com.apple.security.virtualization</key>{value}</dict></plist>"
            )).unwrap();
            let mut child = tokio::process::Command::new("/usr/bin/codesign")
                .args(["--force", "--sign", "-", "--entitlements"])
                .arg(&entitlements)
                .arg(&executable)
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let status = match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
                Ok(result) => result.unwrap(),
                Err(_) => {
                    crate::termination::terminate_child(&mut child, "fixture codesign")
                        .await
                        .unwrap();
                    panic!("fixture signing deadline expired");
                }
            };
            assert!(status.success());
            assert_eq!(verify(&executable).is_ok(), accepted);
        }
        let mut bytes = std::fs::read(&executable).unwrap();
        // Preserve the Mach-O header so this tests signed-content integrity,
        // rather than merely rejection of an unrecognizable file format.
        bytes[16 * 1024] ^= 1;
        std::fs::write(&executable, bytes).unwrap();
        assert!(
            verify(&executable)
                .unwrap_err()
                .to_string()
                .contains("signature validation failed")
        );
    }
}
