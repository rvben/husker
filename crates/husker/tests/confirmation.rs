#![cfg(not(feature = "linux-net"))]
//! The confirmation gate on the real binary, with and without a terminal.
//!
//! `destroy` prompts before it contacts the daemon, so pointing the CLI at a
//! closed loopback port makes the outcome unambiguous: a gate that refuses
//! exits 6 with the matching kind, and a gate that opens reaches the daemon
//! and fails with `daemon_unreachable` instead.

use std::fs::File;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

/// A pseudo-terminal pair. The slave becomes the CLI's stdin so that
/// `is_terminal()` holds; the master is where the test types the answer.
struct Pty {
    master: File,
    slave: File,
}

fn open_pty() -> Pty {
    let mut master = 0;
    let mut slave = 0;
    // SAFETY: openpty writes two descriptors into the provided integers and
    // touches nothing through the null name, termios and winsize pointers.
    // The termios and winsize parameters are `*const` on Linux and `*mut` on
    // macOS; a null `*mut` coerces to either.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: both descriptors were just created and are owned by nothing else.
    unsafe {
        Pty {
            master: File::from_raw_fd(master),
            slave: File::from_raw_fd(slave),
        }
    }
}

fn destroy_command(temp: &TempDir, stdin: Stdio, extra: &[&str]) -> Output {
    let config = temp.path().join("config.toml");
    std::fs::write(&config, "").unwrap();
    Command::new(env!("CARGO_BIN_EXE_husker"))
        .args(["--api-url", "http://127.0.0.1:1", "--config"])
        .arg(&config)
        .args(["destroy", "web"])
        .args(extra)
        .env_remove("HUSKER_CONTEXT")
        .env("HUSKER_CONTEXTS_FILE", temp.path().join("contexts.toml"))
        .env("HUSKER_DATA_DIR", temp.path().join("data"))
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

/// Run `destroy` with a terminal on stdin that already holds `answer`.
fn destroy_answering(answer: &str) -> Output {
    let temp = tempfile::tempdir().unwrap();
    let mut pty = open_pty();
    // The line is queued in the terminal before the CLI starts, so the prompt
    // reads it the moment it asks; the test never races the read.
    pty.master.write_all(answer.as_bytes()).unwrap();
    pty.master.flush().unwrap();
    destroy_command(&temp, Stdio::from(pty.slave), &[])
}

/// The error envelope, which the contract puts on the last line of stderr
/// even when a prompt preceded it.
fn envelope(output: &Output) -> serde_json::Value {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let last = stderr.lines().last().unwrap_or_default();
    serde_json::from_str(last)
        .unwrap_or_else(|_| panic!("the last stderr line is not an envelope:\n{stderr}"))
}

#[test]
fn a_prompt_answered_no_refuses_and_changes_nothing() {
    let output = destroy_answering("n\n");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("[y/N]"), "no prompt was shown:\n{stderr}");
    assert_eq!(output.status.code(), Some(6), "{stderr}");
    let error = &envelope(&output)["error"];
    assert_eq!(error["kind"], "confirmation_declined");
    assert_eq!(
        error["message"],
        "Destroy VM 'web' was not confirmed; nothing was changed"
    );
    assert!(error["hint"].as_str().unwrap().contains("--yes"));
    assert!(output.stdout.is_empty());
}

#[test]
fn an_empty_answer_keeps_the_default_of_no() {
    let output = destroy_answering("\n");
    assert_eq!(output.status.code(), Some(6));
    assert_eq!(envelope(&output)["error"]["kind"], "confirmation_declined");
}

#[test]
fn a_prompt_answered_yes_lets_the_command_proceed() {
    let output = destroy_answering("yes\n");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("[y/N]"), "no prompt was shown:\n{stderr}");
    assert_eq!(output.status.code(), Some(5), "{stderr}");
    assert_eq!(envelope(&output)["error"]["kind"], "daemon_unreachable");
}

#[test]
fn without_a_terminal_the_gate_refuses_instead_of_prompting() {
    let temp = tempfile::tempdir().unwrap();
    let output = destroy_command(&temp, Stdio::null(), &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("[y/N]"),
        "prompted without a terminal:\n{stderr}"
    );
    assert_eq!(output.status.code(), Some(6), "{stderr}");
    let error = &envelope(&output)["error"];
    assert_eq!(error["kind"], "confirmation_required");
    assert!(error["hint"].as_str().unwrap().contains("--yes"));
}

#[test]
fn yes_bypasses_the_gate_entirely() {
    let temp = tempfile::tempdir().unwrap();
    let output = destroy_command(&temp, Stdio::null(), &["--yes"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("[y/N]"),
        "prompted despite --yes:\n{stderr}"
    );
    assert_eq!(output.status.code(), Some(5), "{stderr}");
    assert_eq!(envelope(&output)["error"]["kind"], "daemon_unreachable");
}
