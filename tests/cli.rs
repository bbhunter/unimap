//! Runs the real binary. Nothing here needs network access, root or Nmap.

use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

fn unimap() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_unimap"));
    cmd.stdin(Stdio::null());
    cmd
}

fn run(args: &[&str]) -> Output {
    unimap().args(args).output().expect("failed to run unimap")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn no_arguments_prints_help_and_fails() {
    let o = run(&[]);
    assert!(!o.status.success());
    let text = stdout(&o) + &stderr(&o);
    assert!(text.contains("Usage:"), "{text}");
}

#[test]
fn help_lists_every_flag() {
    let o = run(&["--help"]);
    assert!(o.status.success());
    let text = stdout(&o);
    for flag in [
        "--target",
        "--files",
        "--output",
        "--unique-output",
        "--quiet",
        "--threads",
        "--resolvers",
        "--ports",
        "--min-rate",
        "--fast-scan",
        "--logs-dir",
        "--no-keep-nmap-logs",
        "--raw-output",
        "--url-output",
        "--stdin",
    ] {
        assert!(text.contains(flag), "help is missing {flag}:\n{text}");
    }
}

#[test]
fn version_matches_cargo() {
    let o = run(&["--version"]);
    assert!(o.status.success());
    assert!(stdout(&o).trim().ends_with(env!("CARGO_PKG_VERSION")));
}

#[test]
fn invalid_target_exits_with_error() {
    let o = run(&["-t", "not a valid host"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        stdout(&o).contains("Target is empty or invalid"),
        "{}",
        stdout(&o)
    );
}

#[test]
fn missing_input_file_exits_with_error() {
    let o = run(&["-f", "/nonexistent/unimap-targets.txt"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("Can not open file"), "{}", stdout(&o));
}

#[test]
fn conflicting_flags_are_rejected_by_clap() {
    for args in [
        vec!["-t", "a.com", "-f", "x.txt"],
        vec!["-t", "a.com", "--stdin"],
        vec!["-t", "a.com", "-o", "-u", "x.csv"],
        vec!["-t", "a.com", "-r", "--url-output"],
        vec!["-t", "a.com", "--threads", "0"],
    ] {
        let o = run(&args);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", stderr(&o));
    }
}

#[test]
fn stdin_with_only_invalid_targets_fails() {
    let mut child = unimap()
        .args(["--stdin", "-q"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"localhost\n\nbad host\n")
        .unwrap();
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(
        stdout(&o).contains("Target is empty or invalid"),
        "{}",
        stdout(&o)
    );
}

#[test]
fn missing_nmap_fails_before_resolving() {
    let dir = tempfile::tempdir().unwrap();
    let o = unimap()
        .args([
            "-t",
            "example.com",
            "--logs-dir",
            dir.path().to_str().unwrap(),
        ])
        .env("PATH", "")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    let text = stdout(&o);
    assert!(text.contains("could not execute nmap"), "{text}");
    assert!(!text.contains("Performing parallel resolution"), "{text}");
}

#[test]
fn unwritable_logs_dir_fails() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("a-file");
    std::fs::write(&file, "x").unwrap();
    let o = unimap()
        .args(["-t", "example.com", "--logs-dir", file.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("does not exist"), "{}", stdout(&o));
}

#[test]
fn invalid_resolvers_file_content_fails() {
    let dir = tempfile::tempdir().unwrap();
    let resolvers = dir.path().join("resolvers.txt");
    std::fs::write(&resolvers, "1.1.1.1\nnot-an-ip\n").unwrap();
    let o = unimap()
        .args([
            "-t",
            "example.com",
            "--resolvers",
            resolvers.to_str().unwrap(),
            "--logs-dir",
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("not-an-ip"), "{}", stdout(&o));
}
