//! Runs the `secret-redact` binary on stdin and checks its output and exit status

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn run(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_secret-redact"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(stdin.as_bytes())
        .expect("stdin takes the input");
    child.wait_with_output().expect("the binary exits")
}

fn token() -> String {
    format!("ghp_{}", "1A2b3C4d5E6f7G8h9I0j1K2l3M4n5O6p7Q8r")
}

#[test]
fn redacts_stdin_and_reports_on_stderr() {
    let out = run(&[], &format!("line one\ntoken {}\n", token()));
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "line one\ntoken [REDACTED:github-pat]\n"
    );
    assert_eq!(String::from_utf8(out.stderr).unwrap(), "-:2: github-pat\n");
}

#[test]
fn check_exits_one_on_a_secret_and_zero_on_clean_text() {
    let out = run(&["--check"], &token());
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let out = run(&["--check"], "nothing here\n");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn strict_finds_what_standard_lets_through() {
    let line = "secret: some-plain-words-here-ok\n";
    assert_eq!(run(&["--check"], line).status.code(), Some(0));
    assert_eq!(run(&["--check", "--strict"], line).status.code(), Some(1));
}

#[test]
fn unknown_option_and_missing_file_exit_two() {
    assert_eq!(run(&["--nope"], "").status.code(), Some(2));
    assert_eq!(run(&["/no/such/file"], "").status.code(), Some(2));
}
