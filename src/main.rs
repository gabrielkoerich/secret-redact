//! The `secret-redact` command, redacting or checking stdin and files with the crate's rules
#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a CLI writes its text to stdout and its findings and errors to stderr"
)]

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process::ExitCode;

use secret_redact::Redactor;

const USAGE: &str = "usage: secret-redact [--strict] [<file>]
       secret-redact --check [--strict] [<file>...]

Without --check, prints the text of <file> or stdin with every secret replaced by
[REDACTED:<rule>], and one line per secret on stderr.
--check prints one line per secret, <file>:<line>: <rule>, and exits 1 when it finds any.
--strict adds wide patterns with no entropy or placeholder checks.

Exit status: 0 no secret (or redacted), 1 a secret found by --check, 2 an error";

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("secret-redact: {err}");
            ExitCode::from(2)
        }
    }
}

fn run(args: Vec<String>) -> Result<ExitCode, String> {
    let mut strict = false;
    let mut check = false;
    let mut files = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--strict" => strict = true,
            "--check" => check = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(ExitCode::SUCCESS);
            }
            "-V" | "--version" => {
                println!("secret-redact {}", env!("CARGO_PKG_VERSION"));
                return Ok(ExitCode::SUCCESS);
            }
            flag if flag.starts_with('-') && flag != "-" => {
                return Err(format!("unknown option {flag}\n{USAGE}"));
            }
            _ => files.push(arg),
        }
    }

    let redactor = if strict {
        Redactor::strict()
    } else {
        Redactor::standard()
    };
    if files.is_empty() {
        files.push("-".to_string());
    }

    if !check && files.len() > 1 {
        return Err(format!(
            "redacting takes one file, use --check for several\n{USAGE}"
        ));
    }

    let mut found = false;
    let mut stdout = io::stdout().lock();
    for file in &files {
        let text = read(file)?;
        let out = redactor.redact(&text);
        for finding in &out.findings {
            eprintln!("{file}:{}: {}", finding.line, finding.rule);
        }
        found |= !out.findings.is_empty();
        if !check {
            stdout
                .write_all(out.text.as_bytes())
                .map_err(|err| err.to_string())?;
        }
    }

    if check && found {
        return Ok(ExitCode::from(1));
    }

    Ok(ExitCode::SUCCESS)
}

fn read(file: &str) -> Result<String, String> {
    if file == "-" {
        let mut text = String::new();
        io::stdin()
            .read_to_string(&mut text)
            .map_err(|err| format!("stdin: {err}"))?;
        return Ok(text);
    }

    fs::read_to_string(file).map_err(|err| format!("{file}: {err}"))
}
