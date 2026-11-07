# secret-redact

Find secrets in text and replace each one with `[REDACTED:<rule>]`. A Rust crate and a CLI.

```bash
secret-redact < agent.log > clean.log           # redact, one line per secret on stderr
secret-redact --check notes/*.md                # exit 1 when a file holds a secret
secret-redact --check --strict < comment.md     # wide patterns too, for text about to be posted
```

## Rules

| Set | What it finds | Use it for |
|---|---|---|
| standard | Prefixed tokens and private keys from the gitleaks default config, plus credentials in URLs, `Authorization` headers, `--password` flags and `key = value` lines. Entropy and placeholder checks keep `$TOKEN`, `<password>`, `changeme` and code like `token = load_token()` as they are | Text people keep and read: notes, logs, transcripts |
| strict | The standard rules, then wide patterns with no entropy or placeholder checks: any `gh*_` token, `sk-` key, connection string, bearer token or long `password=` value | Text that leaves the machine, such as a GitHub comment |

When two rules match the same text, the earlier rule wins, so a specific rule such as `github-pat` names the secret before a wide one does.

## Library

```rust
let out = secret_redact::redact("token ghp_...");
println!("{}", out.text);                          // token [REDACTED:github-pat]

if secret_redact::strict().contains_secret(body) {
    // do not post it
}

// A project token on top of the standard rules
let redactor = secret_redact::Redactor::standard()
    .with_rule("app-token", r"\b(app_[0-9a-f]{64})\b")?;
```

`scan` returns each finding with its rule, byte range and line. `redact` returns the new text and the findings.

## Install

```bash
cargo install secret-redact
```

## Develop

```bash
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
DYLINT_RUSTFLAGS="-D warnings" cargo dylint --all -- --all-targets
cargo test
```

Tests build their fake secrets at run time, so a gitleaks scan of this repository finds none.
