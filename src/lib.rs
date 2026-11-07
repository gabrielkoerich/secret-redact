//! Find secrets in text and replace each one with `[REDACTED:<rule>]`. The standard rules come
//! from the gitleaks default config with entropy and placeholder checks, strict adds wide patterns

mod rules;

use std::fmt;
use std::sync::LazyLock;

use regex::Regex;

use rules::Spec;

pub use regex::Error;

/// One secret in the text: the rule that found it, its byte range and its line, counted from 1
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// The id of the rule, such as `github-pat`
    pub rule: &'static str,
    /// Byte offset of the first byte of the secret
    pub start: usize,
    /// Byte offset just past the secret
    pub end: usize,
    /// Line of the secret's first byte, counted from 1
    pub line: usize,
}

/// The text with every finding replaced, and the findings in the order they appear
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redacted {
    /// The text with each secret replaced by `[REDACTED:<rule>]`
    pub text: String,
    /// The secrets that were replaced, offsets into the original text
    pub findings: Vec<Finding>,
}

impl Redacted {
    /// One rule id per finding, in order
    pub fn rules(&self) -> Vec<&'static str> {
        self.findings.iter().map(|finding| finding.rule).collect()
    }
}

struct Rule {
    id: &'static str,
    regex: Regex,
    entropy: Option<f64>,
    keywords: &'static [&'static str],
    allow: Vec<Regex>,
}

/// A set of rules. When two matches overlap, the earlier rule names the secret and the
/// replacement covers both
pub struct Redactor {
    rules: Vec<Rule>,
}

impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.rules.iter().map(|rule| rule.id))
            .finish()
    }
}

impl Redactor {
    /// Prefixed tokens, private keys and credentials in URLs, headers and `key = value` lines,
    /// checked for entropy and placeholders so that variables and code stay as they are
    pub fn standard() -> Self {
        Self::from_specs(rules::PREFIXED.iter().chain(rules::CREDENTIALS))
    }

    /// The standard rules, then wide patterns with no entropy or placeholder checks. For text
    /// that must not leave the machine with anything that looks like a secret
    pub fn strict() -> Self {
        Self::from_specs(
            rules::PREFIXED
                .iter()
                .chain(rules::CREDENTIALS)
                .chain(rules::BROAD),
        )
    }

    /// Adds a rule after the others. Capture group 1 is the secret when the pattern has one,
    /// otherwise the whole match
    ///
    /// # Errors
    ///
    /// The pattern is not a valid regex
    pub fn with_rule(mut self, id: &'static str, pattern: &str) -> Result<Self, Error> {
        self.rules.push(Rule {
            id,
            regex: Regex::new(pattern)?,
            entropy: None,
            keywords: &[],
            allow: Vec::new(),
        });
        Ok(self)
    }

    fn from_specs<'a>(specs: impl Iterator<Item = &'a Spec>) -> Self {
        let rules = specs
            .map(|spec| Rule {
                id: spec.id,
                regex: Regex::new(spec.pattern)
                    .unwrap_or_else(|err| panic!("rule {}: {err}", spec.id)),
                entropy: spec.entropy,
                keywords: spec.keywords,
                allow: spec
                    .allow
                    .iter()
                    .map(|pattern| {
                        Regex::new(pattern)
                            .unwrap_or_else(|err| panic!("allow pattern of {}: {err}", spec.id))
                    })
                    .collect(),
            })
            .collect();
        Self { rules }
    }

    /// Every secret in `text`, in the order they appear
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let lower = text.to_ascii_lowercase();
        let mut found: Vec<Finding> = Vec::new();
        for rule in &self.rules {
            if !rule.keywords.is_empty() && !rule.keywords.iter().any(|kw| lower.contains(kw)) {
                continue;
            }

            for cap in rule.regex.captures_iter(text) {
                let Some(secret) = cap.get(1).or_else(|| cap.get(0)) else {
                    continue;
                };
                let value = secret.as_str();
                if value.is_empty() {
                    continue;
                }

                if rule.entropy.is_some_and(|min| shannon(value) < min) {
                    continue;
                }

                if rule.allow.iter().any(|re| re.is_match(value)) {
                    continue;
                }

                let (start, end) = (secret.start(), secret.end());
                // The earlier rule names the secret, and the replaced text covers both matches
                if let Some(f) = found.iter_mut().find(|f| start < f.end && end > f.start) {
                    f.start = f.start.min(start);
                    f.end = f.end.max(end);
                    continue;
                }

                found.push(Finding {
                    rule: rule.id,
                    start,
                    end,
                    line: 0,
                });
            }
        }

        found.sort_by_key(|f| f.start);
        let mut merged: Vec<Finding> = Vec::with_capacity(found.len());
        for finding in found {
            if let Some(last) = merged.last_mut().filter(|last| finding.start < last.end) {
                last.end = last.end.max(finding.end);
                continue;
            }

            merged.push(finding);
        }
        let mut found = merged;
        for finding in &mut found {
            finding.line = text[..finding.start].matches('\n').count() + 1;
        }
        found
    }

    /// `text` with every finding replaced by `[REDACTED:<rule>]`
    pub fn redact(&self, text: &str) -> Redacted {
        let findings = self.scan(text);
        let mut out = text.to_string();
        for finding in findings.iter().rev() {
            out.replace_range(
                finding.start..finding.end,
                &format!("[REDACTED:{}]", finding.rule),
            );
        }
        Redacted {
            text: out,
            findings,
        }
    }

    /// Whether `text` holds at least one secret
    pub fn contains_secret(&self, text: &str) -> bool {
        !self.scan(text).is_empty()
    }
}

/// The standard rules, compiled once
pub fn standard() -> &'static Redactor {
    static STANDARD: LazyLock<Redactor> = LazyLock::new(Redactor::standard);
    &STANDARD
}

/// The strict rules, compiled once
pub fn strict() -> &'static Redactor {
    static STRICT: LazyLock<Redactor> = LazyLock::new(Redactor::strict);
    &STRICT
}

/// [`standard`] redaction of `text`
pub fn redact(text: &str) -> Redacted {
    standard().redact(text)
}

fn shannon(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    let mut n = 0u32;
    for b in data.bytes() {
        counts[usize::from(b)] += 1;
        n += 1;
    }
    let n = f64::from(n);
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Secrets are built at run time, so a gitleaks scan of this repository does not flag them
    fn github_token() -> String {
        format!("ghp_{}", "1A2b3C4d5E6f7G8h9I0j1K2l3M4n5O6p7Q8r")
    }

    fn aws_key() -> String {
        format!("AKIA{}", "DAYHPLK3P2M4N5Q7")
    }

    fn private_key() -> String {
        let kind = "RSA PRIVATE KEY";
        let body = "MIIEowIBAAKCAQEA4fS3V2k9pL0qR7tY8uI1oP2aS3dF4gH5jK6lZ".repeat(2);
        format!("-----BEGIN {kind}-----\n{body}\n-----END {kind}-----\n")
    }

    fn assert_redacts(redactor: &Redactor, line: &str, secret: &str, rule: &str) {
        let out = redactor.redact(line);
        assert!(
            out.rules().contains(&rule),
            "{rule} missed in {line}: {:?}",
            out.rules()
        );
        assert!(!out.text.contains(secret), "{}", out.text);
    }

    fn credential_lines() -> Vec<(String, String, &'static str)> {
        let pass = format!("{}{}", "Dvr9q", "Zx2Lk7");
        let bearer = format!("{}{}", "aB3dE5gH7jK9", "mN1pQ3rS5tU7");
        let jwt = format!(
            "eyJ{}.eyJ{}.{}",
            "hbGciOiJIUzI1NiJ9xx", "zdWIiOiIxMjM0NTY3ODkwIn0x", "dozjgNryP4J3jVmNHl0w5N"
        );
        let tskey = format!("tskey-auth-{}{}", "kQ3x9Lm2", "CNTRL-a8f3K9pLq2");
        let openai = format!("sk-proj-{}", "Ab3Cd5Ef7Gh9Ij1Kl3Mn5Op7Qr9St1Uv3Wx5");
        let telegram = format!("{}:AA{}", "123456789", "Hk3Lm9Pq2Rs7Tv4Wx1Yz6Ab8Cd0Ef5Gh2");
        vec![
            (
                format!("ffmpeg -i rtsp://admin:{pass}@192.168.1.26:554/cam"),
                pass.clone(),
                "url-credentials",
            ),
            (
                format!("curl -H 'Authorization: Bearer {bearer}' https://ha"),
                bearer,
                "authorization-header",
            ),
            (format!("ha token {jwt}"), jwt, "jwt"),
            (
                format!("DVR_PASSWORD={pass}"),
                pass.clone(),
                "secret-assignment",
            ),
            (format!("mysql --password {pass} db"), pass, "password-flag"),
            (format!("TS_AUTHKEY {tskey}"), tskey, "tailscale-auth-key"),
            (format!("key {openai}"), openai, "openai-api-key"),
            (format!("bot {telegram}"), telegram, "telegram-bot-token"),
        ]
    }

    #[test]
    fn rules_compile() {
        assert!(!Redactor::standard().rules.is_empty());
        assert!(Redactor::strict().rules.len() > Redactor::standard().rules.len());
    }

    #[test]
    fn leaves_plain_text_alone() {
        let text = "A note about beans and search ranking.\nAll tests pass.\n";
        for redactor in [standard(), strict()] {
            let out = redactor.redact(text);
            assert_eq!(out.text, text);
            assert!(out.findings.is_empty(), "{:?}", out.rules());
        }
    }

    #[test]
    fn redacts_aws_github_and_private_key_with_lines() {
        let (aws, github, pem) = (aws_key(), github_token(), private_key());
        let body = format!("AWS {aws}\n\nGitHub {github}\n\n{pem}plain text stays.\n");
        let out = redact(&body);
        assert_eq!(
            out.rules(),
            ["aws-access-token", "github-pat", "private-key"]
        );
        assert_eq!(
            out.findings.iter().map(|f| f.line).collect::<Vec<_>>(),
            [1, 3, 5]
        );
        for secret in [&aws, &github, &pem] {
            assert!(!out.text.contains(secret.as_str()), "{}", out.text);
        }
        assert!(out.text.contains("[REDACTED:github-pat]"), "{}", out.text);
        assert!(out.text.contains("plain text stays."), "{}", out.text);
    }

    #[test]
    fn standard_skips_the_aws_example_and_strict_does_not() {
        let example = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let line = format!("AWS_ACCESS_KEY_ID={example}");
        assert!(!standard().contains_secret(&line));
        assert!(strict().contains_secret(&line));
    }

    #[test]
    fn redacts_credentials_with_no_fixed_prefix() {
        for (line, secret, rule) in credential_lines() {
            assert_redacts(standard(), &line, &secret, rule);
        }
    }

    #[test]
    fn keeps_variables_placeholders_and_lookalikes() {
        for line in [
            "rtsp://$U:$P@192.168.1.26:554/cam",
            "https://user:<password>@host/path",
            "the task-retry-loop-that-runs-every-few-minutes-and-more was fixed",
            "token = random_token()?;",
            "password: changeme",
            "export APP_TOKEN=$APP_TOKEN",
            "Authorization: Bearer $TOKEN",
            "token: config.auth.token",
            "api_key = API_KEY_FROM_ENV",
            "token_count = 12345678",
            "ffmpeg --preset=basic averylongpresetname",
            "fn mcp(base: &str, token: Option<&str>)",
            "passbox exec --env GITHUB_TOKEN=github/token -- gh",
            "secret: some-plain-words-here",
        ] {
            let out = standard().redact(line);
            assert_eq!(out.text, line, "{:?}", out.rules());
        }
    }

    #[test]
    fn a_second_pass_changes_nothing() {
        for redactor in [standard(), strict()] {
            for (line, _, _) in credential_lines() {
                let once = redactor.redact(&line).text;
                assert_eq!(redactor.redact(&once).text, once);
            }
        }
    }

    #[test]
    fn with_rule_adds_a_project_token() {
        let redactor = Redactor::standard()
            .with_rule("app-token", r"\b(app_[0-9a-f]{64})\b")
            .unwrap();
        let token = format!("app_{}", "0123456789abcdef".repeat(4));
        assert_redacts(&redactor, &format!("APP {token}"), &token, "app-token");
        assert!(Redactor::standard().with_rule("bad", "(").is_err());
    }

    #[test]
    fn strict_catches_low_confidence_patterns() {
        let password = format!("password = \"{}{}\"", "some_long_config_", "value_16_chars");
        assert!(!standard().contains_secret("password = \"x\""));
        assert!(strict().contains_secret(&password));
        let bearer = format!("Authorization: Bearer {}", "abc.def");
        assert!(strict().contains_secret(&bearer));
        let url = format!("DATABASE_URL=postgres://{}@host:5432/mydb", "user:pass");
        assert!(strict().contains_secret(&url));
        assert!(strict().contains_secret("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ"));
    }

    #[test]
    fn specific_rule_wins_over_a_wider_one_on_the_same_text() {
        let key = format!("sk-ant-api03-{}", "x".repeat(24));
        let out = strict().redact(&format!("ANTHROPIC_API_KEY={key}"));
        assert_eq!(out.rules(), ["anthropic-key"]);
        let token = github_token();
        let out = strict().redact(&format!("export GITHUB_TOKEN={token}"));
        assert_eq!(out.rules(), ["github-pat"]);
    }

    #[test]
    fn overlapping_matches_are_redacted_as_one_span() {
        let url = format!("postgres://user:{}@db.internal:5432/app", "Dvr9qZx2Lk7");
        let out = strict().redact(&format!("DATABASE_URL={url}"));
        assert_eq!(out.rules(), ["url-credentials"]);
        assert_eq!(out.text, "DATABASE_URL=[REDACTED:url-credentials]");
    }

    #[test]
    fn finds_several_secrets_on_one_line() {
        let a = format!("ghp_{}", "a".repeat(36));
        let b = format!("ghp_{}", "b".repeat(36));
        let out = strict().redact(&format!("key1={a} and token2={b}"));
        assert_eq!(out.rules(), ["github-token", "github-token"]);
        assert!(
            !out.text.contains(&a) && !out.text.contains(&b),
            "{}",
            out.text
        );
    }

    #[test]
    fn secrets_in_comments_and_markdown_are_found() {
        let token = github_token();
        for line in [
            format!("// GITHUB_TOKEN={token}"),
            format!("* token: {token}"),
        ] {
            assert!(strict().contains_secret(&line), "{line}");
            assert!(standard().contains_secret(&line), "{line}");
        }
    }
}
