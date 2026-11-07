pub(crate) struct Spec {
    pub id: &'static str,
    pub pattern: &'static str,
    pub entropy: Option<f64>,
    pub keywords: &'static [&'static str],
    pub allow: &'static [&'static str],
}

// Ids and patterns from the gitleaks default config. Assigned-prefix tokens and private keys
pub(crate) const PREFIXED: &[Spec] = &[
    Spec {
        id: "age-secret-key",
        pattern: r"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}",
        entropy: None,
        keywords: &["age-secret-key-1"],
        allow: &[],
    },
    Spec {
        id: "anthropic-admin-api-key",
        pattern: r"\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)\b",
        entropy: None,
        keywords: &["sk-ant-admin01"],
        allow: &[],
    },
    Spec {
        id: "anthropic-api-key",
        pattern: r"\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)\b",
        entropy: None,
        keywords: &["sk-ant-api03"],
        allow: &[],
    },
    Spec {
        id: "aws-access-token",
        pattern: r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b",
        entropy: Some(3.0),
        keywords: &["a3t", "akia", "asia", "abia", "acca"],
        allow: &[r".+EXAMPLE$"],
    },
    Spec {
        id: "gcp-api-key",
        pattern: r"\b(AIza[\w-]{35})\b",
        entropy: Some(4.0),
        keywords: &["aiza"],
        allow: &[],
    },
    Spec {
        id: "github-app-token",
        pattern: r"(?:ghu|ghs)_[0-9a-zA-Z]{36}",
        entropy: Some(3.0),
        keywords: &["ghu_", "ghs_"],
        allow: &[],
    },
    Spec {
        id: "github-fine-grained-pat",
        pattern: r"github_pat_\w{82}",
        entropy: Some(3.0),
        keywords: &["github_pat_"],
        allow: &[],
    },
    Spec {
        id: "github-oauth",
        pattern: r"gho_[0-9a-zA-Z]{36}",
        entropy: Some(3.0),
        keywords: &["gho_"],
        allow: &[],
    },
    Spec {
        id: "github-pat",
        pattern: r"ghp_[0-9a-zA-Z]{36}",
        entropy: Some(3.0),
        keywords: &["ghp_"],
        allow: &[],
    },
    Spec {
        id: "github-refresh-token",
        pattern: r"ghr_[0-9a-zA-Z]{36}",
        entropy: Some(3.0),
        keywords: &["ghr_"],
        allow: &[],
    },
    Spec {
        id: "gitlab-pat",
        pattern: r"glpat-[\w-]{20}",
        entropy: Some(3.0),
        keywords: &["glpat-"],
        allow: &[],
    },
    Spec {
        id: "private-key",
        pattern: r"(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----",
        entropy: None,
        keywords: &["-----begin"],
        allow: &[],
    },
    Spec {
        id: "slack-app-token",
        pattern: r"(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+",
        entropy: Some(2.0),
        keywords: &["xapp"],
        allow: &[],
    },
    Spec {
        id: "slack-bot-token",
        pattern: r"xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        entropy: Some(3.0),
        keywords: &["xoxb"],
        allow: &[],
    },
    Spec {
        id: "slack-user-token",
        pattern: r"xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}",
        entropy: Some(2.0),
        keywords: &["xoxp-", "xoxe-"],
        allow: &[],
    },
];

/// Values that name a secret without being one: shell and template variables, placeholders, a
/// marker an earlier pass left, and code that reads a secret from somewhere else
const PLACEHOLDERS: &[&str] = &[
    r"^\[REDACTED",
    r"^\$",
    r"^<.*>$",
    r"^\{.*\}$",
    r"^\*+$",
    r"(?i)^x{3,}$",
    r"(?i)^(none|null|nil|true|false|undefined|required|optional|redacted|changeme|example|placeholder)$",
    r"(?i)(your|my)[_-]?(api[_-]?)?(token|key|secret|password)",
    r"[()]|::|->",
    r"^[A-Z][A-Z0-9_]{2,}$",
    r"^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)+$",
    r"[<>&\[\]]",
    r"^[a-z0-9._-]*/[a-z0-9._/-]*$",
];

/// `PLACEHOLDERS`, and a value that lacks a letter or a digit, since code and prose fill the
/// `key = value` shape far more often than a credential does
const ASSIGNMENT_ALLOW: &[&str] = &[
    r"^\[REDACTED",
    r"^\$",
    r"^<.*>$",
    r"^\{.*\}$",
    r"^\*+$",
    r"(?i)^x{3,}$",
    r"(?i)^(none|null|nil|true|false|undefined|required|optional|redacted|changeme|example|placeholder)$",
    r"(?i)(your|my)[_-]?(api[_-]?)?(token|key|secret|password)",
    r"[()]|::|->",
    r"^[A-Z][A-Z0-9_]{2,}$",
    r"^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)+$",
    r"[<>&\[\]]",
    r"^[a-z0-9._-]*/[a-z0-9._/-]*$",
    r"^[^0-9]*$",
    r"^[^A-Za-z]*$",
];

// Credentials with no fixed prefix, which reach logs through URLs, headers and config lines
pub(crate) const CREDENTIALS: &[Spec] = &[
    Spec {
        id: "url-credentials",
        pattern: r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:([^\s@/]+)@",
        entropy: None,
        keywords: &["://"],
        allow: PLACEHOLDERS,
    },
    Spec {
        id: "authorization-header",
        pattern: r"(?i)(?:\bbearer|authorization:\s*basic)\s+([A-Za-z0-9._~+/=-]{16,})",
        entropy: Some(3.0),
        keywords: &["bearer", "authorization"],
        allow: PLACEHOLDERS,
    },
    Spec {
        id: "jwt",
        pattern: r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",
        entropy: None,
        keywords: &["eyj"],
        allow: &[],
    },
    Spec {
        id: "secret-assignment",
        pattern: r#"(?i)(?:password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|access[_-]?key|auth[_-]?token|token)\b["']?\s*[:=]\s*["']?([^\s"'`,;]{8,})"#,
        entropy: Some(3.2),
        keywords: &["pass", "pwd", "secret", "key", "token"],
        allow: ASSIGNMENT_ALLOW,
    },
    Spec {
        id: "password-flag",
        pattern: r#"(?i)--(?:password|passwd)[= ]["']?([^\s"']{6,})"#,
        entropy: None,
        keywords: &["--pass"],
        allow: PLACEHOLDERS,
    },
    Spec {
        id: "tailscale-auth-key",
        pattern: r"\b(tskey-[a-z]+-[A-Za-z0-9]{8,}(?:-[A-Za-z0-9]+)?)",
        entropy: None,
        keywords: &["tskey-"],
        allow: &[],
    },
    Spec {
        id: "openai-api-key",
        pattern: r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,})",
        entropy: Some(3.5),
        keywords: &["sk-"],
        allow: &[],
    },
    Spec {
        id: "telegram-bot-token",
        pattern: r"\b(\d{8,10}:AA[A-Za-z0-9_-]{33})\b",
        entropy: None,
        keywords: &[":aa"],
        allow: &[],
    },
];

// Strict only: wide patterns with no entropy or placeholder checks, for text that must never
// leave the machine with anything that looks like a secret. The generic one goes last
pub(crate) const BROAD: &[Spec] = &[
    broad("aws-access-key", r"AKIA[0-9A-Z]{16}"),
    broad(
        "aws-secret-key",
        r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*\S+",
    ),
    broad("github-token", r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    broad("github-fine-grained-token", r"github_pat_[A-Za-z0-9_]{22,}"),
    broad("anthropic-key", r"sk-ant-[A-Za-z0-9\-]{20,}"),
    broad("openai-key", r"sk-[A-Za-z0-9\-]{20,}"),
    broad("slack-token", r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    broad("stripe-key", r"[sr]k_(?:live|test)_[A-Za-z0-9]{20,}"),
    broad("telegram-token", r"\d{8,10}:[A-Za-z0-9_-]{35}"),
    broad(
        "json-web-token",
        r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
    ),
    broad(
        "private-key-header",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    ),
    broad(
        "connection-string",
        r"(?i)(?:postgres|mysql|mongodb|redis)://[^\s]{10,}",
    ),
    broad("bearer-token", r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"),
    broad(
        "generic-secret",
        r#"(?i)(?:password|secret|token|api[_\-]?key)\s*[=:]\s*["']?[A-Za-z0-9+/=_\-]{16,}["']?"#,
    ),
];

const fn broad(id: &'static str, pattern: &'static str) -> Spec {
    Spec {
        id,
        pattern,
        entropy: None,
        keywords: &[],
        allow: &[],
    }
}
