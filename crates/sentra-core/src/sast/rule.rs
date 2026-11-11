//! SAST and Secret Scanning Rule Definitions (REQ-F05, REQ-F07, EXTENSIONS.md).

use serde::{Deserialize, Serialize};

use crate::domain::finding::Severity;

/// Classification category of a static security check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleCategory {
    /// Secrets, credentials, private keys, or API tokens.
    Secret,
    /// SQL injection antipatterns.
    SqlInjection,
    /// OS command injection antipatterns.
    CommandInjection,
    /// Arbitrary dynamic code evaluation (eval / Function).
    DangerousEval,
    /// Unsound or unverified Rust unsafe blocks.
    UnsoundUnsafe,
    /// Path traversal or unvalidated filesystem access.
    PathTraversal,
    /// CI/CD workflow and supply chain security antipatterns.
    CiCdWorkflow,
    /// Authentication, session, and credential verification flaws.
    Authentication,
    /// Cryptographic weaknesses and side-channel timing leaks.
    Cryptographic,
    /// Agent skill, prompt injection, and plugin safety risks.
    AgentSkillSecurity,
    /// Framework and deployment misconfigurations (Django, Laravel, Spring Boot, Firebase).
    Misconfiguration,
    /// Smart contract vulnerabilities and decentralized ledger flaws (Solidity).
    SmartContract,
    /// Server-Side Request Forgery and cloud metadata service abuse.
    Ssrf,
    /// Mass assignment and unvalidated object property modification.
    MassAssignment,
    /// Cross-Site Scripting (XSS) and template unescaping flaws.
    CrossSiteScripting,
    /// Unrestricted resource consumption and denial of service.
    ResourceExhaustion,
}

impl RuleCategory {
    /// Human-readable category label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Secret => "SECRET_LEAK",
            Self::SqlInjection => "SQL_INJECTION",
            Self::CommandInjection => "COMMAND_INJECTION",
            Self::DangerousEval => "DANGEROUS_EVAL",
            Self::UnsoundUnsafe => "UNSOUND_UNSAFE",
            Self::PathTraversal => "PATH_TRAVERSAL",
            Self::CiCdWorkflow => "CICD_WORKFLOW",
            Self::Authentication => "AUTHENTICATION",
            Self::Cryptographic => "CRYPTOGRAPHIC",
            Self::AgentSkillSecurity => "AGENT_SKILL_SECURITY",
            Self::Misconfiguration => "SECURITY_MISCONFIGURATION",
            Self::SmartContract => "SMART_CONTRACT",
            Self::Ssrf => "SSRF",
            Self::MassAssignment => "MASS_ASSIGNMENT",
            Self::CrossSiteScripting => "CROSS_SITE_SCRIPTING",
            Self::ResourceExhaustion => "RESOURCE_EXHAUSTION",
        }
    }
}

/// Static analysis rule descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SastRule {
    /// Stable rule identifier (e.g. `SENTRA-SEC-001`).
    pub id: &'static str,
    /// Concise rule name.
    pub name: &'static str,
    /// Security rule category.
    pub category: RuleCategory,
    /// Default assessed severity.
    pub severity: Severity,
    /// Associated Common Weakness Enumeration (CWE) identifier.
    pub cwe_id: &'static str,
    /// Full description of the risk.
    pub description: &'static str,
    /// Recommended remediation guidance.
    pub recommendation: &'static str,
}

/// Rule registry for built-in SAST and secret scanning checks.
pub static BUILTIN_RULES: &[SastRule] = &[
    SastRule {
        id: "SENTRA-SEC-001",
        name: "AwsAccessKeyId",
        category: RuleCategory::Secret,
        severity: Severity::Critical,
        cwe_id: "CWE-798",
        description: "Hardcoded AWS Access Key ID detected. Embedding cloud credentials in source code enables unauthorized infrastructure compromise.",
        recommendation: "Rotate the leaked key immediately in AWS IAM and load credentials from environment variables, AWS Secrets Manager, or IAM instance profiles.",
    },
    SastRule {
        id: "SENTRA-SEC-002",
        name: "GitHubAccessToken",
        category: RuleCategory::Secret,
        severity: Severity::Critical,
        cwe_id: "CWE-798",
        description: "Hardcoded GitHub Personal Access Token or OAuth token detected. Leaked tokens grant unauthorized access to repositories, organizations, or CI workflows.",
        recommendation: "Revoke the exposed token on GitHub immediately and inject repository access tokens via GitHub Actions secrets or secret managers.",
    },
    SastRule {
        id: "SENTRA-SEC-003",
        name: "PrivateKeyHeader",
        category: RuleCategory::Secret,
        severity: Severity::Critical,
        cwe_id: "CWE-312",
        description: "Unencrypted cryptographic private key block found in source tree. Storing private keys in plaintext compromises cryptographic identity and confidentiality.",
        recommendation: "Remove the private key from source control, revoke the affected key pair, and load keys from secured secret vaults or HSMs.",
    },
    SastRule {
        id: "SENTRA-SEC-004",
        name: "SlackApiToken",
        category: RuleCategory::Secret,
        severity: Severity::High,
        cwe_id: "CWE-798",
        description: "Hardcoded Slack bot or user token detected. Leaked tokens enable unauthorized messaging, workspace data exfiltration, or channel surveillance.",
        recommendation: "Revoke the Slack token via the Slack API portal and pass it through environment variables.",
    },
    SastRule {
        id: "SENTRA-SEC-005",
        name: "HardcodedGenericSecret",
        category: RuleCategory::Secret,
        severity: Severity::High,
        cwe_id: "CWE-798",
        description: "Hardcoded literal assigned to a secret, API key, token, or password identifier. Hardcoded secrets in code files risk exposure across forks, logs, and artifacts.",
        recommendation: "Extract credentials to `.env` (ignored by git) or dedicated configuration stores.",
    },
    SastRule {
        id: "SENTRA-SEC-006",
        name: "AwsSecretAccessKey",
        category: RuleCategory::Secret,
        severity: Severity::Critical,
        cwe_id: "CWE-798",
        description: "Hardcoded AWS Secret Access Key detected: a 40-character key value on a line that names an AWS secret access key. Together with an access key ID it grants the IAM principal's full API access.",
        recommendation: "Deactivate and rotate the key pair in AWS IAM immediately and load credentials from environment variables, AWS Secrets Manager, or IAM roles.",
    },
    SastRule {
        id: "SENTRA-SAST-001",
        name: "SqlInjectionStringInterpolation",
        category: RuleCategory::SqlInjection,
        severity: Severity::Critical,
        cwe_id: "CWE-89",
        description: "SQL query constructed via string formatting, template literals, or string concatenation. Direct string interpolation in SQL statements allows attackers to alter query logic.",
        recommendation: "Use parameterized queries or prepared statements (`$1`, `?`, or ORM query builders) instead of dynamic string concatenation.",
    },
    SastRule {
        id: "SENTRA-SAST-002",
        name: "OsCommandInjection",
        category: RuleCategory::CommandInjection,
        severity: Severity::Critical,
        cwe_id: "CWE-78",
        description: "Shell command execution with interpolated dynamic arguments. Shell wrappers (`sh -c`, `cmd /c`, `exec`) parse metacharacters, allowing arbitrary OS command injection.",
        recommendation: "Pass arguments as discrete elements to `Command::arg(...)` or `execFile` without invoking an intermediate system shell.",
    },
    SastRule {
        id: "SENTRA-SAST-003",
        name: "DangerousEvalExecution",
        category: RuleCategory::DangerousEval,
        severity: Severity::High,
        cwe_id: "CWE-95",
        description: "Dynamic code execution via `eval()`, `new Function()`, or `exec()` detected. Dynamic evaluation permits untrusted strings to execute arbitrary code with full application privileges.",
        recommendation: "Replace dynamic evaluation with static lookup tables, JSON parsers, or safe domain-specific expression interpreters.",
    },
    SastRule {
        id: "SENTRA-SAST-004",
        name: "NakedRustUnsafeBlock",
        category: RuleCategory::UnsoundUnsafe,
        severity: Severity::Medium,
        cwe_id: "CWE-119",
        description: "Rust `unsafe` block without an explicit `// SAFETY:` rationale comment. Per Rust memory-safety guidelines, every unsafe block must document the invariants upheld.",
        recommendation: "Add a comment immediately preceding or inside the block documenting why the unsafe operation is sound (e.g. `// SAFETY: Pointer is non-null and correctly aligned`).",
    },
    SastRule {
        id: "SENTRA-SAST-005",
        name: "InsecurePathTraversal",
        category: RuleCategory::PathTraversal,
        severity: Severity::High,
        cwe_id: "CWE-22",
        description: "Filesystem path constructed directly from unvalidated request parameters. Attackers can supply `..` components to read or overwrite arbitrary host files.",
        recommendation: "Validate and canonicalize all user-supplied paths against a strict root boundary before performing filesystem operations.",
    },
    SastRule {
        id: "SENTRA-TAINT-001",
        name: "SqlInjectionViaTaintFlow",
        category: RuleCategory::SqlInjection,
        severity: Severity::Critical,
        cwe_id: "CWE-89",
        description: "Unsanitized user-controlled input traced from source to database execution sink through data-flow tracking.",
        recommendation: "Use parameterized queries or prepared statements ($1, ?, or ORM methods) and validate/cast inputs before execution.",
    },
    SastRule {
        id: "SENTRA-TAINT-002",
        name: "CommandInjectionViaTaintFlow",
        category: RuleCategory::CommandInjection,
        severity: Severity::Critical,
        cwe_id: "CWE-78",
        description: "Unsanitized user or external input traced to OS process/shell execution sink.",
        recommendation: "Avoid shell invocation; pass arguments as discrete array elements directly to the binary executor.",
    },
    SastRule {
        id: "SENTRA-TAINT-003",
        name: "DynamicCodeEvalViaTaintFlow",
        category: RuleCategory::DangerousEval,
        severity: Severity::Critical,
        cwe_id: "CWE-95",
        description: "Untrusted external data flow reached dynamic code evaluation (eval / Function).",
        recommendation: "Eliminate dynamic code execution in favor of static parser or serialization routines.",
    },
    SastRule {
        id: "SENTRA-TAINT-004",
        name: "PathTraversalViaTaintFlow",
        category: RuleCategory::PathTraversal,
        severity: Severity::High,
        cwe_id: "CWE-22",
        description: "Unsanitized user input traced from source to filesystem path read/write operation.",
        recommendation: "Canonicalize and validate paths against an explicit allowlisted base directory before filesystem access.",
    },
    // CI/CD Workflow & Supply Chain Security (ci-cd-security skill)
    SastRule {
        id: "SENTRA-CICD-001",
        name: "WorkflowPullRequestTargetPwn",
        category: RuleCategory::CiCdWorkflow,
        severity: Severity::Critical,
        cwe_id: "CWE-284",
        description: "GitHub Actions `pull_request_target` trigger detected. This trigger runs in the context of the base repository with read/write tokens and access to secrets, creating a critical pwn-request vector if untrusted PR code is checked out or interpolated.",
        recommendation: "Use the unprivileged `pull_request` trigger instead, or isolate privileged operations into a separate workflow triggered by `workflow_dispatch` with strict reviewer gates.",
    },
    SastRule {
        id: "SENTRA-CICD-002",
        name: "WorkflowScriptTemplateInjection",
        category: RuleCategory::CiCdWorkflow,
        severity: Severity::Critical,
        cwe_id: "CWE-94",
        description: "GitHub Actions expression `${{ github.event... }}` or `${{ github.head_ref }}` interpolated directly into a `run:` script block. Attackers can control PR titles, branch names, or issue comments to execute arbitrary shell commands.",
        recommendation: "Pass untrusted GitHub event contexts via intermediate environment variables (e.g. `env: PR_TITLE: ${{ github.event.pull_request.title }}`) and reference the variable in shell scripts via `$PR_TITLE`.",
    },
    SastRule {
        id: "SENTRA-CICD-003",
        name: "WorkflowPermissivePermissions",
        category: RuleCategory::CiCdWorkflow,
        severity: Severity::High,
        cwe_id: "CWE-272",
        description: "GitHub Actions workflow configured with `permissions: write-all` or missing top-level restrictive permissions. Overly permissive GITHUB_TOKEN permissions violate the principle of least privilege.",
        recommendation: "Declare `permissions: {}` at the top level and grant only required granular scopes (e.g. `contents: read`) per individual job.",
    },
    SastRule {
        id: "SENTRA-CICD-004",
        name: "WorkflowEnvFileInjection",
        category: RuleCategory::CiCdWorkflow,
        severity: Severity::High,
        cwe_id: "CWE-94",
        description: "Untrusted expression interpolated directly into environment file write operation (`>> $GITHUB_ENV` or `>> $GITHUB_OUTPUT`). Attackers can inject newlines to override environment variables or workflow outputs.",
        recommendation: "Use delimiter syntax or sanitize multi-line user inputs before appending to GitHub environment files.",
    },
    // Authentication & Cryptographic Hygiene (auth-implementation-patterns & golang-security skills)
    SastRule {
        id: "SENTRA-AUTH-001",
        name: "TimingAttackInSecretComparison",
        category: RuleCategory::Cryptographic,
        severity: Severity::High,
        cwe_id: "CWE-208",
        description: "Direct equality comparison (`===` or `==`) used on cryptographic hashes, API tokens, or HMAC signatures. Variable-time comparison leaks information through byte-by-byte timing discrepancies.",
        recommendation: "Use constant-time comparison routines such as `crypto.timingSafeEqual` in Node/Bun, `crypto/subtle.ConstantTimeCompare` in Go, or `subtle::ConstantTimeEq` in Rust.",
    },
    SastRule {
        id: "SENTRA-AUTH-002",
        name: "InsecureJwtNoneAlgorithm",
        category: RuleCategory::Authentication,
        severity: Severity::Critical,
        cwe_id: "CWE-327",
        description: "JWT configuration permits the unauthenticated `none` algorithm or explicitly disables signature verification (`verify: false`). This allows attackers to forge arbitrary authentication tokens.",
        recommendation: "Enforce strict algorithm allowlists (e.g. `['HS256', 'RS256']`) and reject unverified tokens unconditionally.",
    },
    SastRule {
        id: "SENTRA-AUTH-003",
        name: "WeakPasswordHashAlgorithm",
        category: RuleCategory::Cryptographic,
        severity: Severity::High,
        cwe_id: "CWE-328",
        description: "Obsolete or broken cryptographic hash function (`MD5` or `SHA-1`) used for password hashing or credential verification. These algorithms are vulnerable to collision and fast pre-image attacks.",
        recommendation: "Upgrade to memory-hard password hashing algorithms such as Argon2id or bcrypt with adaptive work factors.",
    },
    // AI Agent & Plugin Safety (skill-security skill)
    SastRule {
        id: "SENTRA-SKILL-001",
        name: "AgentPromptInjectionBypass",
        category: RuleCategory::AgentSkillSecurity,
        severity: Severity::High,
        cwe_id: "CWE-693",
        description: "Prompt injection or guardrail override directive detected in agent instructions or skill definition (e.g. 'ignore previous instructions', 'system prompt override', or 'mark as safe').",
        recommendation: "Isolate untrusted data from system prompts, treat external skills as untrusted input, and enforce deterministic policy verification before executing agent-requested actions.",
    },
    SastRule {
        id: "SENTRA-SKILL-002",
        name: "AgentCredentialHarvester",
        category: RuleCategory::AgentSkillSecurity,
        severity: Severity::Critical,
        cwe_id: "CWE-552",
        description: "Agent skill or plugin instruction attempting to harvest environment variables, API secrets, or credentials for unauthorized egress or telemetry.",
        recommendation: "Deny agent tools access to host environment files (`.env`, `process.env`), isolate worker execution within bounded sandboxes, and redact sensitive variables.",
    },
    // Go Path Traversal Scoping (golang-security skill)
    SastRule {
        id: "SENTRA-GO-001",
        name: "InsecureFilePathClean",
        category: RuleCategory::PathTraversal,
        severity: Severity::High,
        cwe_id: "CWE-22",
        description: "Go `filepath.Clean()` used on untrusted path input without verifying root directory enclosure. `filepath.Clean` removes lexical dot-dots but does not prevent filesystem root escape.",
        recommendation: "In Go 1.24+, use `os.Root` for scoped filesystem operations. In earlier versions, verify containment using `filepath.Rel` and explicit path prefix boundary checks.",
    },
    // Django Framework Security (django-security skill)
    SastRule {
        id: "SENTRA-DJANGO-001",
        name: "DjangoDebugTrueInProduction",
        category: RuleCategory::Misconfiguration,
        severity: Severity::Critical,
        cwe_id: "CWE-200",
        description: "Django `DEBUG = True` detected. Running with debug mode enabled discloses full stack traces, environment variables, local file paths, and database query parameters upon errors.",
        recommendation: "Set `DEBUG = False` in production environments and source configuration from environment variables (e.g. `DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'`).",
    },
    SastRule {
        id: "SENTRA-DJANGO-002",
        name: "DjangoWildcardAllowedHosts",
        category: RuleCategory::Misconfiguration,
        severity: Severity::High,
        cwe_id: "CWE-346",
        description: "Django `ALLOWED_HOSTS = ['*']` wildcard host validation detected. Wildcard host headers allow HTTP Host header poisoning, password reset token theft, and cache poisoning.",
        recommendation: "Explicitly allowlist only verified domain names and subdomains in `ALLOWED_HOSTS`.",
    },
    SastRule {
        id: "SENTRA-DJANGO-003",
        name: "DjangoCsrfExemptBypass",
        category: RuleCategory::Misconfiguration,
        severity: Severity::High,
        cwe_id: "CWE-352",
        description: "Django `@csrf_exempt` decorator applied to view. Disabling CSRF protection allows third-party origins to forge cross-site state-changing requests.",
        recommendation: "Remove `@csrf_exempt` and pass CSRF tokens via headers (`X-CSRFToken`) or cookies (`CSRF_COOKIE_HTTPONLY = False` with SameSite=Lax).",
    },
    // Laravel Framework Security (laravel-security skill)
    SastRule {
        id: "SENTRA-LARAVEL-001",
        name: "LaravelDebugModeEnabled",
        category: RuleCategory::Misconfiguration,
        severity: Severity::Critical,
        cwe_id: "CWE-200",
        description: "Laravel `APP_DEBUG=true` detected. Debug mode exposes Ignition or Whoops error pages with full system environment variables, database passwords, and API secrets.",
        recommendation: "Set `APP_DEBUG=false` in `.env` and production configuration files.",
    },
    SastRule {
        id: "SENTRA-LARAVEL-002",
        name: "LaravelMassAssignmentUnguarded",
        category: RuleCategory::Misconfiguration,
        severity: Severity::High,
        cwe_id: "CWE-915",
        description: "Laravel model defines `protected $guarded = []` disabling mass assignment protection. Attackers can overwrite sensitive attributes such as `is_admin` or `role`.",
        recommendation: "Use `$fillable` allowlists or specify guarded attributes explicitly (e.g. `protected $guarded = ['id', 'is_admin']`).",
    },
    // Spring Boot Security (springboot-security skill)
    SastRule {
        id: "SENTRA-SPRING-001",
        name: "SpringBootOverlyPermissiveCors",
        category: RuleCategory::Misconfiguration,
        severity: Severity::High,
        cwe_id: "CWE-942",
        description: "Spring Boot CORS configured with wildcard origin `.allowedOrigins(\"*\")` while allowing credentials (`allowCredentials(true)`). This combination allows arbitrary web origins to read authenticated responses.",
        recommendation: "Specify explicit trusted origins using `.allowedOriginPatterns(...)` and avoid combining wildcards with credentials.",
    },
    SastRule {
        id: "SENTRA-SPRING-002",
        name: "SpringBootActuatorExposure",
        category: RuleCategory::Misconfiguration,
        severity: Severity::High,
        cwe_id: "CWE-200",
        description: "Spring Boot Actuator endpoints exposed broadly via `management.endpoints.web.exposure.include=*`. Actuators can leak heap dumps, environment properties, and thread dumps.",
        recommendation: "Limit exposed actuator endpoints to `health,info` and require authentication for sensitive diagnostics.",
    },
    // Firebase Security Rules (firebase-security-rules-auditor skill)
    SastRule {
        id: "SENTRA-FIREBASE-001",
        name: "FirebasePermissiveRule",
        category: RuleCategory::Misconfiguration,
        severity: Severity::Critical,
        cwe_id: "CWE-284",
        description: "Firebase security rule configured with `allow read, write: if true;`. This grants unauthenticated public read/write access to the entire database or storage bucket.",
        recommendation: "Enforce user authentication (e.g. `allow read, write: if request.auth != null;`) and validate role-based resource ownership.",
    },
    // Solidity Smart Contract Security (solidity-security skill)
    SastRule {
        id: "SENTRA-SOLIDITY-001",
        name: "SolidityTxOriginAuth",
        category: RuleCategory::SmartContract,
        severity: Severity::Critical,
        cwe_id: "CWE-287",
        description: "Solidity smart contract uses `tx.origin` for authorization instead of `msg.sender`. Phishing contracts can intermediate transactions and trick users into authorizing unintended actions.",
        recommendation: "Replace `tx.origin` with `msg.sender` for authorization checks.",
    },
    SastRule {
        id: "SENTRA-SOLIDITY-002",
        name: "SolidityReentrancyExternalCall",
        category: RuleCategory::SmartContract,
        severity: Severity::High,
        cwe_id: "CWE-841",
        description: "Solidity low-level call `.call{value:` executed without adhering to Checks-Effects-Interactions (CEI) pattern or ReentrancyGuard. Attackers can re-enter the contract before state balances update.",
        recommendation: "Update internal balances before initiating external Ether transfers (Checks-Effects-Interactions) or guard the function with OpenZeppelin `ReentrancyGuard`.",
    },
    // CI/CD Action Pinning (ci-cd-security skill)
    SastRule {
        id: "SENTRA-CICD-005",
        name: "WorkflowUnpinnedActionBranchRef",
        category: RuleCategory::CiCdWorkflow,
        severity: Severity::Medium,
        cwe_id: "CWE-829",
        description: "GitHub Actions workflow references an action via a mutable branch (e.g. `@main`, `@master`, `@dev`) instead of an immutable 40-character commit SHA. Upstream branch updates flow into CI runs immediately without operator review.",
        recommendation: "Pin action references to immutable commit SHAs with an inline tag comment (e.g. `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`).",
    },
    // Go Injection & Crypto Safety (golang-security skill)
    SastRule {
        id: "SENTRA-GO-002",
        name: "GoCommandInjectionShellWrapper",
        category: RuleCategory::CommandInjection,
        severity: Severity::Critical,
        cwe_id: "CWE-78",
        description: "Go process execution invokes shell wrappers `exec.Command(\"sh\", \"-c\", ...)` or `exec.Command(\"bash\", \"-c\", ...)` with dynamic or formatted arguments. This enables arbitrary shell command injection.",
        recommendation: "Execute binaries directly without shell interpreters (e.g. `exec.Command(\"git\", \"log\", arg)`), passing arguments as discrete slice elements.",
    },
    SastRule {
        id: "SENTRA-GO-003",
        name: "GoSqlInjectionFormattedQuery",
        category: RuleCategory::SqlInjection,
        severity: Severity::Critical,
        cwe_id: "CWE-89",
        description: "Go SQL query dynamically formatted with `fmt.Sprintf` or string concatenation into `db.Query`, `db.Exec`, or `db.QueryRow`. Unsanitized user parameters allow SQL injection.",
        recommendation: "Use parameterized queries with placeholder bindings (e.g. `db.Query(\"SELECT * FROM users WHERE id = $1\", userID)`).",
    },
    SastRule {
        id: "SENTRA-GO-004",
        name: "GoWeakCryptoOrPrng",
        category: RuleCategory::Cryptographic,
        severity: Severity::Medium,
        cwe_id: "CWE-338",
        description: "Go code uses `math/rand` or `crypto/md5` in security-sensitive or token generation contexts. `math/rand` is predictable and `md5` is vulnerable to collisions.",
        recommendation: "Use `crypto/rand` for token and nonce generation, and `crypto/sha256` or `golang.org/x/crypto` for secure cryptographic hashing.",
    },
    // Authentication, Cookies & JWT (auth-implementation-patterns skill)
    SastRule {
        id: "SENTRA-AUTH-004",
        name: "InsecureCookieFlags",
        category: RuleCategory::Authentication,
        severity: Severity::Medium,
        cwe_id: "CWE-614",
        description: "Session or authentication cookie configured with `httpOnly: false`, `secure: false`, or `sameSite: 'none'` without `secure`. This exposes cookies to XSS exfiltration and network sniffing.",
        recommendation: "Always set `httpOnly: true`, `secure: true`, and `sameSite: 'lax'` or `'strict'` on sensitive cookies.",
    },
    SastRule {
        id: "SENTRA-AUTH-005",
        name: "HardcodedJwtSecretKey",
        category: RuleCategory::Secret,
        severity: Severity::High,
        cwe_id: "CWE-798",
        description: "Hardcoded, predictable, or trivial symmetric secret used for JWT signing/verification (e.g. 'secret', 'jwt_secret', 'shhhhh'). Attackers can forge arbitrary JWT authentication claims.",
        recommendation: "Load cryptographically random JWT signing keys (minimum 256 bits) from secure environment variables or a secret vault.",
    },
    // Cloud SSRF & Metadata Security (google-cloud-waf-security skill)
    SastRule {
        id: "SENTRA-CLOUD-001",
        name: "CloudMetadataServiceSsrfTarget",
        category: RuleCategory::Ssrf,
        severity: Severity::High,
        cwe_id: "CWE-918",
        description: "Hardcoded or dynamically targeted cloud instance metadata endpoint (`169.254.169.254` or `metadata.google.internal`). In SSRF scenarios, this exposes cloud instance identity credentials and tokens.",
        recommendation: "Block link-local addresses (`169.254.0.0/16`) in outgoing HTTP clients, validate destination IPs against allowlists, and enforce IMDSv2 / Metadata-Flavor headers.",
    },
    // API Security & Mass Assignment (api-security-testing skill)
    SastRule {
        id: "SENTRA-API-001",
        name: "ApiMassAssignmentUpdate",
        category: RuleCategory::MassAssignment,
        severity: Severity::High,
        cwe_id: "CWE-915",
        description: "Direct unvalidated assignment of `req.body` or `request.body` into database update or creation methods (`.update(req.body)`, `.create(req.body)`). Attackers can overwrite unauthorized fields such as roles or privileges.",
        recommendation: "Validate input using explicit schemas/DTOs (e.g. Zod, Joi) or pick only permitted fields explicitly.",
    },
    // Supply Chain & Script Safety (ci-cd-security & owasp-top-10-testing skills)
    SastRule {
        id: "SENTRA-SUPPLY-001",
        name: "InsecureCurlPipeToShell",
        category: RuleCategory::CiCdWorkflow,
        severity: Severity::High,
        cwe_id: "CWE-494",
        description: "Download and pipe to shell execution (`curl | bash`, `curl | sh`, `wget | sh`) detected in script or workflow. If the transport or remote server is compromised, arbitrary code executes directly.",
        recommendation: "Download packages via verified package managers or verify the SHA-256 checksum of downloaded scripts before execution.",
    },
    // Go Filesystem & Cryptography (golang-security skill)
    SastRule {
        id: "SENTRA-GO-005",
        name: "GoZipSlipPathTraversal",
        category: RuleCategory::PathTraversal,
        severity: Severity::High,
        cwe_id: "CWE-29",
        description: "Go archive extraction (`archive/zip` or `archive/tar`) extracts entries without validating that destination paths do not escape the destination root via `../` (ZipSlip).",
        recommendation: "Validate each entry path with `filepath.Clean` and check `strings.HasPrefix(destPath, targetDir)` or use `os.Root` in Go 1.24+.",
    },
    SastRule {
        id: "SENTRA-GO-006",
        name: "GoInsecureCipherMode",
        category: RuleCategory::Cryptographic,
        severity: Severity::High,
        cwe_id: "CWE-327",
        description: "Use of legacy or broken cryptographic ciphers (e.g. DES via `des.NewCipher`, 3DES via `des.NewTripleDESCipher`, or RC4) in Go code.",
        recommendation: "Use authenticated symmetric encryption such as AES-256-GCM (`cipher.NewGCM`) or ChaCha20-Poly1305.",
    },
    SastRule {
        id: "SENTRA-GO-007",
        name: "GoInsecureSshIgnoreHostKey",
        category: RuleCategory::Authentication,
        severity: Severity::High,
        cwe_id: "CWE-295",
        description: "SSH client uses `ssh.InsecureIgnoreHostKey()` callback, completely disabling host key verification and enabling man-in-the-middle attacks.",
        recommendation: "Use `knownhosts.New` or a fixed host public key callback (`ssh.FixedHostKey`) instead of ignoring host keys.",
    },
    // Django Advanced Checks (django-security skill)
    SastRule {
        id: "SENTRA-DJANGO-004",
        name: "DjangoRawSqlInjection",
        category: RuleCategory::SqlInjection,
        severity: Severity::Critical,
        cwe_id: "CWE-89",
        description: "Django raw SQL query execution using `.raw(...)`, `.extra(...)`, or `cursor.execute(...)` with string formatting or f-strings.",
        recommendation: "Pass query parameters as a list or tuple to the query method (e.g. `Model.objects.raw('SELECT * FROM myapp_model WHERE id = %s', [user_id])`).",
    },
    SastRule {
        id: "SENTRA-DJANGO-005",
        name: "DjangoTemplateXssSafeFilter",
        category: RuleCategory::CrossSiteScripting,
        severity: Severity::High,
        cwe_id: "CWE-79",
        description: "Django template uses `|safe` filter or `{% autoescape off %}` to disable HTML escaping on potentially user-controlled variables.",
        recommendation: "Remove `|safe` and rely on Django's default autoescaping, or sanitize content with `bleach` before marking as safe.",
    },
    // Laravel Advanced Checks (laravel-security skill)
    SastRule {
        id: "SENTRA-LARAVEL-003",
        name: "LaravelRawSqlInjection",
        category: RuleCategory::SqlInjection,
        severity: Severity::Critical,
        cwe_id: "CWE-89",
        description: "Laravel query builder uses `DB::raw(...)`, `whereRaw(...)`, `selectRaw(...)`, or `havingRaw(...)` with unparameterized string concatenation.",
        recommendation: "Use query bindings with question mark placeholders: `->whereRaw('price > ? and status = ?', [$price, $status])`.",
    },
    SastRule {
        id: "SENTRA-LARAVEL-004",
        name: "LaravelBladeUnescapedXss",
        category: RuleCategory::CrossSiteScripting,
        severity: Severity::High,
        cwe_id: "CWE-79",
        description: "Laravel Blade template outputs unescaped raw HTML using `{!! $variable !!}` instead of default escaped `{{ $variable }}`.",
        recommendation: "Use standard `{{ $variable }}` interpolation for automatic `htmlspecialchars` escaping.",
    },
    // Spring Boot Advanced Checks (springboot-security skill)
    SastRule {
        id: "SENTRA-SPRING-003",
        name: "SpringBootSpelInjection",
        category: RuleCategory::CommandInjection,
        severity: Severity::Critical,
        cwe_id: "CWE-917",
        description: "Spring Expression Language (SpEL) parser parses dynamic or user-controlled expressions (`parseExpression(...)`), enabling arbitrary Java code execution.",
        recommendation: "Use `SimpleEvaluationContext` instead of `StandardEvaluationContext` to prevent arbitrary method invocation and Java type access.",
    },
    SastRule {
        id: "SENTRA-SPRING-004",
        name: "SpringBootCsrfDisabled",
        category: RuleCategory::Misconfiguration,
        severity: Severity::Medium,
        cwe_id: "CWE-352",
        description: "Spring Security CSRF protection explicitly disabled (`.csrf().disable()` or `.csrf(AbstractHttpConfigurer::disable)`).",
        recommendation: "Keep CSRF enabled for cookie-based stateful sessions; if creating stateless REST APIs, ensure authentication is solely token-based.",
    },
    // CI/CD Secret Exposure (ci-cd-security skill)
    SastRule {
        id: "SENTRA-CICD-006",
        name: "WorkflowSecretExfiltrationRisk",
        category: RuleCategory::Secret,
        severity: Severity::High,
        cwe_id: "CWE-532",
        description: "GitHub Actions workflow echoes secrets or writes secret expressions (`${{ secrets.* }}`) into public PR issue comments, logs, or curl request parameters.",
        recommendation: "Pass secrets only via step `env:` blocks to binaries that natively consume them, and never `echo` secrets into runner output.",
    },
    // OAuth2 & JWT Verification (auth-implementation-patterns skill)
    SastRule {
        id: "SENTRA-AUTH-006",
        name: "OAuthMissingStateOrPkce",
        category: RuleCategory::Authentication,
        severity: Severity::High,
        cwe_id: "CWE-352",
        description: "OAuth 2.0 authorization URL constructed without a cryptographically random `state` parameter or missing PKCE `code_challenge`.",
        recommendation: "Generate a cryptographically random `state` parameter verified in callback, and mandate PKCE (RFC 7636) for authorization code flows.",
    },
    SastRule {
        id: "SENTRA-AUTH-007",
        name: "JwtMissingExpirationValidation",
        category: RuleCategory::Authentication,
        severity: Severity::High,
        cwe_id: "CWE-613",
        description: "JWT verification explicitly disables expiration checking (`ignoreExpiration: true`) or does not enforce the `exp` claim, allowing replayed expired tokens.",
        recommendation: "Ensure `ignoreExpiration` is false and verify that JWTs have short lifetimes with mandatory `exp` claim enforcement.",
    },
    // API Resource Limits (api-security-testing skill)
    SastRule {
        id: "SENTRA-API-002",
        name: "ApiUnboundedResourceCollection",
        category: RuleCategory::ResourceExhaustion,
        severity: Severity::Medium,
        cwe_id: "CWE-770",
        description: "API route executes unpaginated database queries (`.findAll()`, `.find()`, `SELECT *`) directly returning unbounded collections without `limit`, `take`, or pagination.",
        recommendation: "Enforce default maximum page sizes (e.g. `limit: Math.min(requestedLimit, 100)`) on all list endpoints.",
    },
];

/// Finds a rule by its stable ID.
pub fn find_rule_by_id(id: &str) -> Option<&'static SastRule> {
    BUILTIN_RULES.iter().find(|r| r.id == id)
}
