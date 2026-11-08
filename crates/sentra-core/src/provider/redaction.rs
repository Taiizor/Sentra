//! Strict privacy enforcement and credential redaction (REQ-F09, ADR-0005).

/// Privacy filter for sanitizing prompts and model responses before audit recording or external dispatch.
pub struct RedactionFilter;

impl RedactionFilter {
    /// Masks common secret patterns, authentication tokens, and private keys.
    pub fn redact_text(input: &str) -> String {
        let mut text = input.to_string();

        // 1. Redact PEM private key blocks
        while let Some(start) = text.find("-----BEGIN") {
            if let Some(end_marker) = text[start..].find("-----END") {
                let actual_end_marker = start + end_marker;
                if let Some(final_dashes) = text[actual_end_marker..].find("-----\n") {
                    let cut_end = actual_end_marker + final_dashes + 6;
                    text.replace_range(start..cut_end, "[REDACTED_PRIVATE_KEY]\n");
                    continue;
                } else if let Some(final_dashes) = text[actual_end_marker..].find("-----") {
                    let cut_end = actual_end_marker + final_dashes + 5;
                    text.replace_range(start..cut_end, "[REDACTED_PRIVATE_KEY]");
                    continue;
                }
            }
            break;
        }

        // 2. Redact GitHub personal access tokens (`ghp_...`, `github_pat_...`)
        text = redact_prefixed_token(&text, "ghp_", 36);
        text = redact_prefixed_token(&text, "github_pat_", 82);

        // 3. Redact GitLab personal access tokens (`glpat-...`)
        text = redact_prefixed_token(&text, "glpat-", 20);

        // 4. Redact AWS access key IDs (`AKIA...`)
        text = redact_aws_keys(&text);

        // 5. Redact Bearer authorization headers
        text = redact_bearer_tokens(&text);

        text
    }

    /// Checks whether an input text contains detectable credentials or unredacted secrets.
    pub fn contains_secrets(input: &str) -> bool {
        input.contains("-----BEGIN")
            || input.contains("ghp_")
            || input.contains("github_pat_")
            || input.contains("glpat-")
            || has_aws_access_key(input)
            || has_bearer_token(input)
    }
}

fn redact_prefixed_token(text: &str, prefix: &str, min_length: usize) -> String {
    let mut result = text.to_string();
    let mut search_from = 0;

    while let Some(pos) = result[search_from..].find(prefix) {
        let start = search_from + pos;
        let mut end = start + prefix.len();
        while end < result.len() {
            let b = result.as_bytes()[end];
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
                end += 1;
            } else {
                break;
            }
        }

        if (end - start) >= (prefix.len() + min_length) {
            result.replace_range(start..end, "[REDACTED_TOKEN]");
            search_from = start + "[REDACTED_TOKEN]".len();
        } else {
            search_from = end;
        }
    }
    result
}

fn redact_aws_keys(text: &str) -> String {
    let mut result = text.to_string();
    let prefix = "AKIA";
    let mut search_from = 0;

    while let Some(pos) = result[search_from..].find(prefix) {
        let start = search_from + pos;
        let end = start + 20; // 4 + 16 chars
        if end <= result.len() {
            let candidate = &result[start..end];
            if candidate
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            {
                result.replace_range(start..end, "[REDACTED_AWS_KEY]");
                search_from = start + "[REDACTED_AWS_KEY]".len();
                continue;
            }
        }
        search_from = start + prefix.len();
    }
    result
}

fn redact_bearer_tokens(text: &str) -> String {
    let mut result = text.to_string();
    let prefix = "Bearer ";
    let mut search_from = 0;

    while let Some(pos) = result[search_from..].find(prefix) {
        let start = search_from + pos + prefix.len();
        let mut end = start;
        while end < result.len() {
            let b = result.as_bytes()[end];
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' {
                end += 1;
            } else {
                break;
            }
        }
        if (end - start) >= 16 {
            result.replace_range(start..end, "[REDACTED_BEARER_TOKEN]");
            search_from = start + "[REDACTED_BEARER_TOKEN]".len();
        } else {
            search_from = end;
        }
    }
    result
}

fn has_aws_access_key(text: &str) -> bool {
    let mut search_from = 0;
    while let Some(pos) = text[search_from..].find("AKIA") {
        let start = search_from + pos;
        let end = start + 20;
        if end <= text.len() {
            let candidate = &text[start..end];
            if candidate
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            {
                return true;
            }
        }
        search_from = start + 4;
    }
    false
}

fn has_bearer_token(text: &str) -> bool {
    if let Some(pos) = text.find("Bearer ") {
        let start = pos + 7;
        let end = text[start..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'))
            .map(|offset| start + offset)
            .unwrap_or(text.len());
        if (end - start) >= 16 {
            return true;
        }
    }
    false
}
