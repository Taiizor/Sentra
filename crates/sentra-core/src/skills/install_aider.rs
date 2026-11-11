//! Lossless editing of the top-level `read:` list in an Aider `.aider.conf.yml`.
//!
//! Aider loads conventions files listed under `read:` into every chat
//! (<https://aider.chat/docs/usage/conventions.html>, config file format at
//! <https://aider.chat/docs/config/aider_conf.html>). Sentra does not depend on a
//! YAML library here: it performs a conservative, line-based edit that only
//! inserts new list items and leaves every other byte of the file untouched.
//! Anything outside the small set of shapes it fully understands (block
//! scalars, anchors, multi-document files, multi-line flow sequences, tabs, ...)
//! is refused with a manual snippet instead of being rewritten, and so is a file
//! whose top-level values are not valid YAML (the edit would otherwise succeed
//! while Aider still cannot load the file).

use crate::skills::mcp_yaml::inline_value_problem;

/// The config cannot be edited losslessly; the user must apply `snippet` by hand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ManualEdit {
    /// Why the automatic edit was refused.
    pub reason: String,
    /// YAML the user must merge into the file.
    pub snippet: String,
}

/// Plans adding `entries` to the top-level `read:` list of an Aider YAML config.
///
/// * `Ok(None)`: every entry is already listed; nothing to write.
/// * `Ok(Some(text))`: the complete new file content.
/// * `Err(manual)`: the file cannot be edited safely.
pub(crate) fn plan_read_entries(
    existing: Option<&str>,
    entries: &[String],
) -> Result<Option<String>, ManualEdit> {
    let Some(existing) = existing else {
        let mut out = String::from(
            "# Added by Sentra: conventions files Aider loads into every chat.\nread:\n",
        );
        for entry in entries {
            out.push_str(&format!("  - {}\n", render_scalar(entry)));
        }
        return Ok(Some(out));
    };

    let (bom, body) = match existing.strip_prefix('\u{feff}') {
        Some(rest) => ("\u{feff}", rest),
        None => ("", existing),
    };
    let eol = if body.contains("\r\n") { "\r\n" } else { "\n" };
    let lines: Vec<&str> = body.split_inclusive('\n').collect();
    let read = find_read_key(&lines, entries)?;

    let edited = match read {
        None => append_read_block(body, entries, eol),
        Some(index) => edit_read_value(&lines, index, entries, eol)?,
    };
    Ok(edited.map(|text| format!("{bom}{text}")))
}

/// Renders the manual snippet for `entries`.
pub(crate) fn manual_snippet(entries: &[String]) -> String {
    let mut out = String::from("read:\n");
    for entry in entries {
        out.push_str(&format!("  - {}\n", render_scalar(entry)));
    }
    out
}

fn manual(entries: &[String], reason: impl Into<String>) -> ManualEdit {
    ManualEdit {
        reason: reason.into(),
        snippet: manual_snippet(entries),
    }
}

/// Validates the document shape and returns the line index of the top-level `read` key.
fn find_read_key(lines: &[&str], entries: &[String]) -> Result<Option<usize>, ManualEdit> {
    let mut read_index = None;
    let mut seen_content = false;
    let mut previous_value_empty = false;

    for (index, raw) in lines.iter().enumerate() {
        let line = trim_eol(raw);
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if line.starts_with('\t') || line.trim_start_matches(' ').starts_with('\t') {
            return Err(manual(entries, "the file uses tab indentation"));
        }
        if line.starts_with(' ') {
            continue;
        }
        if line == "---" && !seen_content {
            continue;
        }
        if line == "---" || line == "..." || line.starts_with('%') {
            return Err(manual(
                entries,
                "the file uses YAML directives or multiple documents",
            ));
        }
        if (line == "-" || line.starts_with("- ")) && previous_value_empty {
            // Compact block sequence item belonging to the previous key.
            continue;
        }
        let Some((key, value_offset)) = top_level_key(line) else {
            return Err(manual(
                entries,
                "the top level is not a plain block mapping",
            ));
        };
        if let Some(problem) = inline_value_problem(&line[value_offset..]) {
            return Err(manual(
                entries,
                format!(
                    "line {} is not valid YAML ({problem}); fix it first",
                    index + 1
                ),
            ));
        }
        seen_content = true;
        previous_value_empty = strip_comment(&line[value_offset..]).is_empty();
        if key == "read" {
            if read_index.is_some() {
                return Err(manual(entries, "the file declares `read` more than once"));
            }
            read_index = Some(index);
        }
    }
    Ok(read_index)
}

fn append_read_block(body: &str, entries: &[String], eol: &str) -> Option<String> {
    let mut out = String::with_capacity(body.len() + 64 * entries.len());
    out.push_str(body);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push_str(eol);
    }
    out.push_str("read:");
    out.push_str(eol);
    for entry in entries {
        out.push_str("  - ");
        out.push_str(&render_scalar(entry));
        out.push_str(eol);
    }
    Some(out)
}

fn edit_read_value(
    lines: &[&str],
    index: usize,
    entries: &[String],
    eol: &str,
) -> Result<Option<String>, ManualEdit> {
    let line = trim_eol(lines[index]);
    let (_, value_offset) =
        top_level_key(line).ok_or_else(|| manual(entries, "unreadable `read` key"))?;
    let value = strip_comment(&line[value_offset..]);

    if value.is_empty() {
        return edit_block_sequence(lines, index, entries, eol);
    }
    if continuation_follows(lines, index) {
        return Err(manual(entries, "`read` spans multiple lines"));
    }
    if value.starts_with('[') {
        return edit_flow_sequence(lines, index, value_offset, value, entries);
    }
    if value.starts_with(['|', '>', '&', '*', '!', '{', '?', '-', '@', '`']) {
        return Err(manual(
            entries,
            "`read` uses a YAML construct Sentra does not edit automatically",
        ));
    }

    // Single scalar: `read: CONVENTIONS.md` becomes `read: [CONVENTIONS.md, <new>...]`.
    let existing = vec![parse_scalar(value)];
    let missing = missing_entries(&existing, entries);
    if missing.is_empty() {
        return Ok(None);
    }
    if value.contains([',', '[', ']', '{', '}']) && !value.starts_with(['"', '\'']) {
        return Err(manual(
            entries,
            "`read` holds a scalar Sentra cannot rewrite safely",
        ));
    }
    let start = value_offset + line[value_offset..].find(value).unwrap_or(0);
    let end = start + value.len();
    let mut rebuilt = String::new();
    rebuilt.push_str(&line[..start]);
    rebuilt.push('[');
    rebuilt.push_str(value);
    for entry in &missing {
        rebuilt.push_str(", ");
        rebuilt.push_str(&render_scalar(entry));
    }
    rebuilt.push(']');
    rebuilt.push_str(&line[end..]);
    Ok(Some(replace_line(lines, index, &rebuilt)))
}

fn edit_flow_sequence(
    lines: &[&str],
    index: usize,
    value_offset: usize,
    value: &str,
    entries: &[String],
) -> Result<Option<String>, ManualEdit> {
    let line = trim_eol(lines[index]);
    if !value.ends_with(']') {
        return Err(manual(entries, "`read` flow sequence spans multiple lines"));
    }
    let inner = &value[1..value.len() - 1];
    if inner.contains(['[', ']', '{', '}', '"', '\'']) {
        return Err(manual(
            entries,
            "`read` flow sequence contains quoted or nested items",
        ));
    }
    let existing: Vec<String> = inner
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect();
    let missing = missing_entries(&existing, entries);
    if missing.is_empty() {
        return Ok(None);
    }

    let start = value_offset + line[value_offset..].find('[').unwrap_or(0);
    let close = start + value.len() - 1;
    let raw_inner = line[start + 1..close].trim_end();
    let kept_inner = raw_inner.strip_suffix(',').map_or(raw_inner, str::trim_end);
    let mut rebuilt = String::new();
    rebuilt.push_str(&line[..=start]);
    rebuilt.push_str(kept_inner);
    for (position, entry) in missing.iter().enumerate() {
        if !existing.is_empty() || position > 0 {
            rebuilt.push_str(", ");
        }
        rebuilt.push_str(&render_scalar(entry));
    }
    rebuilt.push_str(&line[close..]);
    Ok(Some(replace_line(lines, index, &rebuilt)))
}

fn edit_block_sequence(
    lines: &[&str],
    index: usize,
    entries: &[String],
    eol: &str,
) -> Result<Option<String>, ManualEdit> {
    let mut items = Vec::new();
    let mut item_indent: Option<usize> = None;
    let mut last_item = index;

    for (offset, raw) in lines[index + 1..].iter().enumerate() {
        let line = trim_eol(raw);
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - trimmed.len();
        let is_item = trimmed == "-" || trimmed.starts_with("- ");
        if indent == 0 && !is_item {
            break;
        }
        if !is_item || item_indent.is_some_and(|expected| expected != indent) {
            return Err(manual(
                entries,
                "`read` list contains nested or multi-line items",
            ));
        }
        item_indent = Some(indent);
        let value = strip_comment(&trimmed[1..]);
        let quoted = value.starts_with(['"', '\'']);
        let mapping_like = !quoted && (value.contains(": ") || value.ends_with(':'));
        if value.is_empty()
            || mapping_like
            || value.starts_with(['|', '>', '&', '*', '!', '{', '[', '?', '-'])
        {
            return Err(manual(entries, "`read` list contains non-scalar items"));
        }
        items.push(parse_scalar(value));
        last_item = index + 1 + offset;
    }

    let missing = missing_entries(&items, entries);
    if missing.is_empty() {
        return Ok(None);
    }

    let indent = " ".repeat(item_indent.unwrap_or(2));
    let mut out = String::new();
    for (position, raw) in lines.iter().enumerate() {
        out.push_str(raw);
        if position == last_item {
            if !raw.ends_with('\n') {
                out.push_str(eol);
            }
            for entry in &missing {
                out.push_str(&indent);
                out.push_str("- ");
                out.push_str(&render_scalar(entry));
                out.push_str(eol);
            }
        }
    }
    Ok(Some(out))
}

fn continuation_follows(lines: &[&str], index: usize) -> bool {
    lines[index + 1..]
        .iter()
        .map(|raw| trim_eol(raw))
        .find(|line| {
            let trimmed = line.trim_start();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .is_some_and(|line| line.starts_with([' ', '\t']))
}

fn replace_line(lines: &[&str], index: usize, replacement: &str) -> String {
    let mut out = String::new();
    for (position, raw) in lines.iter().enumerate() {
        if position == index {
            out.push_str(replacement);
            out.push_str(&raw[trim_eol(raw).len()..]);
        } else {
            out.push_str(raw);
        }
    }
    out
}

fn missing_entries(existing: &[String], entries: &[String]) -> Vec<String> {
    let present: Vec<String> = existing.iter().map(|e| normalize_entry(e)).collect();
    let mut missing: Vec<String> = Vec::new();
    for entry in entries {
        let normalized = normalize_entry(entry);
        if !present.contains(&normalized)
            && !missing.iter().any(|m| normalize_entry(m) == normalized)
        {
            missing.push(entry.clone());
        }
    }
    missing
}

fn normalize_entry(entry: &str) -> String {
    let unified = entry.trim().replace('\\', "/");
    unified
        .strip_prefix("./")
        .map(str::to_string)
        .unwrap_or(unified)
}

/// Returns `(key, offset just past the ':')` for a top-level mapping line.
fn top_level_key(line: &str) -> Option<(String, usize)> {
    let (key, after_key) = if let Some(rest) = line.strip_prefix('"') {
        let end = rest.find('"')?;
        (rest[..end].to_string(), end + 2)
    } else if let Some(rest) = line.strip_prefix('\'') {
        let end = rest.find('\'')?;
        (rest[..end].to_string(), end + 2)
    } else {
        if line.starts_with([
            '[', '{', '-', '?', '#', '&', '*', '!', '|', '>', '%', '@', '`', ':', ',',
        ]) {
            return None;
        }
        let bytes = line.as_bytes();
        let colon = (0..bytes.len()).find(|&i| {
            bytes[i] == b':'
                && bytes
                    .get(i + 1)
                    .is_none_or(|next| *next == b' ' || *next == b'\t')
        })?;
        let key = line[..colon].trim_end();
        if key.is_empty() || key.contains(" #") {
            return None;
        }
        (key.to_string(), colon)
    };

    let rest = &line[after_key..];
    let spaces = rest.len() - rest.trim_start_matches([' ', '\t']).len();
    let colon_at = after_key + spaces;
    if line.as_bytes().get(colon_at) != Some(&b':') {
        return None;
    }
    let value_offset = colon_at + 1;
    if line
        .as_bytes()
        .get(value_offset)
        .is_some_and(|next| *next != b' ' && *next != b'\t')
    {
        return None;
    }
    Some((key, value_offset))
}

/// Removes a trailing `# comment` (outside quotes) and surrounding whitespace.
fn strip_comment(value: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut previous_blank = true;
    for (index, ch) in value.char_indices() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => {}
            None if ch == '"' || ch == '\'' => quote = Some(ch),
            None if ch == '#' && previous_blank => return value[..index].trim(),
            None => {}
        }
        previous_blank = ch == ' ' || ch == '\t';
    }
    value.trim()
}

fn parse_scalar(token: &str) -> String {
    let token = token.trim();
    if token.starts_with('"') && token.ends_with('"') && token.len() >= 2 {
        return serde_json::from_str::<String>(token)
            .unwrap_or_else(|_| token[1..token.len() - 1].to_string());
    }
    if token.starts_with('\'') && token.ends_with('\'') && token.len() >= 2 {
        return token[1..token.len() - 1].replace("''", "'");
    }
    token.to_string()
}

/// Renders a path as a YAML scalar: plain when unambiguous, otherwise double-quoted.
fn render_scalar(value: &str) -> String {
    let plain = value.contains('/')
        && !value.starts_with('-')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-'));
    if plain {
        value.to_string()
    } else {
        serde_json::to_string(value).unwrap_or_else(|_| format!("\"{value}\""))
    }
}

fn trim_eol(line: &str) -> &str {
    line.trim_end_matches(['\r', '\n'])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<String> {
        vec![
            ".agents/skills/a/SKILL.md".to_string(),
            ".agents/skills/b/SKILL.md".to_string(),
        ]
    }

    #[test]
    fn creates_new_config() {
        let out = plan_read_entries(None, &entries()).unwrap().unwrap();
        assert!(
            out.ends_with("read:\n  - .agents/skills/a/SKILL.md\n  - .agents/skills/b/SKILL.md\n")
        );
    }

    #[test]
    fn appends_read_key_and_preserves_everything_else() {
        let original = "# my settings\nmodel: sonnet # pinned\nauto-commits: false";
        let out = plan_read_entries(Some(original), &entries())
            .unwrap()
            .unwrap();
        assert_eq!(
            out,
            "# my settings\nmodel: sonnet # pinned\nauto-commits: false\nread:\n  - .agents/skills/a/SKILL.md\n  - .agents/skills/b/SKILL.md\n"
        );
    }

    #[test]
    fn extends_block_list_with_crlf_and_comments() {
        let original = "read:\r\n    - CONVENTIONS.md # mine\r\n    - \"./.agents/skills/a/SKILL.md\"\r\n# trailing\r\nmodel: x\r\n";
        let out = plan_read_entries(Some(original), &entries())
            .unwrap()
            .unwrap();
        assert_eq!(
            out,
            "read:\r\n    - CONVENTIONS.md # mine\r\n    - \"./.agents/skills/a/SKILL.md\"\r\n    - .agents/skills/b/SKILL.md\r\n# trailing\r\nmodel: x\r\n"
        );
    }

    #[test]
    fn extends_compact_block_list() {
        let original = "read:\n- CONVENTIONS.md\nmodel: x\n";
        let out = plan_read_entries(Some(original), &entries())
            .unwrap()
            .unwrap();
        assert_eq!(
            out,
            "read:\n- CONVENTIONS.md\n- .agents/skills/a/SKILL.md\n- .agents/skills/b/SKILL.md\nmodel: x\n"
        );
    }

    #[test]
    fn extends_flow_and_scalar_forms() {
        let flow = "read: [CONVENTIONS.md, notes.txt] # keep\n";
        assert_eq!(
            plan_read_entries(Some(flow), &entries()).unwrap().unwrap(),
            "read: [CONVENTIONS.md, notes.txt, .agents/skills/a/SKILL.md, .agents/skills/b/SKILL.md] # keep\n"
        );
        let empty_flow = "read: []\n";
        assert_eq!(
            plan_read_entries(Some(empty_flow), &entries())
                .unwrap()
                .unwrap(),
            "read: [.agents/skills/a/SKILL.md, .agents/skills/b/SKILL.md]\n"
        );
        let scalar = "read: CONVENTIONS.md\n";
        assert_eq!(
            plan_read_entries(Some(scalar), &entries())
                .unwrap()
                .unwrap(),
            "read: [CONVENTIONS.md, .agents/skills/a/SKILL.md, .agents/skills/b/SKILL.md]\n"
        );
    }

    #[test]
    fn is_idempotent() {
        let first = plan_read_entries(Some("model: x\n"), &entries())
            .unwrap()
            .unwrap();
        assert_eq!(plan_read_entries(Some(&first), &entries()).unwrap(), None);
    }

    #[test]
    fn refuses_constructs_it_cannot_edit() {
        for original in [
            "read: |\n  CONVENTIONS.md\n",
            "read: &files [a]\n",
            "read: [a,\n  b]\n",
            "read:\n  - a\nread:\n  - b\n",
            "model: x\n---\nmodel: y\n",
            "{read: [a]}\n",
            "read:\n  - key: value\n",
            "read:\n\t- a\n",
            // Audit repro: invalid YAML elsewhere in the file.
            "model: : bad\n",
            "model: a: b\nread: [x]\n",
        ] {
            let err = plan_read_entries(Some(original), &entries()).unwrap_err();
            assert!(
                err.snippet.contains("  - .agents/skills/a/SKILL.md"),
                "{original}"
            );
        }
    }

    #[test]
    fn quotes_paths_that_need_it() {
        assert_eq!(
            render_scalar("C:/Users/me/.agents/skills/a/SKILL.md"),
            "\"C:/Users/me/.agents/skills/a/SKILL.md\""
        );
        assert_eq!(
            render_scalar("/home/me/a b/SKILL.md"),
            "\"/home/me/a b/SKILL.md\""
        );
    }
}
