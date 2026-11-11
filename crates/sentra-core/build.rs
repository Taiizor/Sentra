//! Embeds every vendored agent skill directory under `assets/skills/` into
//! the `sentra-core` binary.
//!
//! For each `assets/skills/<id>/` directory the build script:
//!
//! 1. walks every file (the same exclusions as the upstream `skills` CLI
//!    installer: `metadata.json` files and `.git`, `__pycache__`,
//!    `__pypackages__` directories), rejecting symlinks and non-UTF-8 paths;
//! 2. normalizes CRLF to LF in text files (files without a NUL byte), so the
//!    embedded bytes do not depend on the build host's checkout settings and
//!    match the `computedHash` recorded in `assets/skills-lock.json`;
//! 3. parses `name` and `description` from the `SKILL.md` YAML frontmatter, so
//!    the catalog description can never disagree with the shipped `SKILL.md`;
//! 4. writes the normalized copy to `OUT_DIR/skills/<id>/` and emits an
//!    `include_bytes!` table in `OUT_DIR/embedded_skills.rs`.
//!
//! The build fails with a specific message when a skill directory is not
//! well formed, instead of silently embedding a partial skill.

#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// File names the upstream installer never copies.
const EXCLUDED_FILES: &[&str] = &["metadata.json"];
/// Directory names the upstream installer never copies.
const EXCLUDED_DIRS: &[&str] = &[".git", "__pycache__", "__pypackages__"];
/// Agent Skills specification limits.
const MAX_NAME_LEN: usize = 64;
const MAX_DESCRIPTION_LEN: usize = 1024;

struct SkillDir {
    id: String,
    description: String,
    /// `(relative forward-slash path, absolute path of the normalized copy)`,
    /// sorted by the UTF-8 bytes of the relative path.
    files: Vec<(String, PathBuf)>,
}

fn main() {
    let manifest_dir = PathBuf::from(env_var("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env_var("OUT_DIR"));
    let skills_root = manifest_dir.join("assets").join("skills");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/skills");

    let embedded_root = out_dir.join("skills");
    if embedded_root.exists() {
        fs::remove_dir_all(&embedded_root)
            .unwrap_or_else(|e| fail(&format!("cannot clear {}: {e}", embedded_root.display())));
    }

    let mut ids: Vec<String> = Vec::new();
    for entry in read_dir_sorted(&skills_root) {
        let file_type = entry
            .1
            .symlink_metadata()
            .unwrap_or_else(|e| fail(&format!("cannot stat {}: {e}", entry.1.display())))
            .file_type();
        if file_type.is_symlink() {
            fail(&format!(
                "{} is a symlink; vendored skills must be regular directories",
                entry.1.display()
            ));
        }
        if file_type.is_dir() {
            ids.push(entry.0);
        } else {
            fail(&format!(
                "{} is not a directory; assets/skills/ may only contain <id>/ skill directories",
                entry.1.display()
            ));
        }
    }
    if ids.is_empty() {
        fail(&format!(
            "no skill directories found under {}",
            skills_root.display()
        ));
    }

    let mut skills = Vec::with_capacity(ids.len());
    for id in ids {
        validate_skill_name(&id).unwrap_or_else(|e| fail(&format!("skill directory `{id}`: {e}")));
        skills.push(embed_skill(&skills_root, &embedded_root, id));
    }

    let generated = render(&skills);
    let target = out_dir.join("embedded_skills.rs");
    fs::write(&target, generated)
        .unwrap_or_else(|e| fail(&format!("cannot write {}: {e}", target.display())));
}

fn embed_skill(skills_root: &Path, embedded_root: &Path, id: String) -> SkillDir {
    let source_dir = skills_root.join(&id);
    let mut relative_files = Vec::new();
    collect_files(&source_dir, "", &mut relative_files);
    relative_files.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    let mut files = Vec::with_capacity(relative_files.len());
    let mut skill_md: Option<String> = None;
    for relative in relative_files {
        let source = source_dir.join(&relative);
        let raw = fs::read(&source)
            .unwrap_or_else(|e| fail(&format!("cannot read {}: {e}", source.display())));
        let content = normalize_line_endings(raw);
        if relative == "SKILL.md" {
            let text = String::from_utf8(content.clone())
                .unwrap_or_else(|_| fail(&format!("{} is not valid UTF-8", source.display())));
            skill_md = Some(text);
        }
        let target = embedded_root.join(&id).join(&relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .unwrap_or_else(|e| fail(&format!("cannot create {}: {e}", parent.display())));
        }
        fs::write(&target, &content)
            .unwrap_or_else(|e| fail(&format!("cannot write {}: {e}", target.display())));
        files.push((relative, target));
    }

    let Some(skill_md) = skill_md else {
        fail(&format!(
            "skill `{id}` has no SKILL.md at {}",
            source_dir.display()
        ));
    };
    let frontmatter = parse_frontmatter(&skill_md)
        .unwrap_or_else(|e| fail(&format!("{id}/SKILL.md frontmatter: {e}")));
    let name = frontmatter_value(&frontmatter, "name")
        .unwrap_or_else(|e| fail(&format!("{id}/SKILL.md: {e}")));
    if name != id {
        fail(&format!(
            "{id}/SKILL.md: frontmatter name `{name}` must equal the directory name `{id}`"
        ));
    }
    let description = frontmatter_value(&frontmatter, "description")
        .unwrap_or_else(|e| fail(&format!("{id}/SKILL.md: {e}")));
    let trimmed = description.trim();
    if trimmed.is_empty() {
        fail(&format!("{id}/SKILL.md: description is empty"));
    }
    if trimmed.chars().count() > MAX_DESCRIPTION_LEN {
        fail(&format!(
            "{id}/SKILL.md: description exceeds {MAX_DESCRIPTION_LEN} characters"
        ));
    }

    SkillDir {
        id,
        description: trimmed.to_string(),
        files,
    }
}

/// Recursively collects regular files below `dir` as forward-slash paths.
fn collect_files(dir: &Path, prefix: &str, out: &mut Vec<String>) {
    for (name, path) in read_dir_sorted(dir) {
        let file_type = path
            .symlink_metadata()
            .unwrap_or_else(|e| fail(&format!("cannot stat {}: {e}", path.display())))
            .file_type();
        if file_type.is_symlink() {
            fail(&format!(
                "{} is a symlink; vendored skills must not contain links",
                path.display()
            ));
        }
        if name.contains('\\') || name.contains('"') {
            fail(&format!(
                "{} has a file name that cannot be embedded portably",
                path.display()
            ));
        }
        if file_type.is_dir() {
            if EXCLUDED_DIRS.contains(&name.as_str()) {
                continue;
            }
            collect_files(&path, &format!("{prefix}{name}/"), out);
        } else if file_type.is_file() {
            if EXCLUDED_FILES.contains(&name.as_str()) {
                continue;
            }
            out.push(format!("{prefix}{name}"));
        } else {
            fail(&format!(
                "{} is neither a file nor a directory",
                path.display()
            ));
        }
    }
}

/// Lists a directory as `(UTF-8 name, path)` pairs sorted by name bytes.
fn read_dir_sorted(dir: &Path) -> Vec<(String, PathBuf)> {
    let reader = fs::read_dir(dir)
        .unwrap_or_else(|e| fail(&format!("cannot read directory {}: {e}", dir.display())));
    let mut entries = Vec::new();
    for entry in reader {
        let entry = entry
            .unwrap_or_else(|e| fail(&format!("cannot read directory {}: {e}", dir.display())));
        let name = entry
            .file_name()
            .into_string()
            .unwrap_or_else(|raw| fail(&format!("{}: non-UTF-8 file name {raw:?}", dir.display())));
        entries.push((name, entry.path()));
    }
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    entries
}

/// Text files (no NUL byte) get CRLF replaced by LF, as in the `skills` CLI
/// v2 content hash; binary files are embedded unchanged.
fn normalize_line_endings(content: Vec<u8>) -> Vec<u8> {
    if content.contains(&0) || !content.windows(2).any(|w| w == b"\r\n") {
        return content;
    }
    let mut out = Vec::with_capacity(content.len());
    let mut iter = content.iter().peekable();
    while let Some(&byte) = iter.next() {
        if byte == b'\r' && iter.peek() == Some(&&b'\n') {
            continue;
        }
        out.push(byte);
    }
    out
}

/// Agent Skills `name` rules: 1-64 chars of `[a-z0-9-]`, no leading,
/// trailing, or consecutive hyphens.
fn validate_skill_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(format!("name must be 1-{MAX_NAME_LEN} characters"));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("name may only contain lowercase letters, digits, and hyphens".to_string());
    }
    if name.starts_with('-') || name.ends_with('-') || name.contains("--") {
        return Err(
            "name must not start or end with a hyphen or contain consecutive hyphens".to_string(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Minimal YAML frontmatter reader.
//
// Only top-level `key: value` pairs are read. Values may be plain scalars
// (optionally continued on more-indented lines), single- or double-quoted
// single-line scalars, or literal/folded block scalars. Anything else under a
// key that the catalog needs is rejected instead of being guessed.
// ---------------------------------------------------------------------------

/// A top-level frontmatter key with its raw value lines.
struct RawEntry {
    key: String,
    /// Text after `key:` on the key line.
    inline: String,
    /// Following lines that belong to this key (indented or blank).
    continuation: Vec<String>,
}

fn parse_frontmatter(text: &str) -> Result<Vec<RawEntry>, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines = text.split('\n');
    if lines.next().map(str::trim_end) != Some("---") {
        return Err("SKILL.md must start with a `---` frontmatter line".to_string());
    }
    let mut entries: Vec<RawEntry> = Vec::new();
    let mut closed = false;
    for line in lines {
        if line.trim_end() == "---" {
            closed = true;
            break;
        }
        let starts_indented = line.starts_with(' ') || line.starts_with('\t');
        if line.trim().is_empty() || starts_indented {
            if let Some(last) = entries.last_mut() {
                last.continuation.push(line.to_string());
            } else if !line.trim().is_empty() {
                return Err("indented line before the first key".to_string());
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let Some((key, rest)) = line.split_once(':') else {
            return Err(format!("unsupported top-level line `{line}`"));
        };
        entries.push(RawEntry {
            key: key.trim().to_string(),
            inline: rest.trim().to_string(),
            continuation: Vec::new(),
        });
    }
    if !closed {
        return Err("frontmatter is not closed by a `---` line".to_string());
    }
    Ok(entries)
}

fn frontmatter_value(entries: &[RawEntry], key: &str) -> Result<String, String> {
    let mut matches = entries.iter().filter(|e| e.key == key);
    let entry = matches
        .next()
        .ok_or_else(|| format!("frontmatter has no `{key}`"))?;
    if matches.next().is_some() {
        return Err(format!("frontmatter has more than one `{key}`"));
    }
    scalar_value(entry).map_err(|e| format!("`{key}`: {e}"))
}

fn scalar_value(entry: &RawEntry) -> Result<String, String> {
    let inline = entry.inline.as_str();
    let has_content = entry.continuation.iter().any(|l| !l.trim().is_empty());
    match inline.chars().next() {
        Some('"') => {
            if has_content {
                return Err("multi-line double-quoted scalars are not supported".to_string());
            }
            parse_double_quoted(inline)
        }
        Some('\'') => {
            if has_content {
                return Err("multi-line single-quoted scalars are not supported".to_string());
            }
            parse_single_quoted(inline)
        }
        Some('|') | Some('>') => parse_block_scalar(inline, &entry.continuation),
        Some('[' | '{' | '&' | '*' | '!' | '%' | '@' | '`') => Err(format!(
            "value starting with `{}` is not a plain string",
            &inline[..1]
        )),
        None => {
            if has_content {
                Err("nested mappings or sequences are not plain strings".to_string())
            } else {
                Err("value is empty".to_string())
            }
        }
        Some(_) => Ok(parse_plain(inline, &entry.continuation)),
    }
}

fn parse_plain(inline: &str, continuation: &[String]) -> String {
    let strip_comment = |s: &str| -> String {
        match s.find(" #") {
            Some(idx) => s[..idx].trim_end().to_string(),
            None => s.trim_end().to_string(),
        }
    };
    let mut value = strip_comment(inline);
    let mut pending_newlines = 0usize;
    for line in continuation {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            pending_newlines += 1;
            continue;
        }
        if pending_newlines > 0 {
            value.push_str(&"\n".repeat(pending_newlines));
            pending_newlines = 0;
        } else {
            value.push(' ');
        }
        value.push_str(&strip_comment(trimmed));
    }
    value
}

fn parse_single_quoted(inline: &str) -> Result<String, String> {
    let body = &inline[1..];
    let mut out = String::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            if chars.peek() == Some(&'\'') {
                chars.next();
                out.push('\'');
                continue;
            }
            let rest: String = chars.collect();
            return trailing_is_comment(&rest)
                .then_some(out)
                .ok_or_else(|| "text after closing quote".to_string());
        }
        out.push(c);
    }
    Err("unterminated single-quoted scalar".to_string())
}

fn parse_double_quoted(inline: &str) -> Result<String, String> {
    let body = &inline[1..];
    let mut out = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                let rest: String = chars.collect();
                return trailing_is_comment(&rest)
                    .then_some(out)
                    .ok_or_else(|| "text after closing quote".to_string());
            }
            '\\' => {
                let escape = chars.next().ok_or("dangling escape")?;
                match escape {
                    '0' => out.push('\0'),
                    'a' => out.push('\u{7}'),
                    'b' => out.push('\u{8}'),
                    't' | '\t' => out.push('\t'),
                    'n' => out.push('\n'),
                    'v' => out.push('\u{b}'),
                    'f' => out.push('\u{c}'),
                    'r' => out.push('\r'),
                    'e' => out.push('\u{1b}'),
                    ' ' => out.push(' '),
                    '"' => out.push('"'),
                    '/' => out.push('/'),
                    '\\' => out.push('\\'),
                    'N' => out.push('\u{85}'),
                    '_' => out.push('\u{a0}'),
                    'L' => out.push('\u{2028}'),
                    'P' => out.push('\u{2029}'),
                    'x' => out.push(hex_escape(&mut chars, 2)?),
                    'u' => out.push(hex_escape(&mut chars, 4)?),
                    'U' => out.push(hex_escape(&mut chars, 8)?),
                    other => return Err(format!("unsupported escape `\\{other}`")),
                }
            }
            other => out.push(other),
        }
    }
    Err("unterminated double-quoted scalar".to_string())
}

fn hex_escape(chars: &mut std::str::Chars<'_>, digits: usize) -> Result<char, String> {
    let hex: String = chars.by_ref().take(digits).collect();
    if hex.len() != digits {
        return Err("truncated hex escape".to_string());
    }
    let code = u32::from_str_radix(&hex, 16).map_err(|_| format!("invalid hex escape `{hex}`"))?;
    char::from_u32(code).ok_or_else(|| format!("invalid code point `{hex}`"))
}

fn trailing_is_comment(rest: &str) -> bool {
    let rest = rest.trim();
    rest.is_empty() || rest.starts_with('#')
}

/// Literal (`|`) and folded (`>`) block scalars with optional chomping
/// (`-`, `+`) and indentation indicators.
fn parse_block_scalar(header: &str, continuation: &[String]) -> Result<String, String> {
    let header = match header.find(" #") {
        Some(idx) => header[..idx].trim_end(),
        None => header,
    };
    let mut indicator = header.chars();
    let folded = indicator.next() == Some('>');
    let mut chomp = 'c';
    let mut explicit_indent: Option<usize> = None;
    for c in indicator {
        match c {
            '-' | '+' if chomp == 'c' => chomp = c,
            '1'..='9' if explicit_indent.is_none() => {
                explicit_indent = Some(c as usize - '0' as usize)
            }
            _ => return Err(format!("unsupported block scalar header `{header}`")),
        }
    }
    let indent_of = |line: &str| line.len() - line.trim_start_matches(' ').len();
    let indent = match explicit_indent {
        Some(n) => n,
        None => continuation
            .iter()
            .find(|l| !l.trim().is_empty())
            .map(|l| indent_of(l))
            .unwrap_or(0),
    };
    if indent == 0 {
        return Err("block scalar has no indented content".to_string());
    }
    let mut lines: Vec<&str> = Vec::with_capacity(continuation.len());
    for line in continuation {
        if line.trim().is_empty() {
            lines.push("");
        } else if indent_of(line) < indent {
            return Err("block scalar line is less indented than its first line".to_string());
        } else {
            lines.push(&line[indent..]);
        }
    }
    let trailing_blank = lines.iter().rev().take_while(|l| l.is_empty()).count();
    let body = &lines[..lines.len() - trailing_blank];

    let mut text = String::new();
    if folded {
        let mut previous_blank = true;
        let mut pending_newlines = 0usize;
        for line in body {
            if line.is_empty() {
                pending_newlines += 1;
                continue;
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                return Err("more-indented lines in folded scalars are not supported".to_string());
            }
            if !previous_blank || pending_newlines > 0 {
                if pending_newlines > 0 {
                    text.push_str(&"\n".repeat(pending_newlines));
                } else {
                    text.push(' ');
                }
            }
            pending_newlines = 0;
            previous_blank = false;
            text.push_str(line);
        }
    } else {
        text = body.join("\n");
    }
    match chomp {
        '-' => {}
        '+' => {
            text.push('\n');
            text.push_str(&"\n".repeat(trailing_blank));
        }
        _ => {
            if !body.is_empty() {
                text.push('\n');
            }
        }
    }
    Ok(text)
}

// ---------------------------------------------------------------------------
// Code generation.
// ---------------------------------------------------------------------------

fn render(skills: &[SkillDir]) -> String {
    let mut out = String::new();
    out.push_str(
        "// @generated by crates/sentra-core/build.rs from assets/skills/. Do not edit.\n",
    );
    out.push_str("pub(super) static EMBEDDED_SKILLS: &[EmbeddedSkill] = &[\n");
    for skill in skills {
        let skill_md = skill
            .files
            .iter()
            .find(|(rel, _)| rel == "SKILL.md")
            .map(|(_, path)| path)
            .unwrap_or_else(|| fail(&format!("skill `{}` lost its SKILL.md", skill.id)));
        let _ = writeln!(out, "    EmbeddedSkill {{");
        let _ = writeln!(out, "        id: {:?},", skill.id);
        let _ = writeln!(out, "        description: {:?},", skill.description);
        let _ = writeln!(
            out,
            "        skill_md: include_str!({:?}),",
            path_literal(skill_md)
        );
        let _ = writeln!(out, "        files: &[");
        for (relative, path) in &skill.files {
            let _ = writeln!(
                out,
                "            ({:?}, include_bytes!({:?})),",
                relative,
                path_literal(path)
            );
        }
        let _ = writeln!(out, "        ],");
        let _ = writeln!(out, "    }},");
    }
    out.push_str("];\n");
    out
}

fn path_literal(path: &Path) -> String {
    path.to_str()
        .unwrap_or_else(|| fail(&format!("{} is not valid UTF-8", path.display())))
        .to_string()
}

fn env_var(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| fail(&format!("cargo did not set {key}")))
}

fn fail(message: &str) -> ! {
    panic!("sentra-core build: embedded skills: {message}");
}
