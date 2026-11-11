//! Text helpers shared by the skill installer and skill-augmented prompt composition.
//!
//! Bundled `SKILL.md` files may be checked out with either LF or CRLF line endings,
//! so every comparison against previously written Sentra content is line-ending
//! agnostic.

use std::{borrow::Cow, path::Path};

/// Splits a Markdown document into its YAML frontmatter (without the `---`
/// delimiters) and the remaining body.
///
/// Returns `(None, content)` when the document does not start with a complete
/// frontmatter block. A leading UTF-8 byte order mark is ignored.
pub(crate) fn split_frontmatter(content: &str) -> (Option<&str>, &str) {
    let text = content.strip_prefix('\u{feff}').unwrap_or(content);
    let Some(after_open) = strip_delimiter_line(text) else {
        return (None, content);
    };

    let mut offset = 0;
    for line in after_open.split_inclusive('\n') {
        if line.trim_end_matches(['\r', '\n']) == "---" {
            let frontmatter = &after_open[..offset];
            let body = &after_open[offset + line.len()..];
            return (Some(frontmatter), body);
        }
        offset += line.len();
    }
    (None, content)
}

/// Returns the document body with any YAML frontmatter and leading blank lines removed.
pub(crate) fn strip_frontmatter(content: &str) -> &str {
    let (_, body) = split_frontmatter(content);
    body.trim_start_matches(['\r', '\n'])
}

/// Normalizes CRLF line endings to LF.
pub(crate) fn normalize_newlines(text: &str) -> Cow<'_, str> {
    if text.contains('\r') {
        Cow::Owned(text.replace("\r\n", "\n"))
    } else {
        Cow::Borrowed(text)
    }
}

/// Compares two byte buffers as text while ignoring CRLF/LF differences.
pub(crate) fn same_text_ignoring_newlines(left: &[u8], right: &[u8]) -> bool {
    match (std::str::from_utf8(left), std::str::from_utf8(right)) {
        (Ok(l), Ok(r)) => normalize_newlines(l) == normalize_newlines(r),
        _ => left == right,
    }
}

/// Display form of a path for human-readable messages: no Windows `\\?\`
/// prefix and, on Windows, forward slashes only, so a message never mixes a
/// forward-slash base taken from the environment with `\` components.
pub(crate) fn display_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    let plain = if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        rest.to_owned()
    } else {
        text.into_owned()
    };
    if cfg!(windows) {
        plain.replace('\\', "/")
    } else {
        plain
    }
}

fn strip_delimiter_line(text: &str) -> Option<&str> {
    let rest = text.strip_prefix("---")?;
    rest.strip_prefix("\r\n")
        .or_else(|| rest.strip_prefix('\n'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_lf_and_crlf_frontmatter() {
        let lf = "---\nname: a\n---\n\n# Body\n";
        assert_eq!(split_frontmatter(lf), (Some("name: a\n"), "\n# Body\n"));
        assert_eq!(strip_frontmatter(lf), "# Body\n");

        let crlf = "---\r\nname: a\r\n---\r\n# Body\r\n";
        assert_eq!(split_frontmatter(crlf), (Some("name: a\r\n"), "# Body\r\n"));
    }

    #[test]
    fn leaves_documents_without_closed_frontmatter_untouched() {
        assert_eq!(split_frontmatter("# Title\n"), (None, "# Title\n"));
        assert_eq!(
            split_frontmatter("---\nname: a\n"),
            (None, "---\nname: a\n")
        );
        assert_eq!(split_frontmatter("----\n---\n"), (None, "----\n---\n"));
    }

    #[test]
    fn compares_text_across_line_endings() {
        assert!(same_text_ignoring_newlines(b"a\r\nb\r\n", b"a\nb\n"));
        assert!(!same_text_ignoring_newlines(b"a\nb\n", b"a\nc\n"));
    }
}
