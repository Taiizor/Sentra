//! Conservative, lossless editing of the Codex `config.toml` MCP table.
//!
//! Codex reads MCP servers from `[mcp_servers.<name>]` tables in
//! `config.toml`. Sentra never re-serialises the user's TOML: it scans the
//! document statement by statement (string-, comment- and bracket-aware),
//! then either appends a new `[mcp_servers.sentra]` table or replaces only the
//! `command` / `args` values inside an existing one. Any layout it cannot edit
//! with certainty (inline tables, dotted-key definitions, array tables,
//! duplicate headers, unterminated strings) is refused so the caller can print
//! a manual snippet instead.

use std::ops::Range;

/// Why the document was not edited.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Refusal(pub(crate) String);

enum Stmt {
    Header {
        path: Vec<String>,
        array: bool,
        line_end: usize,
    },
    KeyValue {
        key: Vec<String>,
        value: Range<usize>,
        line_end: usize,
    },
}

struct Scanner<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl Scanner<'_> {
    fn refuse<T>(&self, message: &str) -> Result<T, Refusal> {
        let line = self.text[..self.pos.min(self.text.len())]
            .matches('\n')
            .count()
            + 1;
        Err(Refusal(format!("line {line}: {message}")))
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_spaces(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    fn skip_comment(&mut self) {
        if self.peek() == Some(b'#') {
            while !matches!(self.peek(), None | Some(b'\n')) {
                self.pos += 1;
            }
        }
    }

    /// Consumes trailing whitespace/comment and the line break. Returns the
    /// offset where the statement's line ends (before `\r\n` / `\n`).
    fn finish_line(&mut self) -> Result<usize, Refusal> {
        self.skip_spaces();
        self.skip_comment();
        let end = self.pos;
        match self.peek() {
            None => Ok(end),
            Some(b'\n') => {
                self.pos += 1;
                Ok(end)
            }
            Some(b'\r') if self.bytes.get(self.pos + 1) == Some(&b'\n') => {
                self.pos += 2;
                Ok(end)
            }
            Some(_) => self.refuse("unexpected content after a value"),
        }
    }

    fn key_path(&mut self) -> Result<Vec<String>, Refusal> {
        let mut path = Vec::new();
        loop {
            self.skip_spaces();
            let part = match self.peek() {
                Some(b'"') => {
                    let range = self.single_line_string(b'"')?;
                    decode_basic(&self.text[range.start + 1..range.end - 1])
                        .ok_or_else(|| Refusal("unsupported escape in a quoted key".into()))?
                }
                Some(b'\'') => {
                    let range = self.single_line_string(b'\'')?;
                    self.text[range.start + 1..range.end - 1].to_owned()
                }
                _ => {
                    let start = self.pos;
                    while matches!(
                        self.peek(),
                        Some(b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-')
                    ) {
                        self.pos += 1;
                    }
                    if start == self.pos {
                        return self.refuse("expected a key");
                    }
                    self.text[start..self.pos].to_owned()
                }
            };
            path.push(part);
            self.skip_spaces();
            if self.peek() == Some(b'.') {
                self.pos += 1;
            } else {
                return Ok(path);
            }
        }
    }

    fn single_line_string(&mut self, quote: u8) -> Result<Range<usize>, Refusal> {
        let start = self.pos;
        self.pos += 1;
        loop {
            match self.peek() {
                None | Some(b'\n' | b'\r') => return self.refuse("unterminated string"),
                Some(b'\\') if quote == b'"' => self.pos += 2,
                Some(byte) if byte == quote => {
                    self.pos += 1;
                    return Ok(start..self.pos);
                }
                Some(_) => self.pos += 1,
            }
        }
    }

    fn multi_line_string(&mut self, quote: u8) -> Result<(), Refusal> {
        self.pos += 3;
        loop {
            match self.peek() {
                None => return self.refuse("unterminated multi-line string"),
                Some(b'\\') if quote == b'"' => self.pos += 2,
                Some(byte)
                    if byte == quote
                        && self.bytes.get(self.pos + 1) == Some(&quote)
                        && self.bytes.get(self.pos + 2) == Some(&quote) =>
                {
                    self.pos += 3;
                    // Up to two quotes may directly precede the delimiter.
                    let mut extra = 0;
                    while extra < 2 && self.peek() == Some(quote) {
                        self.pos += 1;
                        extra += 1;
                    }
                    return Ok(());
                }
                Some(_) => self.pos += 1,
            }
        }
    }

    fn string_any(&mut self) -> Result<(), Refusal> {
        let quote = self.bytes[self.pos];
        if self.bytes.get(self.pos + 1) == Some(&quote)
            && self.bytes.get(self.pos + 2) == Some(&quote)
        {
            self.multi_line_string(quote)
        } else {
            self.single_line_string(quote).map(|_| ())
        }
    }

    fn value(&mut self) -> Result<Range<usize>, Refusal> {
        let start = self.pos;
        match self.peek() {
            Some(b'"' | b'\'') => self.string_any()?,
            Some(b'[' | b'{') => {
                let mut depth = 0usize;
                loop {
                    match self.peek() {
                        None => return self.refuse("unterminated array or inline table"),
                        Some(b'"' | b'\'') => self.string_any()?,
                        Some(b'#') => self.skip_comment(),
                        Some(b'[' | b'{') => {
                            depth += 1;
                            self.pos += 1;
                        }
                        Some(b']' | b'}') => {
                            depth -= 1;
                            self.pos += 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        Some(_) => self.pos += 1,
                    }
                }
            }
            _ => {
                while !matches!(
                    self.peek(),
                    None | Some(b' ' | b'\t' | b'#' | b'\r' | b'\n')
                ) {
                    self.pos += 1;
                }
                if start == self.pos {
                    return self.refuse("missing value");
                }
            }
        }
        Ok(start..self.pos)
    }

    fn statements(mut self) -> Result<Vec<Stmt>, Refusal> {
        let mut out = Vec::new();
        while self.pos < self.bytes.len() {
            self.skip_spaces();
            match self.peek() {
                None => break,
                Some(b'#' | b'\r' | b'\n') => {
                    self.finish_line()?;
                }
                Some(b'[') => {
                    let array = self.bytes.get(self.pos + 1) == Some(&b'[');
                    self.pos += if array { 2 } else { 1 };
                    let path = self.key_path()?;
                    let close: &[u8] = if array { b"]]" } else { b"]" };
                    if !self.bytes[self.pos..].starts_with(close) {
                        return self.refuse("malformed table header");
                    }
                    self.pos += close.len();
                    let line_end = self.finish_line()?;
                    out.push(Stmt::Header {
                        path,
                        array,
                        line_end,
                    });
                }
                Some(_) => {
                    let key = self.key_path()?;
                    if self.peek() != Some(b'=') {
                        return self.refuse("expected '=' after a key");
                    }
                    self.pos += 1;
                    self.skip_spaces();
                    let value = self.value()?;
                    let line_end = self.finish_line()?;
                    out.push(Stmt::KeyValue {
                        key,
                        value,
                        line_end,
                    });
                }
            }
        }
        Ok(out)
    }
}

fn decode_basic(raw: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next()? {
            'b' => out.push('\u{8}'),
            't' => out.push('\t'),
            'n' => out.push('\n'),
            'f' => out.push('\u{c}'),
            'r' => out.push('\r'),
            'e' => out.push('\u{1b}'),
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            'u' => {
                let hex: String = chars.by_ref().take(4).collect();
                out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
            }
            'U' => {
                let hex: String = chars.by_ref().take(8).collect();
                out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
            }
            'x' => {
                let hex: String = chars.by_ref().take(2).collect();
                out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Parses a single-line basic or literal string value.
fn parse_string(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') && !raw.starts_with("'''") {
        return Some(raw[1..raw.len() - 1].to_owned());
    }
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') && !raw.starts_with("\"\"\"") {
        return decode_basic(&raw[1..raw.len() - 1]);
    }
    None
}

/// Parses an array whose elements are all single-line strings.
fn parse_string_array(raw: &str) -> Option<Vec<String>> {
    let inner = raw.trim().strip_prefix('[')?.strip_suffix(']')?;
    let mut scanner = Scanner {
        text: inner,
        bytes: inner.as_bytes(),
        pos: 0,
    };
    let mut items = Vec::new();
    loop {
        loop {
            match scanner.peek() {
                Some(b' ' | b'\t' | b'\r' | b'\n') => scanner.pos += 1,
                Some(b'#') => scanner.skip_comment(),
                _ => break,
            }
        }
        match scanner.peek() {
            None => return Some(items),
            Some(b'"' | b'\'') => {
                let quote = scanner.bytes[scanner.pos];
                let range = scanner.single_line_string(quote).ok()?;
                items.push(parse_string(&inner[range])?);
            }
            Some(_) => return None,
        }
        loop {
            match scanner.peek() {
                Some(b' ' | b'\t' | b'\r' | b'\n') => scanner.pos += 1,
                Some(b'#') => scanner.skip_comment(),
                _ => break,
            }
        }
        match scanner.peek() {
            Some(b',') => scanner.pos += 1,
            None => return Some(items),
            Some(_) => return None,
        }
    }
}

/// Renders a TOML string, preferring a literal string for Windows paths.
pub(crate) fn toml_string(value: &str) -> String {
    let literal_safe = !value.contains('\'')
        && value
            .chars()
            .all(|ch| ch == '\t' || (!ch.is_control() && ch != '\u{7f}'));
    if literal_safe && value.contains('\\') {
        return format!("'{value}'");
    }
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04X}", u32::from(ch))),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn toml_array(items: &[String]) -> String {
    format!(
        "[{}]",
        items
            .iter()
            .map(|item| toml_string(item))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Renders the full `[mcp_servers.<name>]` table (used for new files and snippets).
pub(crate) fn render_table(name: &str, command: &str, args: &[String], eol: &str) -> String {
    format!(
        "[mcp_servers.{name}]{eol}command = {}{eol}args = {}{eol}",
        toml_string(command),
        toml_array(args)
    )
}

/// Ensures `[mcp_servers.<name>]` has the given `command` and `args`.
///
/// Returns `Ok(None)` when nothing needs to change.
pub(crate) fn upsert_server(
    text: &str,
    name: &str,
    command: &str,
    args: &[String],
) -> Result<Option<String>, Refusal> {
    let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let statements = Scanner {
        text,
        bytes: text.as_bytes(),
        pos: 0,
    }
    .statements()?;

    let target = ["mcp_servers".to_owned(), name.to_owned()];
    let mut table: Vec<String> = Vec::new();
    let mut header_end: Option<usize> = None;
    let mut subtable_without_header = false;
    let mut section: Vec<(&str, Range<usize>, usize)> = Vec::new();
    let mut last_section_line: Option<usize> = None;

    for statement in &statements {
        match statement {
            Stmt::Header {
                path,
                array,
                line_end,
            } => {
                if path.first().map(String::as_str) == Some("mcp_servers") {
                    if *array {
                        return Err(Refusal(
                            "mcp_servers is declared as an array of tables ([[mcp_servers...]])"
                                .into(),
                        ));
                    }
                    if path.as_slice() == target {
                        if header_end.is_some() {
                            return Err(Refusal(format!(
                                "[mcp_servers.{name}] is declared more than once"
                            )));
                        }
                        header_end = Some(*line_end);
                        last_section_line = Some(*line_end);
                    } else if path.len() > 2 && path[..2] == target && header_end.is_none() {
                        subtable_without_header = true;
                    }
                }
                table = path.clone();
            }
            Stmt::KeyValue {
                key,
                value,
                line_end,
            } => {
                if table.as_slice() == target {
                    if key.len() == 1 {
                        section.push((key[0].as_str(), value.clone(), *line_end));
                    }
                    last_section_line = Some(*line_end);
                    continue;
                }
                // A key inside a `[mcp_servers.<name>.<sub>]` table (for example the
                // documented `[mcp_servers.<name>.env]`) belongs to that sub-table and
                // is left alone. Only a key/value pair whose own dotted key reaches
                // `mcp_servers.<name>` from a shallower table defines the server
                // outside its `[mcp_servers.<name>]` header.
                if table.len() >= 2 {
                    continue;
                }
                let full: Vec<&str> = table.iter().chain(key.iter()).map(String::as_str).collect();
                if full.first() == Some(&"mcp_servers") {
                    if full.len() == 1 {
                        return Err(Refusal(
                            "mcp_servers is defined as an inline value; Sentra cannot add a table to it"
                                .into(),
                        ));
                    }
                    if full[1] == name {
                        return Err(Refusal(format!(
                            "mcp_servers.{name} is defined with dotted keys or an inline table"
                        )));
                    }
                }
            }
        }
    }

    let Some(_) = header_end else {
        if subtable_without_header {
            return Err(Refusal(format!(
                "a [mcp_servers.{name}.*] sub-table exists without [mcp_servers.{name}]"
            )));
        }
        let mut out = text.to_owned();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push_str(eol);
        }
        if !out.trim().is_empty() {
            out.push_str(eol);
        }
        out.push_str(&render_table(name, command, args, eol));
        return Ok(Some(out));
    };

    let mut edits: Vec<(Range<usize>, String)> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    let count = |key: &str| section.iter().filter(|(k, _, _)| *k == key).count();
    if count("command") > 1 || count("args") > 1 {
        return Err(Refusal(format!(
            "[mcp_servers.{name}] defines a key more than once"
        )));
    }
    match section.iter().find(|(key, _, _)| *key == "command") {
        Some((_, range, _)) => {
            if parse_string(&text[range.clone()]).as_deref() != Some(command) {
                edits.push((range.clone(), toml_string(command)));
            }
        }
        None => missing.push(format!("command = {}", toml_string(command))),
    }
    match section.iter().find(|(key, _, _)| *key == "args") {
        Some((_, range, _)) => {
            if parse_string_array(&text[range.clone()]).as_deref() != Some(args) {
                edits.push((range.clone(), toml_array(args)));
            }
        }
        None => missing.push(format!("args = {}", toml_array(args))),
    }
    if !missing.is_empty() {
        let at = last_section_line.unwrap_or(text.len());
        let mut insert = String::new();
        for line in missing {
            insert.push_str(eol);
            insert.push_str(&line);
        }
        edits.push((at..at, insert));
    }
    if edits.is_empty() {
        return Ok(None);
    }
    edits.sort_by_key(|edit| std::cmp::Reverse(edit.0.start));
    let mut out = text.to_owned();
    for (range, replacement) in edits {
        out.replace_range(range, &replacement);
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Vec<String> {
        vec!["mcp".to_owned()]
    }

    #[test]
    fn appends_table_and_keeps_existing_text() {
        let text = "# my config\nmodel = \"o4\"\n\n[mcp_servers.other]\ncommand = \"x\"\n";
        let out = upsert_server(text, "sentra", "C:\\bin\\sentra.exe", &args())
            .unwrap()
            .unwrap();
        assert!(out.starts_with(text));
        assert!(out.ends_with(
            "[mcp_servers.sentra]\ncommand = 'C:\\bin\\sentra.exe'\nargs = [\"mcp\"]\n"
        ));
    }

    #[test]
    fn updates_only_command_and_args() {
        let text = "[mcp_servers.sentra]\ncommand = \"old\" # keep me\nenv = { A = \"1\" }\nargs = [\n  \"x\",\n]\n\n[other]\nk = 1\n";
        let out = upsert_server(text, "sentra", "/usr/bin/sentra", &args())
            .unwrap()
            .unwrap();
        assert_eq!(
            out,
            "[mcp_servers.sentra]\ncommand = \"/usr/bin/sentra\" # keep me\nenv = { A = \"1\" }\nargs = [\"mcp\"]\n\n[other]\nk = 1\n"
        );
        assert_eq!(
            upsert_server(&out, "sentra", "/usr/bin/sentra", &args()).unwrap(),
            None
        );
    }

    #[test]
    fn inserts_missing_keys_inside_section() {
        let text = "[mcp_servers.sentra]\nenabled = true\n[x]\n";
        let out = upsert_server(text, "sentra", "s", &args())
            .unwrap()
            .unwrap();
        assert_eq!(
            out,
            "[mcp_servers.sentra]\nenabled = true\ncommand = \"s\"\nargs = [\"mcp\"]\n[x]\n"
        );
    }

    #[test]
    fn refuses_ambiguous_layouts() {
        for text in [
            "mcp_servers = { a = { command = \"x\" } }\n",
            "[mcp_servers]\nsentra = { command = \"x\" }\n",
            "mcp_servers.sentra.command = \"x\"\n",
            "[[mcp_servers]]\nname = \"x\"\n",
            "[mcp_servers.sentra]\n[mcp_servers.sentra]\n",
            "a = \"\"\"unterminated\n",
            "[mcp_servers.sentra.env]\nA = \"1\"\n",
        ] {
            assert!(
                upsert_server(text, "sentra", "s", &args()).is_err(),
                "should refuse: {text}"
            );
        }
    }

    #[test]
    fn rerun_keeps_documented_sub_tables_byte_for_byte() {
        // Layout from the Codex MCP docs: env lives in its own sub-table.
        let text = "[mcp_servers.sentra]\ncommand = \"old\"\n\n[mcp_servers.sentra.env]\nSENTRA_TOKEN = \"keep\"\n\n[mcp_servers.sentra.tools.scan]\napproval_mode = \"approve\"\n";
        let out = upsert_server(text, "sentra", "/usr/bin/sentra", &args())
            .unwrap()
            .unwrap();
        assert_eq!(
            out,
            "[mcp_servers.sentra]\ncommand = \"/usr/bin/sentra\"\nargs = [\"mcp\"]\n\n[mcp_servers.sentra.env]\nSENTRA_TOKEN = \"keep\"\n\n[mcp_servers.sentra.tools.scan]\napproval_mode = \"approve\"\n"
        );
        assert_eq!(
            upsert_server(&out, "sentra", "/usr/bin/sentra", &args()).unwrap(),
            None
        );

        // A sub-table declared before its parent header is also valid TOML.
        let before = "[mcp_servers.sentra.env]\nA = \"1\"\n\n[mcp_servers.sentra]\ncommand = \"old\"\nargs = [\"mcp\"]\n";
        let out = upsert_server(before, "sentra", "s", &args())
            .unwrap()
            .unwrap();
        assert_eq!(
            out,
            "[mcp_servers.sentra.env]\nA = \"1\"\n\n[mcp_servers.sentra]\ncommand = \"s\"\nargs = [\"mcp\"]\n"
        );

        // Another server's sub-tables never matter.
        let other = "[mcp_servers.other.env]\nA = \"1\"\n";
        assert!(
            upsert_server(other, "sentra", "s", &args())
                .unwrap()
                .unwrap()
                .ends_with("[mcp_servers.sentra]\ncommand = \"s\"\nargs = [\"mcp\"]\n")
        );
    }

    #[test]
    fn multi_line_strings_do_not_confuse_the_scanner() {
        let text = "notes = \"\"\"\n[mcp_servers.sentra]\ncommand = \"fake\"\n\"\"\"\n";
        let out = upsert_server(text, "sentra", "s", &args())
            .unwrap()
            .unwrap();
        assert!(out.starts_with(text));
        assert!(out.ends_with("\n[mcp_servers.sentra]\ncommand = \"s\"\nargs = [\"mcp\"]\n"));
    }
}
