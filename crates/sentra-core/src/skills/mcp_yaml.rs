//! Conservative, lossless editing of block-style YAML MCP configuration.
//!
//! Goose (`extensions:` in `config.yaml`), Hermes (`mcp_servers:` in
//! `~/.hermes/config.yaml`) and Continue block files (`mcpServers:` list) keep
//! MCP servers in YAML. Sentra does not ship a YAML library and never
//! re-serialises user YAML. Instead this module recognises the plain
//! block-mapping layout those tools write, and edits only the lines of the
//! `sentra` entry (or appends a new entry). Anything outside that subset
//! (flow collections, anchors, tags, multiple documents, tab indentation,
//! multi-line values on managed keys) is refused, so the caller can print a
//! manual snippet instead of risking the user's file.

/// Why the document was not edited.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Refusal(pub(crate) String);

fn refuse<T>(message: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal(message.into()))
}

/// A value Sentra writes into YAML.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum YamlValue {
    /// A string scalar (quoted when needed).
    Str(String),
    /// A literal token such as `true`, `300`, `{}` or `[]`.
    Raw(&'static str),
    /// A block sequence of string scalars.
    Seq(Vec<String>),
}

/// Where the managed entry lives below the top-level key.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Locate<'a> {
    /// `top_key: { <name>: { ... } }` (Goose, Hermes).
    MapKey(&'a str),
    /// `top_key: [ { name: <name>, ... } ]` (Continue block files).
    SeqItemByName(&'a str),
}

/// Request to ensure an MCP entry exists.
#[derive(Clone, Debug)]
pub(crate) struct Entry<'a> {
    pub(crate) top_key: &'a str,
    pub(crate) locate: Locate<'a>,
    /// Fields of a brand-new entry, in order.
    pub(crate) fresh: Vec<(&'a str, YamlValue)>,
    /// Fields updated (and only these) on an existing entry.
    pub(crate) managed: Vec<(&'a str, YamlValue)>,
}

#[derive(Clone, Copy, Debug)]
struct Line<'a> {
    /// Offset of the first byte of the line.
    start: usize,
    /// Offset just past the last content byte (before `\r\n` / `\n`).
    end: usize,
    /// Offset of the next line (after the line break), or `end` at EOF.
    next: usize,
    indent: usize,
    body: &'a str,
}

impl Line<'_> {
    fn is_trivia(&self) -> bool {
        self.body.is_empty() || self.body.starts_with('#')
    }

    fn body_start(&self) -> usize {
        self.start + self.indent
    }
}

fn split_lines(text: &str) -> Result<Vec<Line<'_>>, Refusal> {
    let mut lines = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let (end, next) = match text[start..].find('\n') {
            Some(offset) => {
                let newline = start + offset;
                let end = if newline > start && text.as_bytes()[newline - 1] == b'\r' {
                    newline - 1
                } else {
                    newline
                };
                (end, newline + 1)
            }
            None => (text.len(), text.len()),
        };
        let raw = &text[start..end];
        let indent = raw.bytes().take_while(|byte| *byte == b' ').count();
        let body = raw[indent..].trim_end();
        if body.starts_with('\t') {
            return refuse(format!("line {} is indented with a tab", lines.len() + 1));
        }
        lines.push(Line {
            start,
            end,
            next,
            indent,
            body,
        });
        start = next;
    }
    Ok(lines)
}

/// Parses a quoted or plain scalar at the start of `text`. Returns the
/// decoded value and the byte length of the scalar token.
fn parse_scalar(text: &str) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    match bytes.first()? {
        b'"' => {
            let mut out = String::new();
            let mut chars = text.char_indices().skip(1);
            while let Some((index, ch)) = chars.next() {
                match ch {
                    '"' => return Some((out, index + 1)),
                    '\\' => {
                        let (_, escape) = chars.next()?;
                        match escape {
                            '\\' => out.push('\\'),
                            '"' => out.push('"'),
                            '/' => out.push('/'),
                            'n' => out.push('\n'),
                            't' => out.push('\t'),
                            'r' => out.push('\r'),
                            '0' => out.push('\0'),
                            'u' | 'x' | 'U' => {
                                let width = match escape {
                                    'x' => 2,
                                    'u' => 4,
                                    _ => 8,
                                };
                                let hex: String =
                                    chars.by_ref().take(width).map(|(_, ch)| ch).collect();
                                out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                            }
                            _ => return None,
                        }
                    }
                    ch => out.push(ch),
                }
            }
            None
        }
        b'\'' => {
            let mut out = String::new();
            let mut index = 1;
            while index < text.len() {
                let rest = &text[index..];
                if let Some(after) = rest.strip_prefix("''") {
                    out.push('\'');
                    index = text.len() - after.len();
                } else if rest.starts_with('\'') {
                    return Some((out, index + 1));
                } else {
                    let ch = rest.chars().next()?;
                    out.push(ch);
                    index += ch.len_utf8();
                }
            }
            None
        }
        b'[' | b'{' | b'&' | b'*' | b'!' | b'|' | b'>' | b'%' | b'@' | b'`' | b'#' => None,
        _ => {
            let end = text.find(" #").unwrap_or(text.len());
            let value = text[..end].trim_end();
            if value.is_empty() || value.contains(": ") || value.ends_with(':') {
                return None;
            }
            Some((value.to_owned(), value.len()))
        }
    }
}

/// True when the remainder of a line after a value is blank or a comment.
fn rest_is_trivia(rest: &str) -> bool {
    let rest = rest.trim_start();
    rest.is_empty() || rest.starts_with('#')
}

/// Checks the text after `key:` on one line (`rest`, starting right after the
/// colon) and returns why YAML rejects it, if it does.
///
/// Sentra edits YAML line by line, so a syntax error elsewhere in the file would
/// survive the edit and the agent would still fail to load the file while the
/// installer reported success. This catches the errors a line-level check can
/// see: values starting with a reserved or structural indicator (`: x`, `- x`,
/// `]`, `@`, ...), plain scalars containing `: ` or ending in `:` (a nested
/// mapping on the same line) and trailing text after a closed quoted scalar,
/// alias or block-scalar header. Constructs that may continue on later lines
/// (flow collections, unterminated quoted scalars) are accepted as they start.
pub(crate) fn inline_value_problem(rest: &str) -> Option<&'static str> {
    let mut value = rest.trim_start_matches([' ', '\t']);
    // Node properties (anchor `&a`, tag `!t`) may precede the value.
    while let Some(after) = value.strip_prefix('&').or_else(|| value.strip_prefix('!')) {
        let end = after.find([' ', '\t']).unwrap_or(after.len());
        value = after[end..].trim_start_matches([' ', '\t']);
    }
    let bytes = value.as_bytes();
    let &first = bytes.first()?;
    let separated = |index: usize| bytes.get(index).is_none_or(|b| matches!(b, b' ' | b'\t'));
    let trailing = |index: usize| {
        (!rest_is_trivia(&value[index..])).then_some("unexpected text after a value")
    };
    match first {
        b'#' | b'[' | b'{' => None,
        b'"' | b'\'' => {
            let mut index = 1;
            while index < bytes.len() {
                match bytes[index] {
                    b'\\' if first == b'"' => index += 2,
                    b'\'' if first == b'\'' && bytes.get(index + 1) == Some(&b'\'') => index += 2,
                    byte if byte == first => return trailing(index + 1),
                    _ => index += 1,
                }
            }
            None
        }
        b'|' | b'>' => {
            let end = 1 + value[1..]
                .bytes()
                .take_while(|b| matches!(b, b'+' | b'-' | b'1'..=b'9'))
                .count();
            trailing(end)
        }
        b'*' => {
            let end = value.find([' ', '\t']).unwrap_or(value.len());
            if end == 1 {
                return Some("an alias needs a name");
            }
            trailing(end)
        }
        b',' | b']' | b'}' | b'%' | b'@' | b'`' => {
            Some("a value cannot start with a reserved or flow indicator")
        }
        b'-' | b'?' | b':' if separated(1) => {
            Some("a block indicator (`- `, `? `, `: `) cannot follow `key:` on the same line")
        }
        _ => {
            let end = [" #", "\t#"]
                .iter()
                .filter_map(|marker| value.find(marker))
                .min()
                .unwrap_or(value.len());
            let plain = value[..end].trim_end_matches([' ', '\t']);
            if plain.contains(": ") || plain.contains(":\t") || plain.ends_with(':') {
                Some("a plain value contains `: ` (a nested mapping on the same line)")
            } else {
                None
            }
        }
    }
}

/// True for a block sequence item line (`- value` or a bare `-`).
fn is_seq_item(body: &str) -> bool {
    body == "-" || body.starts_with("- ")
}

/// Parses `key:` at the start of `body`; returns the key and the offset of
/// the text following the colon.
fn parse_key(body: &str) -> Option<(String, usize)> {
    if body.starts_with('"') || body.starts_with('\'') {
        let (key, length) = parse_scalar(body)?;
        let rest = &body[length..];
        let rest = rest.strip_prefix(':')?;
        if !(rest.is_empty() || rest.starts_with(' ')) {
            return None;
        }
        return Some((key, length + 1));
    }
    if body.starts_with([
        '-', '?', '[', '{', '&', '*', '!', '|', '>', '%', '@', '`', '#',
    ]) {
        return None;
    }
    let mut search = 0;
    loop {
        let colon = search + body[search..].find(':')?;
        let after = &body[colon + 1..];
        if after.is_empty() || after.starts_with(' ') {
            let key = body[..colon].trim_end();
            if key.is_empty() || key.contains(" #") {
                return None;
            }
            return Some((key.to_owned(), colon + 1));
        }
        search = colon + 1;
    }
}

/// The value written after `key:` on the same line.
enum Inline {
    Empty,
    /// Byte range (absolute) of the inline value token.
    Value(usize, usize),
}

fn inline_after(text: &str, line: &Line<'_>, rest_offset: usize) -> Inline {
    let absolute = line.body_start() + rest_offset;
    let rest = &text[absolute..line.end];
    let trimmed = rest.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Inline::Empty;
    }
    let start = absolute + (rest.len() - trimmed.len());
    let end = trimmed.find(" #").map_or(line.end, |index| start + index);
    let token = text[start..end].trim_end();
    Inline::Value(start, start + token.len())
}

fn is_plain_safe(value: &str) -> bool {
    const RESERVED: [&str; 12] = [
        "true", "false", "yes", "no", "on", "off", "null", "y", "n", "~", "nan", "inf",
    ];
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '/' | '-' | '+' | '@'))
        && !value.starts_with([
            '-', '.', '@', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        ])
        && !RESERVED.contains(&value.to_ascii_lowercase().as_str())
}

/// Renders a string scalar (plain when unambiguous, double-quoted otherwise).
pub(crate) fn yaml_string(value: &str) -> String {
    if is_plain_safe(value) {
        return value.to_owned();
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

fn render_field(key: &str, value: &YamlValue, indent: &str, eol: &str) -> String {
    match value {
        YamlValue::Str(text) => format!("{indent}{key}: {}", yaml_string(text)),
        YamlValue::Raw(token) => format!("{indent}{key}: {token}"),
        YamlValue::Seq(items) if items.is_empty() => format!("{indent}{key}: []"),
        YamlValue::Seq(items) => {
            let mut out = format!("{indent}{key}:");
            for item in items {
                out.push_str(eol);
                out.push_str(indent);
                out.push_str("  - ");
                out.push_str(&yaml_string(item));
            }
            out
        }
    }
}

fn render_entry(entry: &Entry<'_>, indent: &str, unit: &str, eol: &str) -> String {
    match entry.locate {
        Locate::MapKey(name) => {
            let inner = format!("{indent}{unit}");
            let mut out = format!("{indent}{}:", yaml_key(name));
            for (key, value) in &entry.fresh {
                out.push_str(eol);
                out.push_str(&render_field(key, value, &inner, eol));
            }
            out
        }
        Locate::SeqItemByName(_) => {
            let inner = format!("{indent}  ");
            let mut out = String::new();
            for (index, (key, value)) in entry.fresh.iter().enumerate() {
                if index == 0 {
                    let field = render_field(key, value, &inner, eol);
                    out.push_str(indent);
                    out.push_str("- ");
                    out.push_str(&field[inner.len()..]);
                } else {
                    out.push_str(eol);
                    out.push_str(&render_field(key, value, &inner, eol));
                }
            }
            out
        }
    }
}

fn yaml_key(key: &str) -> String {
    yaml_string(key)
}

/// Renders `top_key:` followed by the entry (used for new files and snippets).
pub(crate) fn render_block(entry: &Entry<'_>, eol: &str) -> String {
    format!(
        "{}:{eol}{}{eol}",
        yaml_key(entry.top_key),
        render_entry(entry, "  ", "  ", eol)
    )
}

struct Field<'a> {
    line: Line<'a>,
    /// Offset (relative to the line body) of the text after `key:`.
    rest_offset: usize,
}

/// Ensures the entry exists; returns `Ok(None)` when nothing changes.
pub(crate) fn upsert(text: &str, entry: &Entry<'_>) -> Result<Option<String>, Refusal> {
    let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let lines = split_lines(text)?;

    // Validate the document-level layout and find the top key.
    let mut seen_content = false;
    let mut top: Option<(usize, usize)> = None;
    for (index, line) in lines.iter().enumerate() {
        if line.is_trivia() {
            continue;
        }
        if line.indent == 0 {
            if line.body == "---" || line.body.starts_with("--- ") {
                if seen_content {
                    return refuse("the file contains more than one YAML document");
                }
                seen_content = true;
                continue;
            }
            if line.body.starts_with("...") || line.body.starts_with('%') {
                return refuse("YAML directives or document end markers are not supported");
            }
            let Some((key, rest)) = parse_key(line.body) else {
                return refuse(format!(
                    "line {} is not a plain top-level `key:` mapping entry",
                    index + 1
                ));
            };
            if let Some(problem) = inline_value_problem(&line.body[rest..]) {
                return refuse(format!(
                    "line {} is not valid YAML ({problem}); fix it first",
                    index + 1
                ));
            }
            if key == entry.top_key {
                if top.is_some() {
                    return refuse(format!("`{}` appears more than once", entry.top_key));
                }
                top = Some((index, rest));
            }
        }
        seen_content = true;
    }

    let Some((top_index, top_rest)) = top else {
        let mut out = text.to_owned();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push_str(eol);
        }
        out.push_str(&render_block(entry, eol));
        return Ok(Some(out));
    };

    let top_line = lines[top_index];
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let mut empty_inline = false;
    if let Inline::Value(start, end) = inline_after(text, &top_line, top_rest) {
        let token = &text[start..end];
        if matches!(token, "{}" | "[]" | "~" | "null") {
            edits.push((top_line.body_start() + top_rest, end, String::new()));
            empty_inline = true;
        } else {
            return refuse(format!(
                "`{}` uses an inline/flow value that Sentra cannot edit safely",
                entry.top_key
            ));
        }
    }

    // Lines of the top-level block.
    let block_end = lines[top_index + 1..]
        .iter()
        .position(|line| !line.is_trivia() && line.indent == 0)
        .map_or(lines.len(), |offset| top_index + 1 + offset);
    let block: Vec<Line<'_>> = lines[top_index + 1..block_end]
        .iter()
        .copied()
        .filter(|line| !line.is_trivia())
        .collect();
    if empty_inline && !block.is_empty() {
        return refuse(format!(
            "`{}` has both an inline value and nested lines",
            entry.top_key
        ));
    }

    let after = |line: &Line<'_>| -> (usize, String) {
        // Insert after `line`; add a line break first when it ends the file
        // without one.
        if line.next == line.end {
            (line.end, eol.to_owned())
        } else {
            (line.next, String::new())
        }
    };

    let Some(first) = block.first().copied() else {
        let (at, prefix) = after(&top_line);
        let rendered = render_entry(entry, "  ", "  ", eol);
        edits.push((at, at, format!("{prefix}{rendered}{eol}")));
        return Ok(Some(apply(text, edits)));
    };
    let child_indent = first.indent;
    if block.iter().any(|line| line.indent < child_indent) {
        return refuse(format!("`{}` has inconsistent indentation", entry.top_key));
    }
    let child_pad = " ".repeat(child_indent);
    let last_line = *block.last().expect("block is not empty");

    // Locate the entry and collect its field lines.
    let (entry_key_indent, fields, entry_last) = match entry.locate {
        Locate::MapKey(name) => {
            if first.body.starts_with('-') {
                return refuse(format!("`{}` is a list, expected a mapping", entry.top_key));
            }
            let mut found: Option<(usize, usize)> = None;
            for (index, line) in block.iter().enumerate() {
                if line.indent != child_indent {
                    continue;
                }
                let Some((key, rest)) = parse_key(line.body) else {
                    return refuse(format!(
                        "an entry under `{}` is not a plain `key:` line",
                        entry.top_key
                    ));
                };
                if let Some(problem) = inline_value_problem(&line.body[rest..]) {
                    return refuse(format!(
                        "`{}.{key}` is not valid YAML ({problem}); fix it first",
                        entry.top_key
                    ));
                }
                if key == name {
                    if found.is_some() {
                        return refuse(format!("`{name}` appears more than once"));
                    }
                    found = Some((index, rest));
                }
            }
            let Some((index, rest)) = found else {
                let (at, prefix) = after(&last_line);
                let rendered = render_entry(entry, &child_pad, &child_pad, eol);
                edits.push((at, at, format!("{prefix}{rendered}{eol}")));
                return Ok(Some(apply(text, edits)));
            };
            if !matches!(inline_after(text, &block[index], rest), Inline::Empty) {
                return refuse(format!(
                    "`{name}` is written inline; Sentra only edits block mappings"
                ));
            }
            let body: Vec<Line<'_>> = block[index + 1..]
                .iter()
                .copied()
                .take_while(|line| line.indent > child_indent)
                .collect();
            let key_indent = body.first().map_or(child_indent * 2, |line| line.indent);
            let mut fields = Vec::new();
            for line in &body {
                if line.indent < key_indent {
                    return refuse(format!("`{name}` has inconsistent indentation"));
                }
                if line.indent == key_indent && !is_seq_item(line.body) {
                    let Some((field, rest)) = parse_key(line.body) else {
                        return refuse(format!("`{name}` contains a line that is not `key:`"));
                    };
                    if let Some(problem) = inline_value_problem(&line.body[rest..]) {
                        return refuse(format!(
                            "`{name}.{field}` is not valid YAML ({problem}); fix it first"
                        ));
                    }
                    fields.push(Field {
                        line: *line,
                        rest_offset: rest,
                    });
                }
            }
            let last = body.last().copied().unwrap_or(block[index]);
            (key_indent, fields, last)
        }
        Locate::SeqItemByName(name) => {
            if !is_seq_item(first.body) {
                return refuse(format!("`{}` is not a list of entries", entry.top_key));
            }
            let mut found = None;
            let mut index = 0;
            while index < block.len() {
                let line = block[index];
                if line.indent != child_indent || !line.body.starts_with("- ") {
                    return refuse(format!(
                        "`{}` contains an item Sentra cannot parse",
                        entry.top_key
                    ));
                }
                let dash_body = &line.body[2..];
                let gap = dash_body.len() - dash_body.trim_start().len();
                let key_indent = child_indent + 2 + gap;
                let mut fields = Vec::new();
                match parse_key(dash_body.trim_start()) {
                    Some((_, rest))
                        if inline_value_problem(&dash_body.trim_start()[rest..]).is_some() =>
                    {
                        return refuse(format!(
                            "an item of `{}` is not valid YAML; fix it first",
                            entry.top_key
                        ));
                    }
                    Some((_, rest)) => fields.push(Field {
                        line: Line {
                            indent: key_indent,
                            body: dash_body.trim_start(),
                            ..line
                        },
                        rest_offset: rest,
                    }),
                    None => {
                        return refuse(format!("an item of `{}` is not a mapping", entry.top_key));
                    }
                }
                let mut last = line;
                index += 1;
                while index < block.len() && block[index].indent > child_indent {
                    let inner = block[index];
                    if inner.indent == key_indent && !is_seq_item(inner.body) {
                        let Some((_, rest)) = parse_key(inner.body) else {
                            return refuse("a list item contains a line that is not `key:`");
                        };
                        if inline_value_problem(&inner.body[rest..]).is_some() {
                            return refuse(format!(
                                "an item of `{}` is not valid YAML; fix it first",
                                entry.top_key
                            ));
                        }
                        fields.push(Field {
                            line: inner,
                            rest_offset: rest,
                        });
                    } else if inner.indent < key_indent {
                        return refuse("a list item has inconsistent indentation");
                    }
                    last = inner;
                    index += 1;
                }
                let is_match = fields.iter().any(|field| {
                    parse_key(field.line.body).is_some_and(|(key, _)| key == "name")
                        && field_scalar(text, field).as_deref() == Some(name)
                });
                if is_match {
                    if found.is_some() {
                        return refuse(format!("more than one `{name}` item exists"));
                    }
                    found = Some((key_indent, fields, last));
                }
            }
            let Some(found) = found else {
                let (at, prefix) = after(&last_line);
                let rendered = render_entry(entry, &child_pad, &child_pad, eol);
                edits.push((at, at, format!("{prefix}{rendered}{eol}")));
                return Ok(Some(apply(text, edits)));
            };
            found
        }
    };

    // Update managed fields in place; append missing ones.
    let key_pad = " ".repeat(entry_key_indent);
    let mut appended = Vec::new();
    for (key, desired) in &entry.managed {
        let matches: Vec<&Field<'_>> = fields
            .iter()
            .filter(|field| parse_key(field.line.body).is_some_and(|(name, _)| name == *key))
            .collect();
        if matches.len() > 1 {
            return refuse(format!("`{key}` appears more than once in the entry"));
        }
        let Some(field) = matches.first() else {
            appended.push(render_field(key, desired, &key_pad, eol));
            continue;
        };
        match desired {
            YamlValue::Str(_) | YamlValue::Raw(_) => {
                let rendered = match desired {
                    YamlValue::Str(value) => yaml_string(value),
                    YamlValue::Raw(token) => (*token).to_owned(),
                    YamlValue::Seq(_) => unreachable!("handled above"),
                };
                match inline_after(text, &field.line, field.rest_offset) {
                    Inline::Value(start, end) => {
                        let current = parse_scalar(&text[start..end]);
                        let wanted = match desired {
                            YamlValue::Str(value) => value.clone(),
                            YamlValue::Raw(token) => (*token).to_owned(),
                            YamlValue::Seq(_) => unreachable!("handled above"),
                        };
                        match current {
                            Some((value, length)) if length == end - start => {
                                if value != wanted {
                                    edits.push((start, end, rendered));
                                }
                            }
                            _ => {
                                return refuse(format!(
                                    "`{key}` has a value Sentra cannot parse safely"
                                ));
                            }
                        }
                    }
                    Inline::Empty => {
                        return refuse(format!(
                            "`{key}` uses a multi-line value Sentra cannot edit safely"
                        ));
                    }
                }
            }
            YamlValue::Seq(items) => {
                let (current, region) = read_sequence(text, &lines, field, entry_key_indent)?;
                if current != *items {
                    match region {
                        SeqRegion::Flow(start, end) => {
                            let rendered = format!(
                                "[{}]",
                                items
                                    .iter()
                                    .map(|item| yaml_string(item))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            );
                            edits.push((start, end, rendered));
                        }
                        SeqRegion::Block {
                            start,
                            end,
                            item_indent,
                        } => {
                            let pad = " ".repeat(item_indent);
                            let mut rendered = String::new();
                            for item in items {
                                rendered.push_str(eol);
                                rendered.push_str(&pad);
                                rendered.push_str("- ");
                                rendered.push_str(&yaml_string(item));
                            }
                            edits.push((start, end, rendered));
                        }
                    }
                }
            }
        }
    }
    if !appended.is_empty() {
        let (at, prefix) = after(&entry_last);
        edits.push((at, at, format!("{prefix}{}{eol}", appended.join(eol))));
    }
    if edits.is_empty() {
        return Ok(None);
    }
    Ok(Some(apply(text, edits)))
}

fn field_scalar(text: &str, field: &Field<'_>) -> Option<String> {
    match inline_after(text, &field.line, field.rest_offset) {
        Inline::Value(start, end) => {
            let (value, length) = parse_scalar(&text[start..end])?;
            (length == end - start).then_some(value)
        }
        Inline::Empty => None,
    }
}

enum SeqRegion {
    /// Inline flow sequence token range.
    Flow(usize, usize),
    /// Range from the end of the `key:` line to the end of the last item.
    Block {
        start: usize,
        end: usize,
        item_indent: usize,
    },
}

fn parse_flow_sequence(token: &str) -> Option<Vec<String>> {
    let inner = token.strip_prefix('[')?.strip_suffix(']')?;
    let mut items = Vec::new();
    let mut rest = inner.trim_start();
    while !rest.is_empty() {
        let (value, length) = if rest.starts_with('"') || rest.starts_with('\'') {
            parse_scalar(rest)?
        } else {
            let end = rest.find(',').unwrap_or(rest.len());
            let value = rest[..end].trim();
            if value.is_empty() || value.contains(['[', ']', '{', '}', '#']) {
                return None;
            }
            (value.to_owned(), end)
        };
        items.push(value);
        rest = rest[length..].trim_start();
        match rest.strip_prefix(',') {
            Some(after) => rest = after.trim_start(),
            None if rest.is_empty() => {}
            None => return None,
        }
    }
    Some(items)
}

fn read_sequence(
    text: &str,
    lines: &[Line<'_>],
    field: &Field<'_>,
    key_indent: usize,
) -> Result<(Vec<String>, SeqRegion), Refusal> {
    match inline_after(text, &field.line, field.rest_offset) {
        Inline::Value(start, end) => {
            let items = parse_flow_sequence(&text[start..end])
                .ok_or_else(|| Refusal("`args` uses a value Sentra cannot parse safely".into()))?;
            Ok((items, SeqRegion::Flow(start, end)))
        }
        Inline::Empty => {
            let position = lines
                .iter()
                .position(|line| line.start == field.line.start)
                .ok_or_else(|| Refusal("internal line lookup failed".into()))?;
            let mut items = Vec::new();
            let mut end = field.line.end;
            let mut item_indent = key_indent + 2;
            for (offset, line) in lines[position + 1..].iter().enumerate() {
                if line.is_trivia() {
                    continue;
                }
                let is_item = is_seq_item(line.body) && line.indent >= key_indent;
                if !is_item {
                    if line.indent > key_indent {
                        return Err(Refusal(
                            "`args` contains nested values Sentra cannot edit safely".into(),
                        ));
                    }
                    break;
                }
                if offset == 0 || items.is_empty() {
                    item_indent = line.indent;
                } else if line.indent != item_indent {
                    return Err(Refusal("`args` has inconsistent indentation".into()));
                }
                let value_text = line.body[1..].trim_start();
                let (value, length) = parse_scalar(value_text).ok_or_else(|| {
                    Refusal("`args` contains an item Sentra cannot parse safely".into())
                })?;
                if !rest_is_trivia(&value_text[length..]) {
                    return Err(Refusal(
                        "`args` contains an item Sentra cannot parse safely".into(),
                    ));
                }
                items.push(value);
                end = line.end;
            }
            Ok((
                items,
                SeqRegion::Block {
                    start: field.line.end,
                    end,
                    item_indent,
                },
            ))
        }
    }
}

fn apply(text: &str, mut edits: Vec<(usize, usize, String)>) -> String {
    edits.sort_by_key(|edit| std::cmp::Reverse(edit.0));
    let mut out = text.to_owned();
    for (start, end, replacement) in edits {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn goose(command: &str) -> Entry<'static> {
        Entry {
            top_key: "extensions",
            locate: Locate::MapKey("sentra"),
            fresh: vec![
                ("name", YamlValue::Str("sentra".into())),
                ("type", YamlValue::Raw("stdio")),
                ("cmd", YamlValue::Str(command.into())),
                ("args", YamlValue::Seq(vec!["mcp".into()])),
                ("enabled", YamlValue::Raw("true")),
            ],
            managed: vec![
                ("cmd", YamlValue::Str(command.into())),
                ("args", YamlValue::Seq(vec!["mcp".into()])),
            ],
        }
    }

    #[test]
    fn appends_top_key_when_missing() {
        let text = "GOOSE_PROVIDER: openai\n";
        let out = upsert(text, &goose("C:\\s.exe")).unwrap().unwrap();
        assert_eq!(
            out,
            "GOOSE_PROVIDER: openai\nextensions:\n  sentra:\n    name: sentra\n    type: stdio\n    cmd: \"C:\\\\s.exe\"\n    args:\n      - mcp\n    enabled: true\n"
        );
    }

    #[test]
    fn inserts_entry_after_existing_extensions() {
        let text = "extensions:\n  developer:\n    enabled: true\n    type: builtin\n# trailing\nOTHER: 1\n";
        let out = upsert(text, &goose("/bin/s")).unwrap().unwrap();
        assert!(out.starts_with("extensions:\n  developer:\n    enabled: true\n    type: builtin\n  sentra:\n    name: sentra\n"));
        assert!(out.ends_with("# trailing\nOTHER: 1\n"));
    }

    #[test]
    fn rerun_updates_only_cmd_and_args() {
        let text = "extensions:\n  sentra:\n    cmd: /old/sentra # pinned\n    args:\n    - x\n    envs:\n      KEY: value\n    timeout: 300\n";
        let out = upsert(text, &goose("/new/sentra")).unwrap().unwrap();
        assert_eq!(
            out,
            "extensions:\n  sentra:\n    cmd: /new/sentra # pinned\n    args:\n    - mcp\n    envs:\n      KEY: value\n    timeout: 300\n"
        );
        assert_eq!(upsert(&out, &goose("/new/sentra")).unwrap(), None);
    }

    #[test]
    fn refuses_unsupported_layouts() {
        for text in [
            "extensions: {developer: {enabled: true}}\n",
            "extensions:\n  sentra: {cmd: x}\n",
            "a: 1\n---\nb: 2\n",
            "extensions:\n\t sentra:\n",
            "- item\n",
            "extensions:\n  sentra:\n    cmd: |\n      multi\n",
        ] {
            assert!(
                upsert(text, &goose("s")).is_err(),
                "should refuse: {text:?}"
            );
        }
    }

    #[test]
    fn refuses_invalid_values_instead_of_editing_around_them() {
        for text in [
            // Audit repro: a value starting with the mapping indicator.
            "GOOSE_MODEL: : bad\nextensions:\n  a:\n    cmd: x\n",
            "GOOSE_MODEL: a: b\n",
            "GOOSE_MODEL: trailing:\n",
            "GOOSE_MODEL: - item\n",
            "GOOSE_MODEL: ]\n",
            "GOOSE_MODEL: @reserved\n",
            "GOOSE_MODEL: \"closed\" junk\n",
            "GOOSE_MODEL: |x\n",
            "extensions:\n  other: : x\n",
            "extensions:\n  sentra:\n    timeout: : 300\n",
        ] {
            let error = upsert(text, &goose("s")).unwrap_err();
            assert!(error.0.contains("valid YAML"), "{text:?}: {}", error.0);
        }
    }

    #[test]
    fn accepts_valid_values_that_look_unusual() {
        for value in [
            "",
            " # comment",
            " plain value",
            " http://example.com:8080/x",
            " 12:30",
            " \"quoted: with colon\" # c",
            " 'it''s'",
            " [a, b]",
            " {a: 1}",
            " |",
            " >-",
            " &anchor value",
            " !!str 1",
            " *alias",
            " -1",
            " a#b",
            " \"multi-line quoted",
        ] {
            assert_eq!(inline_value_problem(value), None, "{value:?}");
        }
        assert!(inline_value_problem(" : bad").is_some());
        assert!(inline_value_problem(" &a : bad").is_some());
    }

    #[test]
    fn sequence_items_are_located_by_name() {
        let entry = Entry {
            top_key: "mcpServers",
            locate: Locate::SeqItemByName("sentra"),
            fresh: vec![
                ("name", YamlValue::Str("sentra".into())),
                ("command", YamlValue::Str("/bin/s".into())),
                ("args", YamlValue::Seq(vec!["mcp".into()])),
            ],
            managed: vec![
                ("command", YamlValue::Str("/bin/s".into())),
                ("args", YamlValue::Seq(vec!["mcp".into()])),
            ],
        };
        let text = "name: Sentra\nmcpServers:\n  - name: other\n    command: o\n  - name: sentra\n    command: old\n    env:\n      A: b\n";
        let out = upsert(text, &entry).unwrap().unwrap();
        assert_eq!(
            out,
            "name: Sentra\nmcpServers:\n  - name: other\n    command: o\n  - name: sentra\n    command: /bin/s\n    env:\n      A: b\n    args:\n      - mcp\n"
        );
        let fresh = upsert("name: Sentra\nmcpServers: []\n", &entry)
            .unwrap()
            .unwrap();
        assert_eq!(
            fresh,
            "name: Sentra\nmcpServers:\n  - name: sentra\n    command: /bin/s\n    args:\n      - mcp\n"
        );
    }
}
