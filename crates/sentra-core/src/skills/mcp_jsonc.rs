//! Lossless JSON / JSONC editing for MCP client configuration files.
//!
//! Agent configuration files are frequently hand-edited, carry `//` and `/* */`
//! comments or trailing commas (Zed, Augment, Qwen, OpenCode, VS Code), or are
//! large application state files that other programs own (`~/.claude.json`).
//! Re-serialising such a file through a JSON value tree would drop comments,
//! re-order keys, and normalise numbers. This module therefore parses the
//! document into a span tree and applies *surgical text edits*: only the bytes
//! of the inserted or replaced member change, and everything else (comments,
//! key order, whitespace, line endings, number spelling) is preserved verbatim.

use std::ops::Range;

use serde_json::Value;

/// Maximum nesting depth accepted by the parser (defends against stack exhaustion).
const MAX_DEPTH: usize = 256;

/// Syntax error in a JSON/JSONC document, with a 1-based line and column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SyntaxError {
    pub(crate) line: usize,
    pub(crate) column: usize,
    pub(crate) message: &'static str,
}

impl std::fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "line {}, column {}: {}",
            self.line, self.column, self.message
        )
    }
}

/// Why a document could not be edited.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EditError {
    /// The document is not valid JSON/JSONC.
    Syntax(SyntaxError),
    /// The document is valid but its structure cannot be edited without
    /// discarding or reinterpreting user data.
    Shape(String),
}

#[derive(Debug)]
pub(crate) enum Kind {
    Object(Vec<Member>),
    Array(Vec<Node>),
    String(String),
    Number,
    Bool(bool),
    Null,
}

#[derive(Debug)]
pub(crate) struct Node {
    pub(crate) kind: Kind,
    pub(crate) span: Range<usize>,
}

#[derive(Debug)]
pub(crate) struct Member {
    pub(crate) key: String,
    pub(crate) key_start: usize,
    pub(crate) value: Node,
    /// Byte offset of the comma that follows this member, if any.
    pub(crate) comma: Option<usize>,
}

impl Node {
    fn type_name(&self) -> &'static str {
        match self.kind {
            Kind::Object(_) => "object",
            Kind::Array(_) => "array",
            Kind::String(_) => "string",
            Kind::Number => "number",
            Kind::Bool(_) => "boolean",
            Kind::Null => "null",
        }
    }
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn error(&self, at: usize, message: &'static str) -> SyntaxError {
        let at = at.min(self.text.len());
        let prefix = &self.text[..floor_char_boundary(self.text, at)];
        let line = prefix.matches('\n').count() + 1;
        let column = prefix
            .rsplit('\n')
            .next()
            .map_or(0, |segment| segment.chars().count())
            + 1;
        SyntaxError {
            line,
            column,
            message,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_trivia(&mut self) -> Result<(), SyntaxError> {
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\n' | b'\r') => self.pos += 1,
                Some(b'/') => match self.bytes.get(self.pos + 1) {
                    Some(b'/') => {
                        while let Some(byte) = self.peek() {
                            if byte == b'\n' {
                                break;
                            }
                            self.pos += 1;
                        }
                    }
                    Some(b'*') => {
                        let start = self.pos;
                        self.pos += 2;
                        loop {
                            match self.peek() {
                                None => return Err(self.error(start, "unterminated block comment")),
                                Some(b'*') if self.bytes.get(self.pos + 1) == Some(&b'/') => {
                                    self.pos += 2;
                                    break;
                                }
                                Some(_) => self.pos += 1,
                            }
                        }
                    }
                    _ => return Err(self.error(self.pos, "unexpected character '/'")),
                },
                _ => return Ok(()),
            }
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<Node, SyntaxError> {
        if depth > MAX_DEPTH {
            return Err(self.error(self.pos, "nesting is too deep"));
        }
        let start = self.pos;
        match self.peek() {
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => {
                let value = self.parse_string()?;
                Ok(Node {
                    kind: Kind::String(value),
                    span: start..self.pos,
                })
            }
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            Some(b't') => self.parse_literal("true", Kind::Bool(true)),
            Some(b'f') => self.parse_literal("false", Kind::Bool(false)),
            Some(b'n') => self.parse_literal("null", Kind::Null),
            Some(_) => Err(self.error(start, "expected a JSON value")),
            None => Err(self.error(start, "unexpected end of document")),
        }
    }

    fn parse_literal(&mut self, word: &'static str, kind: Kind) -> Result<Node, SyntaxError> {
        let start = self.pos;
        if self.bytes[start..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            if matches!(self.peek(), Some(byte) if byte.is_ascii_alphanumeric() || byte == b'_') {
                return Err(self.error(start, "invalid literal"));
            }
            Ok(Node {
                kind,
                span: start..self.pos,
            })
        } else {
            Err(self.error(start, "invalid literal"))
        }
    }

    fn parse_number(&mut self) -> Result<Node, SyntaxError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(self.error(start, "invalid number")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error(start, "invalid number"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error(start, "invalid number"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        Ok(Node {
            kind: Kind::Number,
            span: start..self.pos,
        })
    }

    fn parse_hex4(&mut self) -> Result<u32, SyntaxError> {
        let start = self.pos;
        let digits = self
            .text
            .get(start..start + 4)
            .ok_or_else(|| self.error(start, "invalid unicode escape"))?;
        let value = u32::from_str_radix(digits, 16)
            .map_err(|_| self.error(start, "invalid unicode escape"))?;
        self.pos += 4;
        Ok(value)
    }

    fn parse_string(&mut self) -> Result<String, SyntaxError> {
        let start = self.pos;
        self.pos += 1; // opening quote
        let mut out = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(self.error(start, "unterminated string"));
            };
            match byte {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let Some(escape) = self.peek() else {
                        return Err(self.error(start, "unterminated string"));
                    };
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let high = self.parse_hex4()?;
                            let code = if (0xD800..0xDC00).contains(&high) {
                                if self.bytes.get(self.pos) == Some(&b'\\')
                                    && self.bytes.get(self.pos + 1) == Some(&b'u')
                                {
                                    self.pos += 2;
                                    let low = self.parse_hex4()?;
                                    if !(0xDC00..0xE000).contains(&low) {
                                        return Err(self.error(self.pos, "invalid surrogate pair"));
                                    }
                                    0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
                                } else {
                                    return Err(self.error(self.pos, "lone surrogate escape"));
                                }
                            } else {
                                high
                            };
                            let ch = char::from_u32(code)
                                .ok_or_else(|| self.error(self.pos, "invalid unicode escape"))?;
                            out.push(ch);
                        }
                        _ => return Err(self.error(self.pos - 1, "invalid escape sequence")),
                    }
                }
                0x00..=0x1F => {
                    return Err(self.error(self.pos, "control character in string"));
                }
                _ => {
                    let rest = &self.text[self.pos..];
                    let ch = rest.chars().next().unwrap_or('\u{FFFD}');
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<Node, SyntaxError> {
        let start = self.pos;
        self.pos += 1;
        let mut members = Vec::new();
        self.skip_trivia()?;
        loop {
            match self.peek() {
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Node {
                        kind: Kind::Object(members),
                        span: start..self.pos,
                    });
                }
                Some(b'"') => {
                    let key_start = self.pos;
                    let key = self.parse_string()?;
                    self.skip_trivia()?;
                    if self.peek() != Some(b':') {
                        return Err(self.error(self.pos, "expected ':' after object key"));
                    }
                    self.pos += 1;
                    self.skip_trivia()?;
                    let value = self.parse_value(depth + 1)?;
                    self.skip_trivia()?;
                    let comma = if self.peek() == Some(b',') {
                        let at = self.pos;
                        self.pos += 1;
                        self.skip_trivia()?;
                        Some(at)
                    } else {
                        None
                    };
                    let closes = self.peek() == Some(b'}');
                    members.push(Member {
                        key,
                        key_start,
                        value,
                        comma,
                    });
                    if comma.is_none() && !closes {
                        return Err(self.error(self.pos, "expected ',' or '}' in object"));
                    }
                }
                None => return Err(self.error(start, "unterminated object")),
                Some(_) => return Err(self.error(self.pos, "expected a string object key")),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<Node, SyntaxError> {
        let start = self.pos;
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_trivia()?;
        loop {
            match self.peek() {
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Node {
                        kind: Kind::Array(items),
                        span: start..self.pos,
                    });
                }
                None => return Err(self.error(start, "unterminated array")),
                Some(_) => {
                    items.push(self.parse_value(depth + 1)?);
                    self.skip_trivia()?;
                    match self.peek() {
                        Some(b',') => {
                            self.pos += 1;
                            self.skip_trivia()?;
                        }
                        Some(b']') => {}
                        _ => return Err(self.error(self.pos, "expected ',' or ']' in array")),
                    }
                }
            }
        }
    }
}

fn floor_char_boundary(text: &str, mut index: usize) -> usize {
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

/// Parses a JSON or JSONC document (comments and trailing commas allowed).
///
/// Returns `Ok(None)` for a document that contains only whitespace and comments.
pub(crate) fn parse(text: &str) -> Result<Option<Node>, SyntaxError> {
    let mut parser = Parser {
        text,
        bytes: text.as_bytes(),
        pos: 0,
    };
    parser.skip_trivia()?;
    if parser.peek().is_none() {
        return Ok(None);
    }
    let root = parser.parse_value(0)?;
    parser.skip_trivia()?;
    if parser.peek().is_some() {
        return Err(parser.error(parser.pos, "unexpected content after the JSON value"));
    }
    Ok(Some(root))
}

/// A value to render into the document, with caller-controlled key order.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Render {
    /// Any JSON value (objects inside are rendered in `serde_json` map order).
    Json(Value),
    /// An object whose members are rendered in the given order.
    Object(Vec<(String, Render)>),
}

impl Render {
    pub(crate) fn object<K: Into<String>>(members: Vec<(K, Render)>) -> Self {
        Self::Object(
            members
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        )
    }

    fn to_value(&self) -> Value {
        match self {
            Self::Json(value) => value.clone(),
            Self::Object(members) => Value::Object(
                members
                    .iter()
                    .map(|(key, value)| (key.clone(), value.to_value()))
                    .collect(),
            ),
        }
    }
}

/// Formatting conventions detected from (or chosen for) a document.
#[derive(Clone, Debug)]
pub(crate) struct Style {
    pub(crate) eol: &'static str,
    pub(crate) unit: String,
}

impl Default for Style {
    fn default() -> Self {
        Self {
            eol: "\n",
            unit: "  ".to_owned(),
        }
    }
}

fn json_string(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| String::from("\"\""))
}

/// Renders a value in pretty multi-line form. `indent` is the indentation of
/// the line on which the value starts; nested lines get `indent + unit`.
pub(crate) fn render(value: &Render, indent: &str, style: &Style) -> String {
    match value {
        Render::Object(members) => render_members(
            members
                .iter()
                .map(|(key, value)| (key.as_str(), value.clone())),
            members.is_empty(),
            indent,
            style,
        ),
        Render::Json(Value::Object(map)) => render_members(
            map.iter()
                .map(|(key, value)| (key.as_str(), Render::Json(value.clone()))),
            map.is_empty(),
            indent,
            style,
        ),
        Render::Json(Value::Array(items)) => {
            if items.is_empty() {
                return "[]".to_owned();
            }
            let scalars = items
                .iter()
                .all(|item| !matches!(item, Value::Array(_) | Value::Object(_)));
            let inline = items
                .iter()
                .map(|item| serde_json::to_string(item).unwrap_or_default())
                .collect::<Vec<_>>()
                .join(", ");
            if scalars && inline.len() <= 100 {
                return format!("[{inline}]");
            }
            let inner = format!("{indent}{}", style.unit);
            let mut out = String::from("[");
            for (index, item) in items.iter().enumerate() {
                out.push_str(style.eol);
                out.push_str(&inner);
                out.push_str(&render(&Render::Json(item.clone()), &inner, style));
                if index + 1 < items.len() {
                    out.push(',');
                }
            }
            out.push_str(style.eol);
            out.push_str(indent);
            out.push(']');
            out
        }
        Render::Json(scalar) => serde_json::to_string(scalar).unwrap_or_default(),
    }
}

fn render_members<'k>(
    members: impl Iterator<Item = (&'k str, Render)>,
    empty: bool,
    indent: &str,
    style: &Style,
) -> String {
    if empty {
        return "{}".to_owned();
    }
    let inner = format!("{indent}{}", style.unit);
    let members: Vec<_> = members.collect();
    let mut out = String::from("{");
    for (index, (key, value)) in members.iter().enumerate() {
        out.push_str(style.eol);
        out.push_str(&inner);
        out.push_str(&json_string(key));
        out.push_str(": ");
        out.push_str(&render(value, &inner, style));
        if index + 1 < members.len() {
            out.push(',');
        }
    }
    out.push_str(style.eol);
    out.push_str(indent);
    out.push('}');
    out
}

/// Renders a brand-new document holding `entry` at `path` (object keys).
pub(crate) fn render_new_document(path: &[&str], entry: &Render, style: &Style) -> String {
    let mut value = entry.clone();
    for key in path.iter().rev() {
        value = Render::object(vec![((*key).to_owned(), value)]);
    }
    let mut out = render(&value, "", style);
    out.push_str(style.eol);
    out
}

/// How a managed member is updated on re-runs.
#[derive(Clone, Debug)]
pub(crate) struct Managed {
    pub(crate) key: String,
    pub(crate) value: Render,
    /// An existing object value whose keys are all listed here is a legacy
    /// shape that may be replaced (for example Zed's pre-2025 nested
    /// `command: {path, args}` form). Any other existing object is refused.
    pub(crate) legacy_object_keys: &'static [&'static str],
}

/// A request to ensure `container_path[..] / entry_name` exists.
#[derive(Clone, Debug)]
pub(crate) struct Upsert<'a> {
    pub(crate) container_path: &'a [&'a str],
    pub(crate) entry_name: &'a str,
    /// Full entry written when the entry does not exist yet.
    pub(crate) fresh: Render,
    /// Members updated (and only these) when the entry already exists.
    pub(crate) managed: Vec<Managed>,
}

struct Edit {
    start: usize,
    end: usize,
    text: String,
}

fn line_start(text: &str, pos: usize) -> usize {
    text[..pos].rfind('\n').map_or(0, |index| index + 1)
}

fn line_indent(text: &str, pos: usize) -> &str {
    let start = line_start(text, pos);
    let line = &text[start..];
    let width = line
        .bytes()
        .take_while(|byte| *byte == b' ' || *byte == b'\t')
        .count();
    &line[..width]
}

/// True when `pos` is the first non-blank character on its line.
fn starts_line(text: &str, pos: usize) -> bool {
    text[line_start(text, pos)..pos]
        .bytes()
        .all(|byte| byte == b' ' || byte == b'\t')
}

/// Detects end-of-line and indentation conventions of an existing document.
pub(crate) fn detect_style(text: &str, root: Option<&Node>) -> Style {
    let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut unit = "  ".to_owned();
    if let Some(Node {
        kind: Kind::Object(members),
        ..
    }) = root
        && let Some(first) = members.first()
        && starts_line(text, first.key_start)
    {
        let indent = line_indent(text, first.key_start);
        if indent.starts_with('\t') {
            unit = "\t".to_owned();
        } else if !indent.is_empty() {
            unit = indent.to_owned();
        }
    }
    Style { eol, unit }
}

fn find_member<'n>(
    members: &'n [Member],
    key: &str,
    where_: &str,
) -> Result<Option<&'n Member>, EditError> {
    let mut found = members.iter().filter(|member| member.key == key);
    let first = found.next();
    if found.next().is_some() {
        return Err(EditError::Shape(format!(
            "key \"{key}\" appears more than once in {where_}"
        )));
    }
    Ok(first)
}

/// Builds the edits that append `items` as the last members of `object`.
fn insert_members(
    text: &str,
    object: &Node,
    members: &[Member],
    items: &[(&str, &Render)],
    style: &Style,
) -> Vec<Edit> {
    let open = object.span.start;
    let close = object.span.end - 1;
    let base = line_indent(text, open).to_owned();
    let member_indent = match members.first() {
        Some(first) if starts_line(text, first.key_start) => {
            line_indent(text, first.key_start).to_owned()
        }
        _ => format!("{base}{}", style.unit),
    };
    let rendered = items
        .iter()
        .map(|(key, value)| {
            format!(
                "{}: {}",
                json_string(key),
                render(value, &member_indent, style)
            )
        })
        .collect::<Vec<_>>()
        .join(&format!(",{}{member_indent}", style.eol));

    let Some(last) = members.last() else {
        let inner = &text[open + 1..close];
        if inner.trim().is_empty() {
            return vec![Edit {
                start: open + 1,
                end: close,
                text: format!("{}{member_indent}{rendered}{}{base}", style.eol, style.eol),
            }];
        }
        // Keep comments that live inside the otherwise empty object.
        return vec![Edit {
            start: open + 1,
            end: open + 1,
            text: format!("{}{member_indent}{rendered}", style.eol),
        }];
    };

    let value_end = last.value.span.end;
    let bytes = text.as_bytes();
    // Insert at the end of the line that holds the last member (past an
    // optional trailing comma and same-line `//` comment) so that comments
    // stay attached to the member they annotate.
    let cursor = last.comma.map_or(value_end, |comma| comma + 1);
    let mut probe = cursor;
    while matches!(bytes.get(probe), Some(b' ' | b'\t')) {
        probe += 1;
    }
    if bytes.get(probe) == Some(&b'/') && bytes.get(probe + 1) == Some(&b'/') {
        while !matches!(bytes.get(probe), None | Some(b'\n' | b'\r')) {
            probe += 1;
        }
    }
    let insert_at = if matches!(bytes.get(probe), Some(b'\n' | b'\r')) {
        probe
    } else {
        cursor
    };
    let trailing_comma = last.comma.is_some();
    let mut edits = Vec::new();
    let mut member_text = format!("{}{member_indent}{rendered}", style.eol);
    if trailing_comma {
        member_text.push(',');
    } else if insert_at == value_end {
        member_text.insert(0, ',');
    } else {
        edits.push(Edit {
            start: value_end,
            end: value_end,
            text: ",".to_owned(),
        });
    }
    edits.push(Edit {
        start: insert_at,
        end: insert_at,
        text: member_text,
    });
    edits
}

fn node_equals(text: &str, node: &Node, value: &Value) -> bool {
    match (&node.kind, value) {
        (Kind::Null, Value::Null) => true,
        (Kind::Bool(left), Value::Bool(right)) => left == right,
        (Kind::String(left), Value::String(right)) => left == right,
        (Kind::Number, Value::Number(_)) => {
            serde_json::from_str::<Value>(&text[node.span.clone()])
                .ok()
                .as_ref()
                == Some(value)
        }
        (Kind::Array(items), Value::Array(values)) => {
            items.len() == values.len()
                && items
                    .iter()
                    .zip(values)
                    .all(|(item, value)| node_equals(text, item, value))
        }
        (Kind::Object(members), Value::Object(map)) => {
            members.len() == map.len()
                && members.iter().all(|member| {
                    map.get(&member.key)
                        .is_some_and(|value| node_equals(text, &member.value, value))
                })
        }
        _ => false,
    }
}

/// Applies `upsert` to `text` (which must not contain a BOM).
///
/// Returns `Ok(None)` when the document already holds the desired values.
pub(crate) fn upsert(text: &str, upsert: &Upsert<'_>) -> Result<Option<String>, EditError> {
    let root = parse(text).map_err(EditError::Syntax)?;
    let Some(root) = root else {
        if text.trim().is_empty() {
            return Ok(Some(render_new_document(
                upsert.container_path,
                &Render::object(vec![(upsert.entry_name.to_owned(), upsert.fresh.clone())]),
                &Style::default(),
            )));
        }
        return Err(EditError::Shape(
            "the file contains only comments and no JSON object".to_owned(),
        ));
    };
    let style = detect_style(text, Some(&root));
    let Kind::Object(root_members) = &root.kind else {
        return Err(EditError::Shape(format!(
            "the top-level value is a {}, not an object",
            root.type_name()
        )));
    };

    // Walk (and if needed create) the container path.
    let mut object = &root;
    let mut members = root_members;
    let mut where_ = String::from("the top-level object");
    for (depth, key) in upsert.container_path.iter().enumerate() {
        match find_member(members, key, &where_)? {
            Some(member) => match &member.value.kind {
                Kind::Object(inner) => {
                    object = &member.value;
                    members = inner;
                    where_ = format!("\"{key}\"");
                }
                _ => {
                    return Err(EditError::Shape(format!(
                        "\"{key}\" is a {}, expected an object",
                        member.value.type_name()
                    )));
                }
            },
            None => {
                let mut value =
                    Render::object(vec![(upsert.entry_name.to_owned(), upsert.fresh.clone())]);
                for inner_key in upsert.container_path[depth + 1..].iter().rev() {
                    value = Render::object(vec![((*inner_key).to_owned(), value)]);
                }
                let edits = insert_members(text, object, members, &[(key, &value)], &style);
                return Ok(Some(apply(text, edits)));
            }
        }
    }

    let Some(entry) = find_member(members, upsert.entry_name, &where_)? else {
        let edits = insert_members(
            text,
            object,
            members,
            &[(upsert.entry_name, &upsert.fresh)],
            &style,
        );
        return Ok(Some(apply(text, edits)));
    };
    let Kind::Object(entry_members) = &entry.value.kind else {
        return Err(EditError::Shape(format!(
            "the existing \"{}\" entry is a {}, expected an object",
            upsert.entry_name,
            entry.value.type_name()
        )));
    };
    let entry_where = format!("the \"{}\" entry", upsert.entry_name);

    let mut edits = Vec::new();
    let mut missing = Vec::new();
    for managed in &upsert.managed {
        let desired = managed.value.to_value();
        match find_member(entry_members, &managed.key, &entry_where)? {
            Some(member) if node_equals(text, &member.value, &desired) => {}
            Some(member) => {
                if let Kind::Object(existing) = &member.value.kind {
                    let legacy = existing
                        .iter()
                        .all(|inner| managed.legacy_object_keys.contains(&inner.key.as_str()));
                    if !existing.is_empty() && (!legacy || managed.legacy_object_keys.is_empty()) {
                        return Err(EditError::Shape(format!(
                            "\"{}\" in {entry_where} is an object with fields Sentra does not manage",
                            managed.key
                        )));
                    }
                }
                let indent = line_indent(text, member.key_start).to_owned();
                edits.push(Edit {
                    start: member.value.span.start,
                    end: member.value.span.end,
                    text: render(&managed.value, &indent, &style),
                });
            }
            None => missing.push(managed),
        }
    }
    if !missing.is_empty() {
        let items: Vec<(&str, &Render)> = missing
            .iter()
            .map(|managed| (managed.key.as_str(), &managed.value))
            .collect();
        edits.extend(insert_members(
            text,
            &entry.value,
            entry_members,
            &items,
            &style,
        ));
    }
    if edits.is_empty() {
        return Ok(None);
    }
    Ok(Some(apply(text, edits)))
}

fn apply(text: &str, mut edits: Vec<Edit>) -> String {
    edits.sort_by_key(|edit| std::cmp::Reverse(edit.start));
    let mut out = text.to_owned();
    for edit in edits {
        out.replace_range(edit.start..edit.end, &edit.text);
    }
    out
}

/// Reads a value at `path` (object keys) from a parsed document.
pub(crate) fn lookup<'n>(root: &'n Node, path: &[&str]) -> Option<&'n Node> {
    let mut node = root;
    for key in path {
        let Kind::Object(members) = &node.kind else {
            return None;
        };
        node = &members
            .iter()
            .rev()
            .find(|member| member.key == *key)?
            .value;
    }
    Some(node)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry() -> Upsert<'static> {
        Upsert {
            container_path: &["mcpServers"],
            entry_name: "sentra",
            fresh: Render::object(vec![
                ("command", Render::Json(json!("/bin/sentra"))),
                ("args", Render::Json(json!(["mcp"]))),
            ]),
            managed: vec![
                Managed {
                    key: "command".into(),
                    value: Render::Json(json!("/bin/sentra")),
                    legacy_object_keys: &[],
                },
                Managed {
                    key: "args".into(),
                    value: Render::Json(json!(["mcp"])),
                    legacy_object_keys: &[],
                },
            ],
        }
    }

    fn reparse(text: &str) -> Value {
        // Strip comments by re-parsing through our parser then serde for strict docs.
        assert!(
            parse(text).is_ok(),
            "edited text must stay parseable: {text}"
        );
        serde_json::from_str(text).unwrap_or(Value::Null)
    }

    #[test]
    fn creates_document_from_empty_text() {
        let out = upsert("  \n", &entry()).unwrap().unwrap();
        assert_eq!(
            reparse(&out),
            json!({"mcpServers": {"sentra": {"command": "/bin/sentra", "args": ["mcp"]}}})
        );
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn inserts_into_existing_container_preserving_other_text() {
        let text = "{\n  \"z\": 1,\n  \"mcpServers\": {\n    \"other\": {\"command\": \"x\"}\n  },\n  \"a\": 2.50\n}\n";
        let out = upsert(text, &entry()).unwrap().unwrap();
        assert!(out.starts_with("{\n  \"z\": 1,\n  \"mcpServers\": {\n    \"other\": {\"command\": \"x\"},\n    \"sentra\": {"));
        assert!(out.contains("\"a\": 2.50"), "number spelling kept: {out}");
        let value = reparse(&out);
        assert_eq!(value["mcpServers"]["other"]["command"], "x");
        assert_eq!(value["mcpServers"]["sentra"]["args"], json!(["mcp"]));
    }

    #[test]
    fn keeps_comments_and_trailing_commas() {
        let text = "// header\n{\n  // servers\n  \"mcpServers\": {\n    \"keep\": {\"command\": \"k\"}, // note\n  },\n}\n";
        let out = upsert(text, &entry()).unwrap().unwrap();
        assert!(out.contains("// header"));
        assert!(out.contains("// servers"));
        assert!(out.contains("// note"));
        assert!(out.contains("\"keep\""));
        let root = parse(&out).unwrap().unwrap();
        let sentra = lookup(&root, &["mcpServers", "sentra", "command"]).unwrap();
        assert!(matches!(&sentra.kind, Kind::String(value) if value == "/bin/sentra"));
    }

    #[test]
    fn rerun_updates_only_managed_members() {
        let text = "{\"mcpServers\":{\"sentra\":{\"command\":\"old\",\"env\":{\"K\":\"V\"}}}}";
        let out = upsert(text, &entry()).unwrap().unwrap();
        let value = reparse(&out);
        assert_eq!(value["mcpServers"]["sentra"]["command"], "/bin/sentra");
        assert_eq!(value["mcpServers"]["sentra"]["args"], json!(["mcp"]));
        assert_eq!(value["mcpServers"]["sentra"]["env"]["K"], "V");
        assert_eq!(upsert(&out, &entry()).unwrap(), None);
    }

    #[test]
    fn refuses_invalid_and_non_object_shapes() {
        assert!(matches!(
            upsert("{\"a\": }", &entry()),
            Err(EditError::Syntax(_))
        ));
        assert!(matches!(
            upsert("[1,2]", &entry()),
            Err(EditError::Shape(_))
        ));
        assert!(matches!(
            upsert("{\"mcpServers\": [1]}", &entry()),
            Err(EditError::Shape(_))
        ));
        assert!(matches!(
            upsert("{\"mcpServers\": {\"sentra\": 1}}", &entry()),
            Err(EditError::Shape(_))
        ));
        assert!(matches!(
            upsert("{\"mcpServers\": {}, \"mcpServers\": {}}", &entry()),
            Err(EditError::Shape(_))
        ));
        // Duplicates in keys Sentra never touches are preserved verbatim.
        let untouched = upsert("{\"a\": 1, \"a\": 2}", &entry()).unwrap().unwrap();
        assert!(untouched.starts_with("{\"a\": 1, \"a\": 2,"));
        assert!(matches!(
            upsert("// only a comment\n", &entry()),
            Err(EditError::Shape(_))
        ));
    }

    #[test]
    fn crlf_and_tabs_are_respected() {
        let text = "{\r\n\t\"x\": true\r\n}\r\n";
        let out = upsert(text, &entry()).unwrap().unwrap();
        assert!(out.contains("\r\n\t\"mcpServers\": {\r\n\t\t\"sentra\""));
        assert!(!out.replace("\r\n", "").contains('\n'));
    }

    #[test]
    fn inserts_multiple_missing_managed_members() {
        let text = "{\"mcpServers\": {\"sentra\": {\"env\": {}}}}";
        let out = upsert(text, &entry()).unwrap().unwrap();
        let value = reparse(&out);
        assert_eq!(value["mcpServers"]["sentra"]["command"], "/bin/sentra");
        assert_eq!(value["mcpServers"]["sentra"]["args"], json!(["mcp"]));
        assert_eq!(value["mcpServers"]["sentra"]["env"], json!({}));
    }

    #[test]
    fn empty_object_with_comment_keeps_comment() {
        let text = "{\n  \"mcpServers\": { /* none yet */ }\n}";
        let out = upsert(text, &entry()).unwrap().unwrap();
        assert!(out.contains("/* none yet */"));
        assert!(parse(&out).is_ok());
    }
}
