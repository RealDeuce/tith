//! Canonical TSP-0004 IPC documents and TSP-0012 consume operations.

#![forbid(unsafe_code)]

use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpcError {
	pub line: usize,
	pub message: &'static str,
}

impl fmt::Display for IpcError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "IPC line {}: {}", self.line, self.message)
	}
}
impl std::error::Error for IpcError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Field {
	pub text: String,
	pub quoted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Line {
	pub fields: Vec<Field>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeKind {
	Request,
	Result,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Document {
	pub kind: EnvelopeKind,
	pub lines: Vec<Line>,
}

fn fail(line: usize, message: &'static str) -> IpcError {
	IpcError { line, message }
}

impl Document {
	pub fn parse(input: &[u8], kind: EnvelopeKind) -> Result<Self, IpcError> {
		let text = std::str::from_utf8(input).map_err(|_| fail(1, "invalid UTF-8"))?;
		if !text.ends_with('\n') {
			return Err(fail(
				text.bytes().filter(|byte| *byte == b'\n').count() + 1,
				"missing final LF",
			));
		}
		let raw: Vec<_> = text.split_terminator('\n').collect();
		if raw.len() < 3 {
			return Err(fail(1, "incomplete envelope"));
		}
		let header = match kind {
			EnvelopeKind::Request => "TITH-IPC 1",
			EnvelopeKind::Result => "TITH-IPC-Result 1",
		};
		if raw[0] != header {
			return Err(fail(1, "invalid envelope header"));
		}
		if raw.last() != Some(&"End") {
			return Err(fail(raw.len(), "missing final End"));
		}
		let mut lines = Vec::with_capacity(raw.len() - 2);
		for (index, value) in raw[1..raw.len() - 1].iter().enumerate() {
			lines.push(parse_line(value, index + 2)?);
		}
		Ok(Self { kind, lines })
	}

	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let mut output = String::new();
		output.push_str(match self.kind {
			EnvelopeKind::Request => "TITH-IPC 1\n",
			EnvelopeKind::Result => "TITH-IPC-Result 1\n",
		});
		for line in &self.lines {
			for (index, field) in line.fields.iter().enumerate() {
				if index != 0 {
					output.push(' ');
				}
				if field.quoted {
					output.push_str(&quote(&field.text));
				} else {
					output.push_str(&field.text);
				}
			}
			output.push('\n');
		}
		output.push_str("End\n");
		output.into_bytes()
	}
}

fn parse_line(input: &str, number: usize) -> Result<Line, IpcError> {
	if input.is_empty()
		|| input.starts_with(' ')
		|| input.ends_with(' ')
		|| input.contains('\t')
		|| input.contains("  ")
	{
		return Err(fail(number, "noncanonical separators"));
	}
	if input.chars().any(|ch| ch.is_control() || ch == '\u{7f}') {
		return Err(fail(number, "prohibited control character"));
	}
	let bytes = input.as_bytes();
	let mut at = 0;
	let mut fields = Vec::new();
	while at < bytes.len() {
		if bytes[at] == b'"' {
			let (text, used) = parse_quoted(&input[at..], number)?;
			fields.push(Field { text, quoted: true });
			at += used;
		} else {
			let end = input[at..]
				.find(' ')
				.map_or(input.len(), |value| at + value);
			let text = &input[at..end];
			if text.is_empty() || !text.is_ascii() || text.contains(['"', '\\']) {
				return Err(fail(number, "invalid unquoted field"));
			}
			fields.push(Field {
				text: text.to_owned(),
				quoted: false,
			});
			at = end;
		}
		if at < bytes.len() {
			if bytes[at] != b' ' {
				return Err(fail(number, "missing field separator"));
			}
			at += 1;
		}
	}
	Ok(Line { fields })
}

fn parse_quoted(input: &str, line: usize) -> Result<(String, usize), IpcError> {
	let bytes = input.as_bytes();
	let mut output = Vec::new();
	let mut at = 1;
	while at < bytes.len() {
		match bytes[at] {
			b'"' => {
				let text = String::from_utf8(output)
					.map_err(|_| fail(line, "quoted value is not UTF-8"))?;
				return Ok((text, at + 1));
			}
			b'\\' => {
				at += 1;
				let escape = *bytes
					.get(at)
					.ok_or_else(|| fail(line, "unterminated escape"))?;
				match escape {
					b'"' => output.push(b'"'),
					b'\\' => output.push(b'\\'),
					b'0' => output.push(0),
					b't' => output.push(b'\t'),
					b'n' => output.push(b'\n'),
					b'r' => output.push(b'\r'),
					b'x' => {
						let digits = bytes
							.get(at + 1..at + 3)
							.ok_or_else(|| fail(line, "short hexadecimal escape"))?;
						if !digits
							.iter()
							.all(|v| v.is_ascii_hexdigit() && !v.is_ascii_lowercase())
						{
							return Err(fail(line, "noncanonical hexadecimal escape"));
						}
						let value = (hex(digits[0])? << 4) | hex(digits[1])?;
						if value > 0x7f || matches!(value, 0 | 9 | 10 | 13 | b'"' | b'\\') {
							return Err(fail(line, "invalid hexadecimal escape"));
						}
						output.push(value);
						at += 2;
					}
					_ => return Err(fail(line, "unknown escape")),
				}
			}
			value if value < 0x20 || value == 0x7f => {
				return Err(fail(line, "unescaped control character"));
			}
			_ => {
				let ch = input[at..]
					.chars()
					.next()
					.ok_or_else(|| fail(line, "invalid UTF-8"))?;
				if ch == '\\' {
					return Err(fail(line, "unescaped reverse solidus"));
				}
				let mut encoded = [0; 4];
				output.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
				at += ch.len_utf8();
				continue;
			}
		}
		at += 1;
	}
	Err(fail(line, "unterminated quoted string"))
}

fn hex(value: u8) -> Result<u8, IpcError> {
	match value {
		b'0'..=b'9' => Ok(value - b'0'),
		b'A'..=b'F' => Ok(value - b'A' + 10),
		_ => Err(fail(0, "invalid hexadecimal digit")),
	}
}

#[must_use]
pub fn quote(value: &str) -> String {
	let mut output = String::from("\"");
	for ch in value.chars() {
		match ch {
			'"' => output.push_str("\\\""),
			'\\' => output.push_str("\\\\"),
			'\0' => output.push_str("\\0"),
			'\t' => output.push_str("\\t"),
			'\n' => output.push_str("\\n"),
			'\r' => output.push_str("\\r"),
			ch if ch <= '\u{1f}' || ch == '\u{7f}' => {
				use fmt::Write as _;
				write!(output, "\\x{:02X}", u32::from(ch)).expect("String writes cannot fail");
			}
			ch => output.push(ch),
		}
	}
	output.push('"');
	output
}

fn exact<'a>(line: &'a Line, words: &[&str]) -> Option<&'a [Field]> {
	(line.fields.len() >= words.len()
		&& line
			.fields
			.iter()
			.zip(words)
			.all(|(field, word)| !field.quoted && field.text == *word))
	.then_some(&line.fields[words.len()..])
}
fn one_quoted<'a>(line: &'a Line, name: &str) -> Option<&'a str> {
	let rest = exact(line, &[name])?;
	match rest {
		[Field { text, quoted: true }] => Some(text),
		_ => None,
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Presentation {
	Path,
	Handle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsumeRequest {
	Capabilities,
	Claim {
		application: String,
		wait: bool,
		claim_key: String,
		presentation: Presentation,
	},
	Renew {
		inbound_id: String,
		claim_token: String,
	},
	Acknowledge {
		inbound_id: String,
		claim_token: String,
	},
	Release {
		inbound_id: String,
		claim_token: String,
	},
	Defer {
		inbound_id: String,
		claim_token: String,
		retry_after: u64,
		description: String,
	},
	Reject {
		inbound_id: String,
		claim_token: String,
		description: String,
	},
	Query {
		inbound_id: String,
	},
}

impl ConsumeRequest {
	pub fn parse(input: &[u8]) -> Result<Self, IpcError> {
		let document = Document::parse(input, EnvelopeKind::Request)?;
		let operation = document
			.lines
			.first()
			.ok_or_else(|| fail(2, "missing operation"))?;
		if exact(operation, &["Capabilities"]) == Some(&[]) && document.lines.len() == 1 {
			return Ok(Self::Capabilities);
		}
		if let Some(
			[
				Field {
					text: application,
					quoted: true,
				},
				Field {
					text: mode,
					quoted: false,
				},
			],
		) = exact(operation, &["Claim-Inbound"])
		{
			if !matches!(mode.as_str(), "Now" | "Wait") || document.lines.len() != 3 {
				return Err(fail(2, "invalid Claim-Inbound"));
			}
			let key = one_quoted(&document.lines[1], "Claim-Key")
				.ok_or_else(|| fail(3, "invalid Claim-Key"))?;
			if key.is_empty() {
				return Err(fail(3, "empty Claim-Key"));
			}
			let presentation = match exact(&document.lines[2], &["Presentation"]) {
				Some(
					[
						Field {
							text,
							quoted: false,
						},
					],
				) if text == "Path" => Presentation::Path,
				Some(
					[
						Field {
							text,
							quoted: false,
						},
					],
				) if text == "Handle" => Presentation::Handle,
				_ => return Err(fail(4, "invalid Presentation")),
			};
			return Ok(Self::Claim {
				application: application.clone(),
				wait: mode == "Wait",
				claim_key: key.to_owned(),
				presentation,
			});
		}
		let control = |name: &str| -> Option<(String, String)> {
			let rest = exact(operation, &[name])?;
			match rest {
				[
					Field {
						text: id,
						quoted: false,
					},
					Field {
						text: token,
						quoted: false,
					},
				] if valid_id(id, 'I') && valid_id(token, 'C') => Some((id.clone(), token.clone())),
				_ => None,
			}
		};
		if let Some((inbound_id, claim_token)) = control("Renew-Inbound") {
			require_line_count(&document, 1)?;
			return Ok(Self::Renew {
				inbound_id,
				claim_token,
			});
		}
		if let Some((inbound_id, claim_token)) = control("Acknowledge-Inbound") {
			require_line_count(&document, 1)?;
			return Ok(Self::Acknowledge {
				inbound_id,
				claim_token,
			});
		}
		if let Some((inbound_id, claim_token)) = control("Release-Inbound") {
			require_line_count(&document, 1)?;
			return Ok(Self::Release {
				inbound_id,
				claim_token,
			});
		}
		if let Some((inbound_id, claim_token)) = control("Defer-Inbound") {
			require_line_count(&document, 3)?;
			let retry_after = unsigned_line(&document.lines[1], "Retry-After", 3)?;
			let description = one_quoted(&document.lines[2], "Description")
				.ok_or_else(|| fail(4, "invalid Description"))?
				.to_owned();
			return Ok(Self::Defer {
				inbound_id,
				claim_token,
				retry_after,
				description,
			});
		}
		if let Some((inbound_id, claim_token)) = control("Reject-Inbound") {
			require_line_count(&document, 2)?;
			let description = one_quoted(&document.lines[1], "Description")
				.ok_or_else(|| fail(3, "invalid Description"))?
				.to_owned();
			return Ok(Self::Reject {
				inbound_id,
				claim_token,
				description,
			});
		}
		if let Some(rest) = exact(operation, &["Query-Inbound"])
			&& let [
				Field {
					text,
					quoted: false,
				},
			] = rest && valid_id(text, 'I')
		{
			require_line_count(&document, 1)?;
			return Ok(Self::Query {
				inbound_id: text.clone(),
			});
		}
		Err(fail(2, "unknown or malformed operation"))
	}
}

fn require_line_count(document: &Document, count: usize) -> Result<(), IpcError> {
	if document.lines.len() == count {
		Ok(())
	} else {
		Err(fail(count + 2, "extra or missing operation data"))
	}
}
fn unsigned_line(line: &Line, name: &str, number: usize) -> Result<u64, IpcError> {
	let rest = exact(line, &[name]).ok_or_else(|| fail(number, "wrong directive"))?;
	match rest {
		[
			Field {
				text,
				quoted: false,
			},
		] if text == "0"
			|| (!text.starts_with('0') && text.bytes().all(|v| v.is_ascii_digit())) =>
		{
			text.parse().map_err(|_| fail(number, "integer overflow"))
		}
		_ => Err(fail(number, "invalid unsigned integer")),
	}
}
fn valid_id(value: &str, prefix: char) -> bool {
	value.len() == 33
		&& value.starts_with(prefix)
		&& value[1..]
			.bytes()
			.all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
}

#[must_use]
pub fn capabilities(
	operations: impl IntoIterator<Item = String>,
	features: impl IntoIterator<Item = String>,
) -> Vec<u8> {
	let mut operations: Vec<_> = operations.into_iter().collect();
	operations.push("Capabilities".to_owned());
	operations.sort();
	operations.dedup();
	let mut features: Vec<_> = features.into_iter().collect();
	features.sort();
	features.dedup();
	let mut lines = vec![Line {
		fields: vec![
			Field {
				text: "Capabilities".to_owned(),
				quoted: false,
			},
			Field {
				text: "Completed".to_owned(),
				quoted: false,
			},
		],
	}];
	for value in operations {
		lines.push(Line {
			fields: vec![
				Field {
					text: "Operation".to_owned(),
					quoted: false,
				},
				Field {
					text: value,
					quoted: true,
				},
			],
		});
	}
	for value in features {
		lines.push(Line {
			fields: vec![
				Field {
					text: "Feature".to_owned(),
					quoted: false,
				},
				Field {
					text: value,
					quoted: true,
				},
			],
		});
	}
	Document {
		kind: EnvelopeKind::Result,
		lines,
	}
	.encode()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn quoted_values_round_trip_canonically() {
		let value = "hello\0\t\n\r\"\\\u{7f}é";
		let document = Document {
			kind: EnvelopeKind::Request,
			lines: vec![Line {
				fields: vec![
					Field {
						text: "Op".to_owned(),
						quoted: false,
					},
					Field {
						text: value.to_owned(),
						quoted: true,
					},
				],
			}],
		};
		let encoded = document.encode();
		assert_eq!(
			Document::parse(&encoded, EnvelopeKind::Request).unwrap(),
			document
		);
		assert!(
			String::from_utf8(encoded)
				.unwrap()
				.contains("\\0\\t\\n\\r\\\"\\\\\\x7F")
		);
	}

	#[test]
	fn parses_claim_and_rejects_noncanonical_text() {
		let request = b"TITH-IPC 1\nClaim-Inbound \"tosser\" Now\nClaim-Key \"worker-1\"\nPresentation Path\nEnd\n";
		assert!(matches!(
			ConsumeRequest::parse(request).unwrap(),
			ConsumeRequest::Claim { wait: false, .. }
		));
		assert!(ConsumeRequest::parse(b"TITH-IPC 1\nCapabilities  \nEnd\n").is_err());
		assert!(ConsumeRequest::parse(b"TITH-IPC 1\r\nCapabilities\r\nEnd\r\n").is_err());
	}

	#[test]
	fn capabilities_are_sorted_and_unique() {
		let encoded = capabilities(
			["Query-Inbound".to_owned(), "Capabilities".to_owned()],
			["Consume.Payload-Handle".to_owned()],
		);
		let text = String::from_utf8(encoded).unwrap();
		assert_eq!(text.matches("Operation \"Capabilities\"").count(), 1);
		assert!(text.find("Capabilities\"").unwrap() < text.find("Query-Inbound\"").unwrap());
	}
}
