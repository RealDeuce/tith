use super::{Document, EnvelopeKind, Field, IpcError, Line, exact, fail};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmitOperation {
	Submit,
	SubmitItems,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionRequest {
	pub operation: SubmitOperation,
	pub jobs: Vec<SubmissionJob>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LookupSubmission {
	pub application: String,
	pub keys: Vec<String>,
}

impl LookupSubmission {
	pub fn parse(input: &[u8]) -> Result<Self, IpcError> {
		let document = Document::parse(input, EnvelopeKind::Request)?;
		let application = match document
			.lines
			.first()
			.and_then(|line| exact(line, &["Lookup-Submission"]))
		{
			Some([Field { text, quoted: true }]) if !text.is_empty() => text.clone(),
			_ => return Err(fail(2, "not a Lookup-Submission operation")),
		};
		let mut keys = Vec::new();
		for (index, line) in document.lines[1..].iter().enumerate() {
			match exact(line, &["Idempotency-Key"]) {
				Some([Field { text, quoted: true }])
					if !text.is_empty() && !keys.contains(text) =>
				{
					keys.push(text.clone());
				}
				_ => return Err(fail(index + 3, "invalid or duplicate Idempotency-Key")),
			}
		}
		if keys.is_empty() {
			return Err(fail(3, "Lookup-Submission contains no Idempotency-Key"));
		}
		Ok(Self { application, keys })
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionJob {
	pub application: String,
	pub idempotency_key: String,
	pub canonical: Vec<u8>,
	pub body: SubmissionBody,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubmissionBody {
	Message(MessageSubmission),
	File(FileSubmission),
	Forward {
		inbound_id: String,
		claim_token: String,
	},
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
	NetMail,
	EchoMail,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageSubmission {
	pub kind: MessageKind,
	pub origin: String,
	pub destination_or_area: String,
	pub to_user: String,
	pub from_user: String,
	pub timestamp: Option<u64>,
	pub subject: String,
	pub message_text: String,
	pub legacy_attributes: Option<u64>,
	pub timestamp_offset: Option<i64>,
	pub tear_line: Option<String>,
	pub origin_line: Option<String>,
	pub message_id: Option<String>,
	pub reply_to: Option<(String, String)>,
	pub additional_kludge_lines: Vec<String>,
	pub class: Option<String>,
	pub next_hop: Option<NextHop>,
	pub failure_policy: Option<FailureOverride>,
	pub attachments: Vec<SourceSubmission>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileSubmission {
	pub origin: String,
	pub area: String,
	pub source: SourceSubmission,
	pub short_description: Option<String>,
	pub long_description_lines: Vec<String>,
	pub tear_line: Option<String>,
	pub magic_word: Option<String>,
	pub replaces: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceSubmission {
	pub source: Source,
	pub ingestion: Ingestion,
	pub disposition: SourceDisposition,
	pub wire_filename: WireFilename,
	pub timestamp: Option<u64>,
	pub expected_size: Option<u64>,
	pub expected_hash: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Source {
	Path(String),
	Handle(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ingestion {
	Copy,
	Move,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceDisposition {
	Keep,
	Delete,
	Truncate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireFilename {
	Generate,
	Name(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NextHop {
	Route,
	Active(String),
	Passive(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureDisposition {
	DeadLetter,
	Discard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureNotification {
	None,
	Sender,
	OriginSysop,
	Both,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureOverride {
	Route,
	Policy {
		disposition: FailureDisposition,
		notification: FailureNotification,
	},
}

impl SubmissionRequest {
	pub fn parse(input: &[u8]) -> Result<Self, IpcError> {
		let document = Document::parse(input, EnvelopeKind::Request)?;
		let operation = match document.lines.first() {
			Some(line) if exact(line, &["Submit"]) == Some(&[]) => SubmitOperation::Submit,
			Some(line) if exact(line, &["Submit-Items"]) == Some(&[]) => {
				SubmitOperation::SubmitItems
			}
			_ => return Err(fail(2, "not a submission operation")),
		};
		let mut at = 1;
		let mut jobs = Vec::new();
		while at < document.lines.len() {
			let end = job_end(&document.lines, at)?;
			let lines = &document.lines[at..=end];
			jobs.push(parse_job(operation, lines, at + 2)?);
			at = end + 1;
		}
		if jobs.is_empty() {
			return Err(fail(3, "submission contains no Job"));
		}
		Ok(Self { operation, jobs })
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParsedJobKind {
	NetMail,
	EchoMail,
	File,
	Forward,
}

fn job_end(lines: &[Line], start: usize) -> Result<usize, IpcError> {
	let Some(opening) = lines.get(start) else {
		return Err(fail(start + 2, "missing Job"));
	};
	if opening
		.fields
		.first()
		.is_none_or(|field| field.quoted || field.text != "Job")
	{
		return Err(fail(start + 2, "expected Job"));
	}
	let mut depth = 1_u64;
	for (index, line) in lines.iter().enumerate().skip(start + 1) {
		if exact(line, &["Attachment"]) == Some(&[]) || exact(line, &["File"]) == Some(&[]) {
			depth += 1;
		} else if exact(line, &["End"]) == Some(&[]) {
			depth -= 1;
			if depth == 0 {
				return Ok(index);
			}
		}
	}
	Err(fail(start + 2, "unterminated Job"))
}

fn parse_job(
	operation: SubmitOperation,
	lines: &[Line],
	base_line: usize,
) -> Result<SubmissionJob, IpcError> {
	let kind = match (operation, lines[0].fields.as_slice()) {
		(
			SubmitOperation::Submit,
			[
				Field {
					text,
					quoted: false,
				},
			],
		) if text == "Job" => ParsedJobKind::NetMail,
		(SubmitOperation::SubmitItems, fields) => match fields {
			[
				Field {
					text: first,
					quoted: false,
				},
				Field {
					text: second,
					quoted: false,
				},
			] if first == "Job" => match second.as_str() {
				"NetMail" => ParsedJobKind::NetMail,
				"EchoMail" => ParsedJobKind::EchoMail,
				"File" => ParsedJobKind::File,
				"Forward" => ParsedJobKind::Forward,
				_ => return Err(fail(base_line, "invalid Job kind")),
			},
			_ => return Err(fail(base_line, "invalid Job opening")),
		},
		_ => return Err(fail(base_line, "invalid Job opening")),
	};
	let mut cursor = Cursor::new(&lines[1..lines.len() - 1], base_line + 1);
	let application = cursor.required_quoted("Application")?;
	let idempotency_key = cursor.required_quoted("Idempotency-Key")?;
	let body = match kind {
		ParsedJobKind::Forward => {
			let fields = cursor.required_fields("Inbound")?;
			let [id, token] = fields else {
				return Err(cursor.error("invalid Inbound"));
			};
			if id.quoted || token.quoted {
				return Err(cursor.error("invalid Inbound"));
			}
			cursor.finish()?;
			SubmissionBody::Forward {
				inbound_id: id.text.clone(),
				claim_token: token.text.clone(),
			}
		}
		ParsedJobKind::File => SubmissionBody::File(parse_file(&mut cursor)?),
		ParsedJobKind::NetMail | ParsedJobKind::EchoMail => {
			SubmissionBody::Message(parse_message(&mut cursor, kind)?)
		}
	};
	let mut canonical = Vec::new();
	for line in lines {
		canonical.extend_from_slice(&line.encode());
	}
	Ok(SubmissionJob {
		application,
		idempotency_key,
		canonical,
		body,
	})
}

fn parse_message(
	cursor: &mut Cursor<'_>,
	kind: ParsedJobKind,
) -> Result<MessageSubmission, IpcError> {
	let origin = cursor.required_quoted("Origin")?;
	let (message_kind, destination_or_area) = match kind {
		ParsedJobKind::NetMail => (MessageKind::NetMail, cursor.required_quoted("Destination")?),
		ParsedJobKind::EchoMail => (MessageKind::EchoMail, cursor.required_quoted("Area")?),
		_ => unreachable!(),
	};
	let to_user = cursor.required_quoted("To-User")?;
	let from_user = cursor.required_quoted("From-User")?;
	let timestamp = cursor.optional_auto_u64("Timestamp")?;
	let subject = cursor.optional_quoted("Subject")?.unwrap_or_default();
	let message_text = cursor.optional_quoted("Message-Text")?.unwrap_or_default();
	let legacy_attributes = cursor.optional_u64("Legacy-Attributes")?;
	let timestamp_offset = cursor.optional_i64("Timestamp-Offset")?;
	let tear_line = cursor.optional_quoted("Tear-Line")?;
	let origin_line = cursor.optional_quoted("Origin-Line")?;
	let message_id = cursor.optional_quoted("Message-ID")?;
	let reply_to = cursor.optional_two_quoted("Reply-To")?;
	let mut additional_kludge_lines = Vec::new();
	while let Some(value) = cursor.optional_quoted("Additional-Kludge-Line")? {
		additional_kludge_lines.push(value);
	}
	let (class, next_hop, failure_policy) = if message_kind == MessageKind::NetMail {
		(
			cursor.optional_quoted("Class")?,
			cursor.optional_next_hop()?,
			cursor.optional_failure_policy()?,
		)
	} else {
		(None, None, None)
	};
	let mut attachments = Vec::new();
	while cursor.peek_exact("Attachment") {
		cursor.advance();
		attachments.push(parse_source(cursor, true)?);
		cursor.required_end()?;
	}
	cursor.finish()?;
	Ok(MessageSubmission {
		kind: message_kind,
		origin,
		destination_or_area,
		to_user,
		from_user,
		timestamp,
		subject,
		message_text,
		legacy_attributes,
		timestamp_offset,
		tear_line,
		origin_line,
		message_id,
		reply_to,
		additional_kludge_lines,
		class,
		next_hop,
		failure_policy,
		attachments,
	})
}

fn parse_file(cursor: &mut Cursor<'_>) -> Result<FileSubmission, IpcError> {
	let origin = cursor.required_quoted("Origin")?;
	let area = cursor.required_quoted("Area")?;
	if !cursor.peek_exact("File") {
		return Err(cursor.error("missing File block"));
	}
	cursor.advance();
	let source = parse_source(cursor, false)?;
	let short_description = cursor.optional_quoted("Short-Description")?;
	let mut long_description_lines = Vec::new();
	while let Some(value) = cursor.optional_quoted("Long-Description-Line")? {
		long_description_lines.push(value);
	}
	let tear_line = cursor.optional_quoted("Tear-Line")?;
	let magic_word = cursor.optional_quoted("Magic-Word")?;
	let replaces = cursor.optional_quoted("Replaces")?;
	let expected_size = cursor.optional_u64("Expected-Size")?;
	let expected_hash = cursor.optional_quoted("Expected-Hash")?;
	let mut source = source;
	if expected_size.is_some() || expected_hash.is_some() {
		source.expected_size = expected_size;
		source.expected_hash = expected_hash;
	}
	cursor.required_end()?;
	cursor.finish()?;
	Ok(FileSubmission {
		origin,
		area,
		source,
		short_description,
		long_description_lines,
		tear_line,
		magic_word,
		replaces,
	})
}

fn parse_source(cursor: &mut Cursor<'_>, attachment: bool) -> Result<SourceSubmission, IpcError> {
	let line = cursor
		.current()
		.ok_or_else(|| cursor.error("missing Source"))?;
	let source = if let Some(fields) = exact(line, &["Source-Path"]) {
		match fields {
			[Field { text, quoted: true }] => Source::Path(text.clone()),
			_ => return Err(cursor.error("invalid Source-Path")),
		}
	} else if let Some(fields) = exact(line, &["Source-Handle"]) {
		match fields {
			[
				Field {
					text,
					quoted: false,
				},
			] => Source::Handle(
				parse_u64(text).ok_or_else(|| cursor.error("invalid Source-Handle"))?,
			),
			_ => return Err(cursor.error("invalid Source-Handle")),
		}
	} else {
		return Err(cursor.error("missing Source"));
	};
	cursor.advance();
	let ingestion = match cursor.optional_unquoted("Ingestion")? {
		None | Some("Copy") => Ingestion::Copy,
		Some("Move") => Ingestion::Move,
		Some(_) => return Err(cursor.error("invalid Ingestion")),
	};
	let disposition = match cursor.optional_unquoted("Source-Disposition")? {
		None | Some("Keep") => SourceDisposition::Keep,
		Some("Delete") => SourceDisposition::Delete,
		Some("Truncate") => SourceDisposition::Truncate,
		Some(_) => return Err(cursor.error("invalid Source-Disposition")),
	};
	let wire_filename = match cursor.optional_one("Wire-Filename")? {
		None if attachment => WireFilename::Generate,
		None => return Err(cursor.error("standalone File requires Wire-Filename")),
		Some(Field {
			text,
			quoted: false,
		}) if text == "Generate" && attachment => WireFilename::Generate,
		Some(Field { text, quoted: true }) => WireFilename::Name(text),
		Some(_) => return Err(cursor.error("invalid Wire-Filename")),
	};
	let timestamp = cursor.optional_auto_u64("File-Timestamp")?;
	let (expected_size, expected_hash) = if attachment {
		(
			cursor.optional_u64("Expected-Size")?,
			cursor.optional_quoted("Expected-Hash")?,
		)
	} else {
		(None, None)
	};
	Ok(SourceSubmission {
		source,
		ingestion,
		disposition,
		wire_filename,
		timestamp,
		expected_size,
		expected_hash,
	})
}

struct Cursor<'a> {
	lines: &'a [Line],
	at: usize,
	base_line: usize,
}

impl<'a> Cursor<'a> {
	fn new(lines: &'a [Line], base_line: usize) -> Self {
		Self {
			lines,
			at: 0,
			base_line,
		}
	}

	fn current(&self) -> Option<&'a Line> {
		self.lines.get(self.at)
	}

	fn advance(&mut self) {
		self.at += 1;
	}

	fn error(&self, message: &'static str) -> IpcError {
		fail(self.base_line + self.at, message)
	}

	fn required_fields(&mut self, name: &str) -> Result<&'a [Field], IpcError> {
		let fields = self
			.current()
			.and_then(|line| exact(line, &[name]))
			.ok_or_else(|| self.error("missing or out-of-order directive"))?;
		self.advance();
		Ok(fields)
	}

	fn required_quoted(&mut self, name: &str) -> Result<String, IpcError> {
		match self.required_fields(name)? {
			[Field { text, quoted: true }] => Ok(text.clone()),
			_ => Err(self.error("invalid quoted directive")),
		}
	}

	fn optional_quoted(&mut self, name: &str) -> Result<Option<String>, IpcError> {
		let Some(fields) = self.current().and_then(|line| exact(line, &[name])) else {
			return Ok(None);
		};
		let value = match fields {
			[Field { text, quoted: true }] => text.clone(),
			_ => return Err(self.error("invalid quoted directive")),
		};
		self.advance();
		Ok(Some(value))
	}

	fn optional_two_quoted(&mut self, name: &str) -> Result<Option<(String, String)>, IpcError> {
		let Some(fields) = self.current().and_then(|line| exact(line, &[name])) else {
			return Ok(None);
		};
		let value = match fields {
			[
				Field {
					text: first,
					quoted: true,
				},
				Field {
					text: second,
					quoted: true,
				},
			] => (first.clone(), second.clone()),
			_ => return Err(self.error("invalid quoted directive")),
		};
		self.advance();
		Ok(Some(value))
	}

	fn optional_unquoted(&mut self, name: &str) -> Result<Option<&'a str>, IpcError> {
		let Some(fields) = self.current().and_then(|line| exact(line, &[name])) else {
			return Ok(None);
		};
		let value = match fields {
			[
				Field {
					text,
					quoted: false,
				},
			] => text.as_str(),
			_ => return Err(self.error("invalid unquoted directive")),
		};
		self.advance();
		Ok(Some(value))
	}

	fn optional_one(&mut self, name: &str) -> Result<Option<Field>, IpcError> {
		let Some(fields) = self.current().and_then(|line| exact(line, &[name])) else {
			return Ok(None);
		};
		let value = match fields {
			[field] => field.clone(),
			_ => return Err(self.error("invalid directive")),
		};
		self.advance();
		Ok(Some(value))
	}

	fn optional_u64(&mut self, name: &str) -> Result<Option<u64>, IpcError> {
		let Some(value) = self.optional_unquoted(name)? else {
			return Ok(None);
		};
		Ok(Some(
			parse_u64(value).ok_or_else(|| self.error("invalid unsigned integer"))?,
		))
	}

	fn optional_i64(&mut self, name: &str) -> Result<Option<i64>, IpcError> {
		let Some(value) = self.optional_unquoted(name)? else {
			return Ok(None);
		};
		Ok(Some(
			parse_i64(value).ok_or_else(|| self.error("invalid signed integer"))?,
		))
	}

	fn optional_auto_u64(&mut self, name: &str) -> Result<Option<u64>, IpcError> {
		let Some(value) = self.optional_unquoted(name)? else {
			return Ok(None);
		};
		if value == "Auto" {
			Ok(None)
		} else {
			Ok(Some(
				parse_u64(value).ok_or_else(|| self.error("invalid timestamp"))?,
			))
		}
	}

	fn optional_next_hop(&mut self) -> Result<Option<NextHop>, IpcError> {
		let Some(fields) = self.current().and_then(|line| exact(line, &["Next-Hop"])) else {
			return Ok(None);
		};
		let value = match fields {
			[
				Field {
					text,
					quoted: false,
				},
			] if text == "Route" => NextHop::Route,
			[
				Field {
					text: mode,
					quoted: false,
				},
				Field { text, quoted: true },
			] if mode == "Active" => NextHop::Active(text.clone()),
			[
				Field {
					text: mode,
					quoted: false,
				},
				Field { text, quoted: true },
			] if mode == "Passive" => NextHop::Passive(text.clone()),
			_ => return Err(self.error("invalid Next-Hop")),
		};
		self.advance();
		Ok(Some(value))
	}

	fn optional_failure_policy(&mut self) -> Result<Option<FailureOverride>, IpcError> {
		let Some(fields) = self
			.current()
			.and_then(|line| exact(line, &["Failure-Policy"]))
		else {
			return Ok(None);
		};
		let value = match fields {
			[
				Field {
					text,
					quoted: false,
				},
			] if text == "Route" => FailureOverride::Route,
			[
				Field {
					text: disposition,
					quoted: false,
				},
				Field {
					text: notify,
					quoted: false,
				},
				Field {
					text: notification,
					quoted: false,
				},
			] if notify == "Notify" => FailureOverride::Policy {
				disposition: match disposition.as_str() {
					"Dead-Letter" => FailureDisposition::DeadLetter,
					"Discard" => FailureDisposition::Discard,
					_ => return Err(self.error("invalid Failure-Policy disposition")),
				},
				notification: match notification.as_str() {
					"None" => FailureNotification::None,
					"Sender" => FailureNotification::Sender,
					"Origin-Sysop" => FailureNotification::OriginSysop,
					"Both" => FailureNotification::Both,
					_ => return Err(self.error("invalid Failure-Policy notification")),
				},
			},
			_ => return Err(self.error("invalid Failure-Policy")),
		};
		self.advance();
		Ok(Some(value))
	}

	fn peek_exact(&self, word: &str) -> bool {
		self.current()
			.is_some_and(|line| exact(line, &[word]) == Some(&[]))
	}

	fn required_end(&mut self) -> Result<(), IpcError> {
		if !self.peek_exact("End") {
			return Err(self.error("missing nested End"));
		}
		self.advance();
		Ok(())
	}

	fn finish(&self) -> Result<(), IpcError> {
		if self.at == self.lines.len() {
			Ok(())
		} else {
			Err(self.error("unknown or out-of-order directive"))
		}
	}
}

fn parse_u64(value: &str) -> Option<u64> {
	(value == "0" || (!value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit())))
		.then(|| value.parse().ok())
		.flatten()
}

fn parse_i64(value: &str) -> Option<i64> {
	let magnitude = value.strip_prefix('-').unwrap_or(value);
	(value == "0"
		|| (!magnitude.is_empty()
			&& !magnitude.starts_with('0')
			&& magnitude.bytes().all(|byte| byte.is_ascii_digit())))
	.then(|| value.parse().ok())
	.flatten()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_nested_submit_and_preserves_canonical_job_bytes() {
		let request = b"TITH-IPC 1\nSubmit\nJob\nApplication \"mailer\"\nIdempotency-Key \"one\"\nOrigin \"fidonet#1/1\"\nDestination \"fidonet#1/2\"\nTo-User \"You\"\nFrom-User \"Me\"\nAttachment\nSource-Path \"/tmp/a\"\nEnd\nEnd\nEnd\n";
		let parsed = SubmissionRequest::parse(request).unwrap();
		assert_eq!(parsed.jobs.len(), 1);
		assert!(parsed.jobs[0].canonical.starts_with(b"Job\n"));
		assert!(parsed.jobs[0].canonical.ends_with(b"End\n"));
		let SubmissionBody::Message(message) = &parsed.jobs[0].body else {
			panic!("message expected");
		};
		assert_eq!(message.attachments.len(), 1);
	}

	#[test]
	fn parses_item_file_and_lookup_is_not_a_submission() {
		let request = b"TITH-IPC 1\nSubmit-Items\nJob File\nApplication \"fdn\"\nIdempotency-Key \"file\"\nOrigin \"fidonet#1/1\"\nArea \"FILES\"\nFile\nSource-Path \"/tmp/a\"\nWire-Filename \"a.zip\"\nEnd\nEnd\nEnd\n";
		let parsed = SubmissionRequest::parse(request).unwrap();
		assert!(matches!(parsed.jobs[0].body, SubmissionBody::File(_)));
		assert!(
			SubmissionRequest::parse(
				b"TITH-IPC 1\nLookup-Submission \"fdn\"\nIdempotency-Key \"file\"\nEnd\n"
			)
			.is_err()
		);
	}
}
