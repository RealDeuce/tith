//! Builds a TSP-0006 Submit request from a legacy stored message.
//!
//! This is the native side of the boundary, so it lives here rather than in
//! `tith-message-legacy`, which must not depend on the native layer.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::path::Path;

use tith_adapter::address::{AddressError, resolve_destination};
use tith_adapter::convert::parse_timezone;
use tith_ipc::{Document, EnvelopeKind, Field, Line};
use tith_message_legacy::{AttachStyle, Disposition, StoredMessage};

/// A message that cannot be submitted as it stands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildError {
	/// The disposition the sender asked for needs a feature the service does
	/// not advertise. TSP-0013 forbids silently weakening the rule, so the
	/// message fails rather than going out with its cleanup dropped.
	MissingFeature { feature: &'static str, file: String },
	/// The message carries an origin this tool cannot sign for.
	NotLocalOrigin { origin: String },
	/// The attachment list could not be resolved.
	Attach(String),
	/// The legacy destination forms are incomplete, malformed, or conflicting.
	Destination(AddressError),
	/// A named attachment is not present next to the message.
	MissingAttachment { file: String },
	/// The legacy local date and timezone could not determine a native instant.
	Timestamp(String),
}

impl fmt::Display for BuildError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::MissingFeature { feature, file } => write!(
				f,
				"attachment \"{file}\" requires the {feature} feature, which the service does not advertise"
			),
			Self::NotLocalOrigin { origin } => write!(
				f,
				"message origin {origin} is not the configured local identity, so it needs a Signed-Origin this tool cannot supply"
			),
			Self::Attach(reason) => write!(f, "{reason}"),
			Self::Destination(error) => write!(f, "cannot resolve message destination: {error}"),
			Self::MissingAttachment { file } => {
				write!(f, "attached file \"{file}\" was not found")
			}
			Self::Timestamp(reason) => write!(f, "cannot resolve message timestamp: {reason}"),
		}
	}
}

impl Error for BuildError {}

impl From<AddressError> for BuildError {
	fn from(value: AddressError) -> Self {
		Self::Destination(value)
	}
}

fn unquoted(text: &str) -> Field {
	Field {
		text: text.to_owned(),
		quoted: false,
	}
}

fn quoted(text: &str) -> Field {
	Field {
		text: text.to_owned(),
		quoted: true,
	}
}

fn line(fields: Vec<Field>) -> Line {
	Line { fields }
}

/// The FTS-0001.016 `AttributeWord` bit which marks attached files.
const ATTRIBUTE_FILE_ATTACHED: u16 = 1 << 4;

/// The `Legacy-Attributes` line for one legacy `AttributeWord`, if needed.
///
/// TTS-0005 section 3 type 101 keeps bit 4 out of `LegacyAttributes`, because the
/// File children carry attachment presence, and makes an absent value the only
/// representation of a zero one. Both would otherwise be a second representation
/// of a fact the Message already states, and TSP-0003 section 3.1 could no longer
/// reconstruct the Message from its legacy form.
fn legacy_attributes(attributes: u16) -> Option<Line> {
	let carried = attributes & !ATTRIBUTE_FILE_ATTACHED;
	(carried != 0).then(|| {
		line(vec![
			unquoted("Legacy-Attributes"),
			unquoted(&carried.to_string()),
		])
	})
}

/// Everything the builder needs that does not come from the message itself.
pub struct Context<'a> {
	pub application: &'a str,
	pub origin: &'a str,
	/// The legacy 3D or 4D rendering of `origin`, used to recognise our own
	/// MSGID values. Absent when `origin` is not a listed TTS-0004 address.
	pub legacy_origin: Option<String>,
	/// Trusted domain used to complete fixed, INTL, and TOPT addresses.
	pub domain: Option<&'a str>,
	/// Trusted legacy-source offset in seconds east of UTC, used only when the
	/// message has neither `TZUTC` nor `TZUTCINFO`.
	pub configured_offset: Option<i64>,
	pub style: AttachStyle,
	/// TSP-0004 features the service advertised.
	pub features: &'a BTreeSet<String>,
	/// Directory the attachments are resolved against.
	pub directory: &'a Path,
	/// Preassigned source-generation identity. A Message uses it when it has no
	/// MSGID; a BSO batch derives every per-action key from it.
	pub fallback_key: &'a str,
}

fn legacy_timestamp(
	date_time: &str,
	controls: &[tith_message_legacy::Control],
	configured_offset: Option<i64>,
) -> Result<(u64, Option<i64>), BuildError> {
	let mut supplied_offset = None;
	for control in controls.iter().filter(|control| {
		matches!(
			control.name.to_ascii_uppercase().as_str(),
			"TZUTC" | "TZUTCINFO"
		)
	}) {
		let offset = parse_timezone(&control.value)
			.ok_or_else(|| BuildError::Timestamp(format!("malformed {} control", control.name)))?;
		if supplied_offset.is_some_and(|existing| existing != offset) {
			return Err(BuildError::Timestamp(
				"conflicting TZUTC and TZUTCINFO controls".to_owned(),
			));
		}
		supplied_offset = Some(offset);
	}
	let offset = supplied_offset.or(configured_offset).ok_or_else(|| {
		BuildError::Timestamp(
			"no TZUTC, TZUTCINFO, or trusted configured offset is available".to_owned(),
		)
	})?;
	if offset % 60 != 0 || offset.unsigned_abs() > (99 * 3600 + 59 * 60) {
		return Err(BuildError::Timestamp(
			"configured offset is not exactly representable by TZUTC".to_owned(),
		));
	}
	let local = tith_message_legacy::parse_date_time(date_time)
		.map_err(|error| BuildError::Timestamp(error.to_string()))?;
	let utc = local
		.checked_sub(offset)
		.ok_or_else(|| BuildError::Timestamp("DateTime and offset overflow".to_owned()))?;
	let timestamp = u64::try_from(utc)
		.map_err(|_| BuildError::Timestamp("DateTime precedes the UNIX epoch".to_owned()))?;
	Ok((timestamp, (offset != 0).then_some(offset)))
}

/// The result of converting one stored message.
#[derive(Debug)]
pub struct Submission {
	pub request: Vec<u8>,
	pub idempotency_key: String,
	/// True when the key was generated because the message had no MSGID, so an
	/// interrupted run may submit this message more than once.
	pub key_is_generated: bool,
	/// The operation this document uses. TSP-0006 section 8 requires a result to
	/// name the operation in its request, so the caller checks against this
	/// rather than assuming `Submit`.
	pub operation: &'static str,
}

/// Converts one stored message into a complete single-Job Submit request.
pub fn build(message: &StoredMessage, context: &Context<'_>) -> Result<Submission, BuildError> {
	let destination =
		resolve_destination(&message.controls, message.destination, context.domain)?.to_string();

	// A message whose MSGID origin is not the local identity is in-transit
	// legacy mail. TSP-0003 keeps such input as unsupported rather than
	// letting a gateway sign as an arbitrary legacy author.
	//
	// The comparison crosses address spaces: MSGID carries a legacy 3D or 4D
	// address while Origin is a TTS-0004 address, so the local identity is
	// rendered into legacy form rather than compared as text.
	if let Some(msgid) = message.control("MSGID")
		&& let Some((origin, _)) = msgid.value.rsplit_once(' ')
		&& origin != context.origin
		&& Some(origin) != context.legacy_origin.as_deref()
	{
		return Err(BuildError::NotLocalOrigin {
			origin: origin.to_owned(),
		});
	}

	let attachments = message
		.attachments(context.style)
		.map_err(|error| BuildError::Attach(error.to_string()))?;

	let (idempotency_key, key_is_generated) = match message.idempotency_key() {
		Some(key) => (key, false),
		None => (context.fallback_key.to_owned(), true),
	};
	let (timestamp, timestamp_offset) = legacy_timestamp(
		&message.date_time,
		&message.controls,
		context.configured_offset,
	)?;

	let mut lines = vec![
		line(vec![unquoted("Submit")]),
		line(vec![unquoted("Job")]),
		line(vec![unquoted("Application"), quoted(context.application)]),
		line(vec![unquoted("Idempotency-Key"), quoted(&idempotency_key)]),
		line(vec![unquoted("Origin"), quoted(context.origin)]),
		line(vec![unquoted("Destination"), quoted(&destination)]),
		line(vec![unquoted("To-User"), quoted(&message.to_user)]),
		line(vec![unquoted("From-User"), quoted(&message.from_user)]),
		line(vec![
			unquoted("Timestamp"),
			unquoted(&timestamp.to_string()),
		]),
	];

	// TSP-0003 makes the Subject a FileList when the attach attribute is set,
	// so it is not a human subject and is not carried as one.
	if !message.has_file_attached() && !message.subject.is_empty() {
		lines.push(line(vec![unquoted("Subject"), quoted(&message.subject)]));
	}
	if !message.text.is_empty() {
		lines.push(line(vec![
			unquoted("Message-Text"),
			quoted(&tith_message_legacy::decode_body(&message.text)),
		]));
	}
	lines.extend(legacy_attributes(message.attributes));
	if let Some(offset) = timestamp_offset {
		lines.push(line(vec![
			unquoted("Timestamp-Offset"),
			unquoted(&offset.to_string()),
		]));
	}
	if let Some(msgid) = message.control("MSGID") {
		lines.push(line(vec![unquoted("Message-ID"), quoted(&msgid.value)]));
	}
	for control in &message.controls {
		// The structured controls have their own mapped fields; only the rest
		// travel verbatim.
		if matches!(
			control.name.to_ascii_uppercase().as_str(),
			"MSGID" | "MSGTO" | "REPLY" | "CHRS" | "CHARSET" | "TZUTC" | "TZUTCINFO"
		) {
			continue;
		}
		lines.push(line(vec![
			unquoted("Additional-Kludge-Line"),
			quoted(&control.raw),
		]));
	}

	for attachment in &attachments {
		let path = context.directory.join(&attachment.name);
		if !path.is_file() {
			return Err(BuildError::MissingAttachment {
				file: attachment.name.clone(),
			});
		}
		if let Some(feature) = attachment.disposition.required_feature()
			&& !context.features.contains(feature)
		{
			return Err(BuildError::MissingFeature {
				feature,
				file: attachment.name.clone(),
			});
		}
		lines.push(line(vec![unquoted("Attachment")]));
		lines.push(line(vec![
			unquoted("Source-Path"),
			quoted(&path.to_string_lossy()),
		]));
		// Delete and Truncate are valid only with Source-Path and Copy.
		lines.push(line(vec![unquoted("Ingestion"), unquoted("Copy")]));
		if attachment.disposition != Disposition::Keep {
			lines.push(line(vec![
				unquoted("Source-Disposition"),
				unquoted(attachment.disposition.ipc_value()),
			]));
		}
		lines.push(line(vec![unquoted("End")]));
	}

	lines.push(line(vec![unquoted("End")]));
	let document = Document {
		kind: EnvelopeKind::Request,
		lines,
	};
	Ok(Submission {
		request: document.encode(),
		idempotency_key,
		key_is_generated,
		operation: "Submit",
	})
}

/// Converts one packed message from a BSO packet into a Submit request.
///
/// The packet supplies the message and the reference file supplies the
/// attachments, so unlike the stored-message path the caller has already
/// resolved which files this message owns.
pub fn build_packed(
	message: &tith_message_legacy::PackedMessage,
	attachments: &[tith_message_legacy::Attachment],
	context: &Context<'_>,
) -> Result<Submission, BuildError> {
	if let Some(msgid) = message.control("MSGID")
		&& let Some((origin, _)) = msgid.value.rsplit_once(' ')
		&& origin != context.origin
		&& Some(origin) != context.legacy_origin.as_deref()
	{
		return Err(BuildError::NotLocalOrigin {
			origin: origin.to_owned(),
		});
	}

	let (idempotency_key, key_is_generated) = match message.idempotency_key() {
		Some(key) => (key, false),
		None => (context.fallback_key.to_owned(), true),
	};
	let (timestamp, timestamp_offset) = legacy_timestamp(
		&message.date_time,
		&message.controls,
		context.configured_offset,
	)?;

	// TSP-0006 gives EchoMail its own Job kind, keyed on the Area that
	// TSP-0003 section 7 read from the AREA line. A Job kind exists only under
	// Submit-Items; the original Submit operation accepts the bare `Job` line
	// and nothing else, so the operation is chosen with the kind.
	let echo = message.area.as_deref();
	let mut lines = vec![
		line(vec![unquoted(if echo.is_some() {
			"Submit-Items"
		} else {
			"Submit"
		})]),
		match echo {
			Some(_) => line(vec![unquoted("Job"), unquoted("EchoMail")]),
			None => line(vec![unquoted("Job")]),
		},
		line(vec![unquoted("Application"), quoted(context.application)]),
		line(vec![unquoted("Idempotency-Key"), quoted(&idempotency_key)]),
		line(vec![unquoted("Origin"), quoted(context.origin)]),
	];
	if let Some(area) = echo {
		lines.push(line(vec![unquoted("Area"), quoted(area)]));
	} else {
		let destination =
			resolve_destination(&message.controls, message.destination, context.domain)?
				.to_string();
		lines.push(line(vec![unquoted("Destination"), quoted(&destination)]));
	}
	lines.push(line(vec![unquoted("To-User"), quoted(&message.to_user)]));
	lines.push(line(vec![
		unquoted("From-User"),
		quoted(&message.from_user),
	]));
	lines.push(line(vec![
		unquoted("Timestamp"),
		unquoted(&timestamp.to_string()),
	]));

	// With the attach attribute set the Subject is a FileList, not a subject.
	if !message.has_file_attached() && !message.subject.is_empty() {
		lines.push(line(vec![unquoted("Subject"), quoted(&message.subject)]));
	}
	if !message.text.is_empty() {
		lines.push(line(vec![
			unquoted("Message-Text"),
			quoted(&tith_message_legacy::decode_body(&message.text)),
		]));
	}
	lines.extend(legacy_attributes(message.attributes));
	if let Some(offset) = timestamp_offset {
		lines.push(line(vec![
			unquoted("Timestamp-Offset"),
			unquoted(&offset.to_string()),
		]));
	}
	if let Some(msgid) = message.control("MSGID") {
		lines.push(line(vec![unquoted("Message-ID"), quoted(&msgid.value)]));
	}
	for control in &message.controls {
		if matches!(
			control.name.to_ascii_uppercase().as_str(),
			"MSGID" | "MSGTO" | "REPLY" | "CHRS" | "CHARSET" | "TZUTC" | "TZUTCINFO"
		) {
			continue;
		}
		lines.push(line(vec![
			unquoted("Additional-Kludge-Line"),
			quoted(&control.raw),
		]));
	}
	push_attachments(&mut lines, attachments, context)?;
	lines.push(line(vec![unquoted("End")]));
	Ok(Submission {
		request: Document {
			kind: EnvelopeKind::Request,
			lines,
		}
		.encode(),
		idempotency_key,
		key_is_generated,
		operation: if echo.is_some() {
			"Submit-Items"
		} else {
			"Submit"
		},
	})
}

/// Converts unclaimed reference entries into one `Job Peer-File` batch.
///
/// TSP-0003 section 9: a reference entry which no packed Message claims and
/// which has no accompanying TIC belongs to no area and to no message. It maps
/// to one peer-addressed standalone File whose Destination is the address its
/// placement selected, and whose section 3.1 directive supplies the
/// `Source-Disposition` rather than authorizing an immediate removal.
///
/// `Next-Hop` is omitted, so each copy is Active when the peer has a usable
/// endpoint and Passive otherwise — except under the Hold flavour, whose whole
/// meaning is "wait for their poll".
pub fn build_peer_files(
	entries: &[tith_message_legacy::Attachment],
	destination: &str,
	hold: bool,
	context: &Context<'_>,
) -> Result<Submission, BuildError> {
	let mut lines = vec![line(vec![unquoted("Submit-Items")])];
	let mut key = String::new();
	for (index, entry) in entries.iter().enumerate() {
		let path = context.directory.join(&entry.name);
		if !path.is_file() {
			return Err(BuildError::MissingAttachment {
				file: entry.name.clone(),
			});
		}
		if let Some(feature) = entry.disposition.required_feature()
			&& !context.features.contains(feature)
		{
			return Err(BuildError::MissingFeature {
				feature,
				file: entry.name.clone(),
			});
		}
		// A reference entry may carry a full path; the wire name never does.
		let wire_filename = basename(&entry.name);
		key = format!("{}:peer-file:{}", context.fallback_key, index + 1);
		lines.extend([
			line(vec![unquoted("Job"), unquoted("Peer-File")]),
			line(vec![unquoted("Application"), quoted(context.application)]),
			line(vec![unquoted("Idempotency-Key"), quoted(&key)]),
			line(vec![unquoted("Origin"), quoted(context.origin)]),
			line(vec![unquoted("Destination"), quoted(destination)]),
		]);
		if hold {
			lines.push(line(vec![unquoted("Next-Hop"), unquoted("Passive")]));
		}
		lines.extend([
			line(vec![unquoted("File")]),
			line(vec![
				unquoted("Source-Path"),
				quoted(&path.to_string_lossy()),
			]),
			line(vec![unquoted("Ingestion"), unquoted("Copy")]),
		]);
		if entry.disposition != Disposition::Keep {
			lines.push(line(vec![
				unquoted("Source-Disposition"),
				unquoted(entry.disposition.ipc_value()),
			]));
		}
		lines.extend([
			line(vec![unquoted("Wire-Filename"), quoted(wire_filename)]),
			line(vec![unquoted("End")]),
			line(vec![unquoted("End")]),
		]);
	}
	Ok(Submission {
		request: Document {
			kind: EnvelopeKind::Request,
			lines,
		}
		.encode(),
		idempotency_key: key,
		key_is_generated: false,
		operation: "Submit-Items",
	})
}

/// Converts request-list actions into one `Job FileRequest` batch.
///
/// TSP-0003 section 8: every successfully parsed action becomes one
/// `FileRequest`, so an unsupported action is not in `actions` and is left in
/// the file for the operator.
#[must_use]
pub fn build_file_requests(
	actions: &[tith_bso::Request],
	destination: &str,
	hold: bool,
	context: &Context<'_>,
) -> Submission {
	let mut lines = vec![line(vec![unquoted("Submit-Items")])];
	let mut key = String::new();
	for (index, action) in actions.iter().enumerate() {
		key = format!("{}:file-request:{}", context.fallback_key, index + 1);
		lines.extend([
			line(vec![unquoted("Job"), unquoted("FileRequest")]),
			line(vec![unquoted("Application"), quoted(context.application)]),
			line(vec![unquoted("Idempotency-Key"), quoted(&key)]),
			line(vec![unquoted("Origin"), quoted(context.origin)]),
			line(vec![unquoted("Destination"), quoted(destination)]),
			line(vec![unquoted("Filename"), quoted(&action.filename)]),
		]);
		if let Some(newer_than) = action.newer_than {
			lines.push(line(vec![
				unquoted("Newer-Than"),
				unquoted(&newer_than.to_string()),
			]));
		}
		if hold {
			lines.push(line(vec![unquoted("Next-Hop"), unquoted("Passive")]));
		}
		lines.push(line(vec![unquoted("End")]));
	}
	Submission {
		request: Document {
			kind: EnvelopeKind::Request,
			lines,
		}
		.encode(),
		idempotency_key: key,
		key_is_generated: false,
		operation: "Submit-Items",
	}
}

/// The final component of a legacy pathname.
fn basename(name: &str) -> &str {
	name.rsplit(['/', '\\']).next().unwrap_or(name)
}

/// Emits one Attachment block per file, gating each disposition on the
/// feature TSP-0006 requires for it.
fn push_attachments(
	lines: &mut Vec<Line>,
	attachments: &[tith_message_legacy::Attachment],
	context: &Context<'_>,
) -> Result<(), BuildError> {
	for attachment in attachments {
		let path = context.directory.join(&attachment.name);
		if !path.is_file() {
			return Err(BuildError::MissingAttachment {
				file: attachment.name.clone(),
			});
		}
		if let Some(feature) = attachment.disposition.required_feature()
			&& !context.features.contains(feature)
		{
			return Err(BuildError::MissingFeature {
				feature,
				file: attachment.name.clone(),
			});
		}
		lines.push(line(vec![unquoted("Attachment")]));
		lines.push(line(vec![
			unquoted("Source-Path"),
			quoted(&path.to_string_lossy()),
		]));
		lines.push(line(vec![unquoted("Ingestion"), unquoted("Copy")]));
		if attachment.disposition != Disposition::Keep {
			lines.push(line(vec![
				unquoted("Source-Disposition"),
				unquoted(attachment.disposition.ipc_value()),
			]));
		}
		lines.push(line(vec![unquoted("End")]));
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;
	use tith_ipc::{SubmissionBody, SubmissionRequest};

	fn stored(subject: &str, attributes: u16, body: &str) -> Vec<u8> {
		let mut bytes = vec![0_u8; tith_message_legacy::HEADER_BYTES];
		bytes[..6].copy_from_slice(b"Sender");
		bytes[36..45].copy_from_slice(b"Recipient");
		bytes[72..72 + subject.len()].copy_from_slice(subject.as_bytes());
		bytes[144..163].copy_from_slice(b"01 Jan 26  00:00:00");
		bytes[166..168].copy_from_slice(&4_u16.to_le_bytes());
		bytes[174..176].copy_from_slice(&2_u16.to_le_bytes());
		bytes[176..178].copy_from_slice(&1_u16.to_le_bytes());
		bytes[186..188].copy_from_slice(&attributes.to_le_bytes());
		bytes.extend_from_slice(body.as_bytes());
		bytes.push(0);
		bytes
	}

	fn features(values: &[&str]) -> BTreeSet<String> {
		values.iter().map(|value| (*value).to_owned()).collect()
	}

	fn temp_dir(name: &str) -> std::path::PathBuf {
		let path = std::env::temp_dir().join(format!("tith-netmail-{name}-{}", std::process::id()));
		let _ = fs::remove_dir_all(&path);
		fs::create_dir_all(&path).unwrap();
		path
	}

	#[test]
	fn builds_a_request_the_real_parser_accepts() {
		let directory = temp_dir("build");
		fs::write(directory.join("a.zip"), b"payload").unwrap();
		let body =
			"\u{1}MSGID: 1:2/3 1a2b3c4d\r\u{1}MSGTO: fidonet#1:2/4\r\u{1}FLAGS KFS\rHello\r\n";
		let message = StoredMessage::parse(&stored("a.zip", 1 << 4, body)).unwrap();
		let built = build(
			&message,
			&Context {
				application: "netmail",
				origin: "1:2/3",
				legacy_origin: None,
				domain: Some("fidonet"),
				configured_offset: Some(0),
				style: AttachStyle::Flags,
				features: &features(&["Submit.Delete"]),
				directory: &directory,
				fallback_key: "unused",
			},
		)
		.unwrap();

		let parsed = SubmissionRequest::parse(&built.request).expect("request parses");
		assert_eq!(parsed.jobs.len(), 1);
		assert_eq!(built.idempotency_key, "msgid:1:2/3 1a2b3c4d");
		assert!(!built.key_is_generated);

		let text = String::from_utf8(built.request).unwrap();
		assert!(text.contains("Source-Disposition Delete"), "{text}");
		assert!(text.contains("Ingestion Copy"), "{text}");
		// The Subject was a FileList, so it must not be carried as a subject.
		assert!(!text.contains("Subject "), "{text}");
		// Bit 4 was the only attribute set, and the Attachment lines already say
		// the message has one, so nothing is left for Legacy-Attributes to carry.
		assert!(!text.contains("Legacy-Attributes"), "{text}");
		// The legacy body is bytes 0x0D and 0x0A; TTS-0005 type 106 stores
		// paragraphs terminated by U+000A, so the body is decoded rather than
		// handed over raw. The IPC form escapes that terminator as \n.
		assert!(text.contains(r#"Message-Text "Hello\n""#), "{text}");
		fs::remove_dir_all(directory).unwrap();
	}

	#[test]
	fn preserves_the_legacy_date_time_and_timezone_offset() {
		let directory = temp_dir("timestamp");
		let mut bytes = stored(
			"Subject",
			0,
			"\u{1}MSGID: 1:2/3 1a2b3c4d\r\u{1}MSGTO: fidonet#1:2/4\r\u{1}TZUTC: -0700\rBody\r",
		);
		let date_time = "18 Aug 26  12:00:00";
		bytes[144..144 + date_time.len()].copy_from_slice(date_time.as_bytes());
		let message = StoredMessage::parse(&bytes).unwrap();
		let built = build(
			&message,
			&Context {
				application: "netmail",
				origin: "1:2/3",
				legacy_origin: None,
				domain: Some("fidonet"),
				configured_offset: None,
				style: AttachStyle::Flags,
				features: &features(&[]),
				directory: &directory,
				fallback_key: "unused",
			},
		)
		.unwrap();
		let parsed = SubmissionRequest::parse(&built.request).unwrap();
		let SubmissionBody::Message(job) = &parsed.jobs[0].body else {
			panic!("stored conversion did not create a Message")
		};
		let local = tith_message_legacy::parse_date_time(date_time).unwrap();
		assert_eq!(
			job.timestamp,
			Some(u64::try_from(local + 7 * 3600).unwrap())
		);
		assert_eq!(job.timestamp_offset, Some(-7 * 3600));
		assert!(
			!job.additional_kludge_lines
				.iter()
				.any(|line| line.starts_with("TZUTC")),
			"TZUTC has a native field and must not also pass through as a kludge"
		);
		fs::remove_dir_all(directory).unwrap();
	}

	#[test]
	fn refuses_a_legacy_timestamp_without_a_trusted_offset() {
		let directory = temp_dir("ambiguous-timestamp");
		let message = StoredMessage::parse(&stored("Subject", 0, "Body\r")).unwrap();
		let error = build(
			&message,
			&Context {
				application: "netmail",
				origin: "1:2/3",
				legacy_origin: None,
				domain: Some("fidonet"),
				configured_offset: None,
				style: AttachStyle::Flags,
				features: &features(&[]),
				directory: &directory,
				fallback_key: "unused",
			},
		)
		.unwrap_err();
		assert_eq!(
			error,
			BuildError::Timestamp(
				"no TZUTC, TZUTCINFO, or trusted configured offset is available".to_owned()
			)
		);
		fs::remove_dir_all(directory).unwrap();
	}

	#[test]
	fn masks_bit_four_and_omits_a_zero_word() {
		// TTS-0005 section 3 type 101: bit 4 belongs to the File children and a
		// zero value is written by omitting the value. Submitting either would
		// give the Message a second representation of a fact it already states,
		// and TSP-0003 section 3.1 could then never reconstruct it.
		let directory = temp_dir("attributes");
		let context = Context {
			application: "netmail",
			origin: "1:2/3",
			legacy_origin: None,
			domain: Some("fidonet"),
			configured_offset: Some(0),
			style: AttachStyle::Flags,
			features: &features(&[]),
			directory: &directory,
			fallback_key: "unused",
		};
		fs::write(directory.join("a.zip"), b"payload").unwrap();
		let body = "\u{1}MSGID: 1:2/3 1a2b3c4d\rHello\r";
		let request = |subject: &str, attributes: u16| {
			let message = StoredMessage::parse(&stored(subject, attributes, body)).unwrap();
			String::from_utf8(build(&message, &context).unwrap().request).unwrap()
		};

		assert!(!request("Subject", 0).contains("Legacy-Attributes"));
		// HLD, bit 9, is legacy metadata with no other native representation.
		let held = request("Subject", 1 << 9);
		assert!(held.contains("Legacy-Attributes 512"), "{held}");
		// Bit 4 is masked out of a word which carries other bits too.
		let both = request("a.zip", (1 << 9) | (1 << 4));
		assert!(both.contains("Legacy-Attributes 512"), "{both}");
		fs::remove_dir_all(directory).unwrap();
	}

	#[test]
	fn refuses_a_disposition_the_service_does_not_advertise() {
		let directory = temp_dir("feature");
		fs::write(directory.join("a.zip"), b"payload").unwrap();
		let body = "\u{1}MSGID: 1:2/3 1a2b3c4d\r\u{1}FLAGS KFS\r";
		let message = StoredMessage::parse(&stored("a.zip", 1 << 4, body)).unwrap();
		let error = build(
			&message,
			&Context {
				application: "netmail",
				origin: "1:2/3",
				legacy_origin: None,
				domain: Some("fidonet"),
				configured_offset: Some(0),
				style: AttachStyle::Flags,
				features: &features(&[]),
				directory: &directory,
				fallback_key: "unused",
			},
		)
		.unwrap_err();
		assert_eq!(
			error,
			BuildError::MissingFeature {
				feature: "Submit.Delete",
				file: "a.zip".to_owned()
			}
		);
		fs::remove_dir_all(directory).unwrap();
	}

	#[test]
	fn refuses_in_transit_mail_from_another_origin() {
		let directory = temp_dir("origin");
		let body = "\u{1}MSGID: 1:9/9 1a2b3c4d\r";
		let message = StoredMessage::parse(&stored("Subject", 0, body)).unwrap();
		let error = build(
			&message,
			&Context {
				application: "netmail",
				origin: "1:2/3",
				legacy_origin: None,
				domain: Some("fidonet"),
				configured_offset: Some(0),
				style: AttachStyle::Flags,
				features: &features(&[]),
				directory: &directory,
				fallback_key: "unused",
			},
		)
		.unwrap_err();
		assert_eq!(
			error,
			BuildError::NotLocalOrigin {
				origin: "1:9/9".to_owned()
			}
		);
		fs::remove_dir_all(directory).unwrap();
	}

	#[test]
	fn uses_the_fallback_key_when_the_message_has_no_msgid() {
		let directory = temp_dir("nokey");
		let message = StoredMessage::parse(&stored("Subject", 0, "Body")).unwrap();
		let built = build(
			&message,
			&Context {
				application: "netmail",
				origin: "1:2/3",
				legacy_origin: None,
				domain: Some("fidonet"),
				configured_offset: Some(0),
				style: AttachStyle::Flags,
				features: &features(&[]),
				directory: &directory,
				fallback_key: "generated:abc",
			},
		)
		.unwrap();
		assert_eq!(built.idempotency_key, "generated:abc");
		assert!(built.key_is_generated);
		SubmissionRequest::parse(&built.request).expect("request parses");
		fs::remove_dir_all(directory).unwrap();
	}

	#[test]
	fn resolves_stored_and_packed_fixed_destinations_with_the_trusted_domain() {
		let directory = temp_dir("fixed-destination");
		let context = Context {
			application: "netmail",
			origin: "fidonet#1:2/3",
			legacy_origin: Some("1:2/3".to_owned()),
			domain: Some("fidonet"),
			configured_offset: Some(-5 * 3600),
			style: AttachStyle::Flags,
			features: &features(&[]),
			directory: &directory,
			fallback_key: "generated:fixed",
		};

		let mut bytes = stored("Subject", 0, "Body");
		bytes[166..168].copy_from_slice(&24_u16.to_le_bytes());
		bytes[174..176].copy_from_slice(&200_u16.to_le_bytes());
		bytes[176..178].copy_from_slice(&2_u16.to_le_bytes());
		bytes[180..182].copy_from_slice(&5_u16.to_le_bytes());
		let stored = StoredMessage::parse(&bytes).unwrap();
		let parsed = SubmissionRequest::parse(&build(&stored, &context).unwrap().request).unwrap();
		let SubmissionBody::Message(stored_job) = &parsed.jobs[0].body else {
			panic!("stored conversion did not create a Message")
		};
		assert_eq!(stored_job.destination_or_area, "fidonet#2:200/24.5");
		assert_eq!(stored_job.timestamp_offset, Some(-5 * 3600));

		let packed = tith_message_legacy::PackedMessage {
			origin: tith_message_legacy::Endpoint {
				zone: 1,
				net: 2,
				node: 3,
				point: 0,
			},
			destination: tith_message_legacy::Endpoint {
				zone: 3,
				net: 300,
				node: 30,
				point: 7,
			},
			attributes: 0,
			date_time: "18 Aug 26  12:00:00".to_owned(),
			to_user: "Recipient".to_owned(),
			from_user: "Sender".to_owned(),
			subject: "Subject".to_owned(),
			controls: Vec::new(),
			text: "Body\r".to_owned(),
			area: None,
		};
		let parsed =
			SubmissionRequest::parse(&build_packed(&packed, &[], &context).unwrap().request)
				.unwrap();
		let SubmissionBody::Message(packed_job) = &parsed.jobs[0].body else {
			panic!("packet conversion did not create a Message")
		};
		assert_eq!(packed_job.destination_or_area, "fidonet#3:300/30.7");
		assert_eq!(packed_job.timestamp_offset, Some(-5 * 3600));
		let local = tith_message_legacy::parse_date_time(&packed.date_time).unwrap();
		assert_eq!(
			packed_job.timestamp,
			Some(u64::try_from(local + 5 * 3600).unwrap())
		);
		fs::remove_dir_all(directory).unwrap();
	}

	#[test]
	fn bso_actions_have_distinct_stable_keys_within_their_source_generation() {
		let directory = temp_dir("bso-keys");
		fs::create_dir_all(directory.join("one")).unwrap();
		fs::create_dir_all(directory.join("two")).unwrap();
		fs::write(directory.join("one/archive.zip"), b"one").unwrap();
		fs::write(directory.join("two/archive.zip"), b"two").unwrap();
		let context = Context {
			application: "bso",
			origin: "fidonet#1:2/3",
			legacy_origin: Some("1:2/3".to_owned()),
			domain: Some("fidonet"),
			configured_offset: Some(0),
			style: AttachStyle::Flags,
			features: &features(&[]),
			directory: &directory,
			fallback_key: "bso-source-generation-7",
		};
		let attachments = [
			tith_message_legacy::Attachment {
				name: "one/archive.zip".to_owned(),
				disposition: Disposition::Keep,
			},
			tith_message_legacy::Attachment {
				name: "two/archive.zip".to_owned(),
				disposition: Disposition::Keep,
			},
		];
		let peer = build_peer_files(&attachments, "fidonet#1:2/4", false, &context).unwrap();
		let peer_again = build_peer_files(&attachments, "fidonet#1:2/4", false, &context).unwrap();
		let keys = |submission: &Submission| {
			SubmissionRequest::parse(&submission.request)
				.unwrap()
				.jobs
				.into_iter()
				.map(|job| job.idempotency_key)
				.collect::<Vec<_>>()
		};
		let peer_keys = keys(&peer);
		assert_eq!(peer_keys.len(), 2);
		assert_ne!(peer_keys[0], peer_keys[1]);
		assert_eq!(keys(&peer_again), peer_keys);

		let requests = [
			tith_bso::Request {
				filename: "nodelist.zip".to_owned(),
				newer_than: None,
				line: "nodelist.zip".to_owned(),
				unsupported: false,
			},
			tith_bso::Request {
				filename: "nodelist.zip".to_owned(),
				newer_than: Some(123),
				line: "nodelist.zip +123".to_owned(),
				unsupported: false,
			},
		];
		let request = build_file_requests(&requests, "fidonet#1:2/4", false, &context);
		let request_again = build_file_requests(&requests, "fidonet#1:2/4", false, &context);
		let request_keys = keys(&request);
		assert_eq!(request_keys.len(), 2);
		assert_ne!(request_keys[0], request_keys[1]);
		assert_eq!(keys(&request_again), request_keys);
		fs::remove_dir_all(directory).unwrap();
	}
}
