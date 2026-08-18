use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[cfg(windows)]
use crate::NamedPipeBinding;
#[cfg(unix)]
use crate::UnixBinding;
use crate::{Binding, ConfiguredBinding, FilesystemBinding, TcpBinding, validate};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use tith_crypto::{KX_PUBLIC_KEY_BYTES, KX_SECRET_KEY_BYTES, KxKeyPair, KxPublicKey, KxSecretKey};
use tith_ipc::{Document, EnvelopeKind, Field, SubmissionRequest, SubmitOperation, quote};

pub const USAGE: &str = "usage: tith-submit (--files ROOT | --tcp ADDRESS CLIENT-PUBLIC CLIENT-SECRET-FILE SERVER-PUBLIC | --unix SOCKET | --named-pipe PIPE SERVICE-SID) (submit FILE|- | submit-items FILE|- | query JOB-ID | query-job JOB-ID | lookup APPLICATION KEY... | cancel JOB-ID | retry JOB-ID | reroute JOB-ID route|active NEXT-HOP|passive NEXT-HOP | capabilities)";

#[derive(Clone, Copy)]
struct SubmissionCommand {
	operation: SubmitOperation,
	job_count: usize,
}

/// Runs the TSP-0006 section 9 command-line client over already-skipped
/// arguments, returning the exit status that section assigns.
pub fn run(arguments: &mut impl Iterator<Item = String>) -> Result<i32, Box<dyn Error>> {
	let binding = binding(arguments, USAGE)?;
	let (request, submission) = request(arguments)?;
	let result = binding.transact(&request)?;
	let document = validate(&result, EnvelopeKind::Result)?;
	io::stdout().write_all(&result)?;
	io::stdout().flush()?;
	let Some(submission) = submission else {
		return Ok(0);
	};
	submission_exit_status(&document, submission).map_err(Into::into)
}

/// Parses the leading carrier selection shared by every command-line client.
///
/// `usage` is the caller's own usage string so a failure names the command the
/// user actually invoked.
pub fn binding(
	arguments: &mut impl Iterator<Item = String>,
	usage: &'static str,
) -> Result<ConfiguredBinding, Box<dyn Error>> {
	Ok(match arguments.next().as_deref() {
		Some("--files") => ConfiguredBinding::Filesystem(FilesystemBinding::new(PathBuf::from(
			arguments.next().ok_or(usage)?,
		))),
		Some("--tcp") => {
			let address: SocketAddr = arguments.next().ok_or(usage)?.parse()?;
			let client_public = decode_public(&arguments.next().ok_or(usage)?)?;
			let client_secret = read_secret(Path::new(&arguments.next().ok_or(usage)?))?;
			let server_public = decode_public(&arguments.next().ok_or(usage)?)?;
			ConfiguredBinding::Tcp(TcpBinding::new(
				address,
				KxKeyPair {
					public: client_public,
					secret: client_secret,
				},
				server_public,
			))
		}
		#[cfg(unix)]
		Some("--unix") => ConfiguredBinding::Unix(UnixBinding::new(PathBuf::from(
			arguments.next().ok_or(usage)?,
		))),
		#[cfg(windows)]
		Some("--named-pipe") => ConfiguredBinding::NamedPipe(NamedPipeBinding::new(
			&arguments.next().ok_or(usage)?,
			&arguments.next().ok_or(usage)?,
		)?),
		_ => return Err(usage.into()),
	})
}

fn request(
	arguments: &mut impl Iterator<Item = String>,
) -> Result<(Vec<u8>, Option<SubmissionCommand>), Box<dyn Error>> {
	let operation = arguments.next().ok_or(USAGE)?;
	let (request, submission) = match operation.as_str() {
		"submit" | "submit-items" => {
			let source = arguments.next().ok_or(USAGE)?;
			if arguments.next().is_some() {
				return Err(USAGE.into());
			}
			let bytes = read_document(&source)?;
			validate(&bytes, EnvelopeKind::Request)?;
			let parsed = SubmissionRequest::parse(&bytes)?;
			let expected = if operation == "submit" {
				SubmitOperation::Submit
			} else {
				SubmitOperation::SubmitItems
			};
			if parsed.operation != expected {
				return Err(format!("input operation does not match {operation}").into());
			}
			let command = SubmissionCommand {
				operation: parsed.operation,
				job_count: parsed.jobs.len(),
			};
			(bytes, Some(command))
		}
		"query" | "query-job" | "cancel" | "retry" => {
			let job = arguments.next().ok_or(USAGE)?;
			if arguments.next().is_some() {
				return Err(USAGE.into());
			}
			let directive = match operation.as_str() {
				"query" => "Query",
				"query-job" => "Query-Job",
				"cancel" => "Cancel",
				"retry" => "Retry",
				_ => unreachable!(),
			};
			(envelope(&format!("{directive} {job}\n")), None)
		}
		"lookup" => {
			let application = arguments.next().ok_or(USAGE)?;
			let keys: Vec<_> = arguments.collect();
			if keys.is_empty() {
				return Err(USAGE.into());
			}
			let mut body = format!("Lookup-Submission {}\n", quote(&application));
			for key in keys {
				writeln!(body, "Idempotency-Key {}", quote(&key))?;
			}
			(envelope(&body), None)
		}
		"reroute" => {
			let job = arguments.next().ok_or(USAGE)?;
			let route = arguments.next().ok_or(USAGE)?;
			let body = match route.as_str() {
				"route" => format!("Reroute {job}\nNext-Hop Route\n"),
				"active" | "passive" => {
					let next_hop = arguments.next().ok_or(USAGE)?;
					let mode = if route == "active" {
						"Active"
					} else {
						"Passive"
					};
					format!("Reroute {job}\nNext-Hop {mode} {}\n", quote(&next_hop))
				}
				_ => return Err(USAGE.into()),
			};
			if arguments.next().is_some() {
				return Err(USAGE.into());
			}
			(envelope(&body), None)
		}
		"capabilities" => {
			if arguments.next().is_some() {
				return Err(USAGE.into());
			}
			(envelope("Capabilities\n"), None)
		}
		_ => return Err(USAGE.into()),
	};
	validate(&request, EnvelopeKind::Request)?;
	Ok((request, submission))
}

fn submission_exit_status(
	document: &Document,
	command: SubmissionCommand,
) -> Result<i32, &'static str> {
	if valid_error_result(document) {
		return Ok(1);
	}
	let operation = match command.operation {
		SubmitOperation::Submit => "Submit",
		SubmitOperation::SubmitItems => "Submit-Items",
	};
	let Some(first) = document.lines.first() else {
		return Err("submission returned an empty result");
	};
	match first.fields.as_slice() {
		[op, status]
			if unquoted(op, operation)
				&& unquoted(status, "Committed")
				&& valid_committed_result(document, command.job_count) =>
		{
			Ok(0)
		}
		[op, status]
			if unquoted(op, operation)
				&& unquoted(status, "Not-Committed")
				&& valid_not_committed_result(document, command.job_count) =>
		{
			Ok(1)
		}
		_ => Err("submission returned an invalid or mismatched result"),
	}
}

fn valid_error_result(document: &Document) -> bool {
	match document.lines.as_slice() {
		[line] => match line.fields.as_slice() {
			[name, reason, description] => {
				unquoted(name, "Error")
					&& matches!(
						reason.text.as_str(),
						"Invalid" | "NotAuthorized" | "TemporaryFailure"
					) && !reason.quoted
					&& description.quoted
			}
			_ => false,
		},
		_ => false,
	}
}

fn valid_committed_result(document: &Document, job_count: usize) -> bool {
	if document.lines.len() != job_count + 1 {
		return false;
	}
	document
		.lines
		.iter()
		.skip(1)
		.enumerate()
		.all(|(offset, line)| match line.fields.as_slice() {
			[name, index, outcome, job_id, state] => {
				unquoted(name, "Job")
					&& parse_index(index) == Some(offset + 1)
					&& !outcome.quoted
					&& matches!(outcome.text.as_str(), "New" | "Existing")
					&& !job_id.quoted
					&& valid_job_id(&job_id.text)
					&& !state.quoted
					&& valid_job_state(&state.text)
			}
			_ => false,
		})
}

fn valid_not_committed_result(document: &Document, job_count: usize) -> bool {
	if document.lines.len() < 2 {
		return false;
	}
	let mut previous = 0;
	for line in document.lines.iter().skip(1) {
		let [name, index, failure, description] = line.fields.as_slice() else {
			return false;
		};
		let Some(index) = parse_index(index) else {
			return false;
		};
		if !unquoted(name, "Failure")
			|| index < previous
			|| index > job_count
			|| failure.quoted
			|| !matches!(
				failure.text.as_str(),
				"Conflict" | "Invalid" | "PermanentFailure" | "TemporaryFailure"
			) || !description.quoted
		{
			return false;
		}
		previous = index;
	}
	true
}

fn unquoted(field: &Field, expected: &str) -> bool {
	!field.quoted && field.text == expected
}

fn parse_index(field: &Field) -> Option<usize> {
	(!field.quoted
		&& !field.text.is_empty()
		&& !field.text.starts_with('0')
		&& field.text.bytes().all(|byte| byte.is_ascii_digit()))
	.then(|| field.text.parse().ok())
	.flatten()
}

fn valid_job_id(value: &str) -> bool {
	value.len() == 33
		&& value.starts_with('J')
		&& value[1..]
			.bytes()
			.all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_job_state(value: &str) -> bool {
	matches!(
		value,
		"Active" | "Queued" | "Deferred" | "Delivered" | "Rejected" | "Failed" | "Cancelled"
	)
}

fn envelope(body: &str) -> Vec<u8> {
	format!("TITH-IPC 1\n{body}End\n").into_bytes()
}

fn read_document(source: &str) -> Result<Vec<u8>, Box<dyn Error>> {
	if source == "-" {
		let mut input = Vec::new();
		io::stdin().read_to_end(&mut input)?;
		Ok(input)
	} else {
		Ok(fs::read(source)?)
	}
}

fn decode_public(value: &str) -> Result<KxPublicKey, Box<dyn Error>> {
	if value.len() != 43 || value.contains('=') {
		return Err("invalid IPC public key".into());
	}
	let bytes: [u8; KX_PUBLIC_KEY_BYTES] = STANDARD_NO_PAD
		.decode(value)?
		.try_into()
		.map_err(|_| "invalid IPC public key length")?;
	Ok(KxPublicKey::from_bytes(bytes))
}

fn read_secret(path: &Path) -> Result<KxSecretKey, Box<dyn Error>> {
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt as _;
		if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
			return Err("IPC secret key file is accessible by group or other users".into());
		}
	}
	let bytes: [u8; KX_SECRET_KEY_BYTES] = fs::read(path)?
		.try_into()
		.map_err(|_| "IPC secret key file has the wrong length")?;
	Ok(KxSecretKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn constructs_canonical_standard_commands() {
		let mut arguments = ["lookup", "mailer", "key one", "key-two"]
			.into_iter()
			.map(str::to_owned);
		let (request, submission) = request(&mut arguments).unwrap();
		assert!(submission.is_none());
		assert_eq!(
			request,
			b"TITH-IPC 1\nLookup-Submission \"mailer\"\nIdempotency-Key \"key one\"\nIdempotency-Key \"key-two\"\nEnd\n"
		);
	}

	#[test]
	fn assigns_submission_exit_statuses() {
		let command = SubmissionCommand {
			operation: SubmitOperation::Submit,
			job_count: 1,
		};
		let committed = validate(
			b"TITH-IPC-Result 1\nSubmit Committed\nJob 1 New J0123456789abcdef0123456789abcdef Queued\nEnd\n",
			EnvelopeKind::Result,
		)
		.unwrap();
		assert_eq!(submission_exit_status(&committed, command), Ok(0));

		let rejected = validate(
			b"TITH-IPC-Result 1\nSubmit Not-Committed\nFailure 1 Invalid \"bad job\"\nEnd\n",
			EnvelopeKind::Result,
		)
		.unwrap();
		assert_eq!(submission_exit_status(&rejected, command), Ok(1));

		let error = validate(
			b"TITH-IPC-Result 1\nError NotAuthorized \"caller is not authorized\"\nEnd\n",
			EnvelopeKind::Result,
		)
		.unwrap();
		assert_eq!(submission_exit_status(&error, command), Ok(1));
	}

	#[test]
	fn rejects_invalid_or_mismatched_submission_results() {
		let command = SubmissionCommand {
			operation: SubmitOperation::Submit,
			job_count: 1,
		};
		for bytes in [
			b"TITH-IPC-Result 1\nSubmit-Items Not-Committed\nFailure 1 Invalid \"bad job\"\nEnd\n"
				.as_slice(),
			b"TITH-IPC-Result 1\nSubmit Not-Committed\nEnd\n",
			b"TITH-IPC-Result 1\nError Unknown \"bad result\"\nEnd\n",
		] {
			let result = validate(bytes, EnvelopeKind::Result).unwrap();
			assert!(submission_exit_status(&result, command).is_err());
		}
	}
}
