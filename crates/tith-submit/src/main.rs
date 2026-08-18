use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use tith_crypto::{KX_PUBLIC_KEY_BYTES, KX_SECRET_KEY_BYTES, KxKeyPair, KxPublicKey, KxSecretKey};
use tith_ipc::{EnvelopeKind, SubmissionRequest, SubmitOperation, quote};
#[cfg(windows)]
use tith_submit::NamedPipeBinding;
#[cfg(unix)]
use tith_submit::UnixBinding;
use tith_submit::{Binding, ConfiguredBinding, FilesystemBinding, TcpBinding, validate};

const USAGE: &str = "usage: tith-submit (--files ROOT | --tcp ADDRESS CLIENT-PUBLIC CLIENT-SECRET-FILE SERVER-PUBLIC | --unix SOCKET | --named-pipe PIPE SERVICE-SID) (submit FILE|- | submit-items FILE|- | query JOB-ID | query-job JOB-ID | lookup APPLICATION KEY... | cancel JOB-ID | retry JOB-ID | reroute JOB-ID route|active NEXT-HOP|passive NEXT-HOP | capabilities)";

fn main() {
	match run() {
		Ok(status) => std::process::exit(status),
		Err(error) => {
			eprintln!("tith-submit: {error}");
			std::process::exit(2);
		}
	}
}

fn run() -> Result<i32, Box<dyn Error>> {
	let mut arguments = std::env::args().skip(1);
	let binding = match arguments.next().as_deref() {
		Some("--files") => ConfiguredBinding::Filesystem(FilesystemBinding::new(PathBuf::from(
			arguments.next().ok_or(USAGE)?,
		))),
		Some("--tcp") => {
			let address: SocketAddr = arguments.next().ok_or(USAGE)?.parse()?;
			let client_public = decode_public(&arguments.next().ok_or(USAGE)?)?;
			let client_secret = read_secret(Path::new(&arguments.next().ok_or(USAGE)?))?;
			let server_public = decode_public(&arguments.next().ok_or(USAGE)?)?;
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
			arguments.next().ok_or(USAGE)?,
		))),
		#[cfg(windows)]
		Some("--named-pipe") => ConfiguredBinding::NamedPipe(NamedPipeBinding::new(
			&arguments.next().ok_or(USAGE)?,
			&arguments.next().ok_or(USAGE)?,
		)?),
		_ => return Err(USAGE.into()),
	};
	let (request, submission) = request(&mut arguments)?;
	let result = binding.transact(&request)?;
	io::stdout().write_all(&result)?;
	io::stdout().flush()?;
	if !submission {
		return Ok(0);
	}
	let result = validate(&result, EnvelopeKind::Result)?;
	let committed = result.lines.first().is_some_and(|line| {
		line.fields.len() == 2
			&& !line.fields[0].quoted
			&& matches!(line.fields[0].text.as_str(), "Submit" | "Submit-Items")
			&& !line.fields[1].quoted
			&& line.fields[1].text == "Committed"
	});
	// TSP-0006 does not assign complete Error results an exit status; issue #11
	// records the temporary choice to classify every complete rejection as one.
	Ok(i32::from(!committed))
}

fn request(
	arguments: &mut impl Iterator<Item = String>,
) -> Result<(Vec<u8>, bool), Box<dyn Error>> {
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
			(bytes, true)
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
			(envelope(&format!("{directive} {job}\n")), false)
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
			(envelope(&body), false)
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
			(envelope(&body), false)
		}
		"capabilities" => {
			if arguments.next().is_some() {
				return Err(USAGE.into());
			}
			(envelope("Capabilities\n"), false)
		}
		_ => return Err(USAGE.into()),
	};
	validate(&request, EnvelopeKind::Request)?;
	Ok((request, submission))
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
		assert!(!submission);
		assert_eq!(
			request,
			b"TITH-IPC 1\nLookup-Submission \"mailer\"\nIdempotency-Key \"key one\"\nIdempotency-Key \"key-two\"\nEnd\n"
		);
	}
}
