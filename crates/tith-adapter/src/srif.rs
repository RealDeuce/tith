//! The FSC-0086.001 external request processor interface.
//!
//! The SRIF filename is the only parameter the mailer passes to the processor.
//! The processor reads the `RequestList` and writes a `ResponseList` naming the
//! files to send, each prefixed by what to do with it afterwards. The mailer is
//! responsible for erasing the SRIF.
//!
//! A `ResponseList` names files to send back to the requesting peer. Each one is
//! a peer-addressed standalone File, submitted as a TSP-0006 `Job Peer-File`
//! addressed to that peer. This module runs the processor and reads its answer;
//! building and sending the submission belongs to the IPC client, so nothing
//! here depends on the native protocol layer.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// What the mailer should do with a file after sending it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Afterward {
	/// `=`: erase the file if it was sent successfully.
	EraseIfSent,
	/// `+`: do not erase the file after sending.
	Keep,
	/// `-`: erase the file in any case after the session.
	EraseAlways,
}

impl Afterward {
	const fn parse(marker: u8) -> Option<Self> {
		Some(match marker {
			b'=' => Self::EraseIfSent,
			b'+' => Self::Keep,
			b'-' => Self::EraseAlways,
			_ => return None,
		})
	}

	/// The TSP-0006 `Source-Disposition` this marker authorizes.
	///
	/// `=` is exactly Delete: TSP-0005 section 5 performs it only after every
	/// delivery copy is Delivered. `+` is Keep. `-` asks for erasure whatever
	/// happens, which no native disposition expresses, so it maps to Keep and
	/// the adapter owes the removal itself rather than overstating what the Job
	/// has promised.
	#[must_use]
	pub const fn disposition(self) -> &'static str {
		match self {
			Self::EraseIfSent => "Delete",
			Self::Keep | Self::EraseAlways => "Keep",
		}
	}

	/// Whether the adapter still owes a local removal of its own.
	///
	/// TSP-0013 section 3 requires such a removal be recorded rather than merely
	/// remembered, because it cannot be inferred from the Job. It is owed for
	/// every `-` file the processor offered, including one excluded from the
	/// reply by the request's condition: "in any case" is not conditional on the
	/// file having been sent.
	#[must_use]
	pub const fn needs_local_cleanup(self) -> bool {
		matches!(self, Self::EraseAlways)
	}
}

/// One file the processor offered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Offered {
	pub path: PathBuf,
	pub afterward: Afterward,
}

/// The facts a SRIF states about the session.
#[derive(Clone, Debug)]
pub struct Session {
	pub sysop: String,
	/// The remote system's main AKA, and any additional ones.
	pub akas: Vec<String>,
	/// The AKA of the local system which was called.
	pub our_aka: String,
	/// Whether the session was password protected.
	pub protected: bool,
	/// Whether the remote identity is listed for this adapter.
	pub listed: bool,
}

/// Writes the SRIF and its request list, then runs the processor.
///
/// `requests` are the filenames the peer asked for, one per line.
pub struct Processor {
	/// The program to run. The SRIF path is appended as its only argument.
	pub program: PathBuf,
	/// A private directory for the SRIF and its two lists.
	pub working_directory: PathBuf,
}

/// What a processor run produced.
#[derive(Clone, Debug)]
pub struct Response {
	pub offered: Vec<Offered>,
}

impl Processor {
	/// Runs the processor for one request.
	pub fn run(
		&self,
		session: &Session,
		requests: &[String],
		identity: u64,
	) -> io::Result<Response> {
		fs::create_dir_all(&self.working_directory)?;
		let request_list = self.working_directory.join(format!("{identity:08x}.req"));
		let response_list = self.working_directory.join(format!("{identity:08x}.rsp"));
		let srif = self.working_directory.join(format!("{identity:08x}.srf"));

		let mut list = String::new();
		for request in requests {
			// A request is one filename per line; a request carrying a line break
			// is not representable and is dropped rather than splitting into two.
			if request.contains(['\r', '\n']) {
				continue;
			}
			list.push_str(request);
			list.push('\n');
		}
		fs::write(&request_list, list)?;
		// The response list must exist and differ from the request list.
		fs::write(&response_list, "")?;
		fs::write(&srif, write_srif(session, &request_list, &response_list))?;

		let status = Command::new(&self.program).arg(&srif).status();
		let result = match status {
			Ok(status) if status.success() => {
				parse_response_list(&fs::read_to_string(&response_list)?)
			}
			Ok(_) | Err(_) => Vec::new(),
		};

		// The mailer is responsible for erasing the SRIF.
		let _ = fs::remove_file(&srif);
		let _ = fs::remove_file(&request_list);
		let _ = fs::remove_file(&response_list);
		status?;
		Ok(Response { offered: result })
	}
}

/// The SRIF text for one session.
#[must_use]
pub fn write_srif(session: &Session, request_list: &Path, response_list: &Path) -> String {
	let mut output = String::new();
	let mut line = |keyword: &str, value: &str| {
		if !value.contains(['\r', '\n']) {
			output.push_str(keyword);
			output.push(' ');
			output.push_str(value);
			output.push('\n');
		}
	};
	line("Sysop", &session.sysop);
	for aka in &session.akas {
		line("AKA", aka);
	}
	// TITH has no line rate and no event schedule to report. Baud zero and Time
	// -1 are the documented ways to say "not applicable" and "no limit".
	line("Baud", "0");
	line("Time", "-1");
	line("RequestList", &request_list.to_string_lossy());
	line("ResponseList", &response_list.to_string_lossy());
	line(
		"RemoteStatus",
		if session.protected {
			"PROTECTED"
		} else {
			"UNPROTECTED"
		},
	);
	line(
		"SystemStatus",
		if session.listed { "LISTED" } else { "UNLISTED" },
	);
	line("SessionType", "OTHER");
	line("OurAKA", &session.our_aka);
	output
}

/// Reads a `ResponseList`.
///
/// One file per line, including its path, with the first character stating what
/// the mailer should do with it afterwards.
#[must_use]
pub fn parse_response_list(contents: &str) -> Vec<Offered> {
	contents
		.lines()
		.filter_map(|line| {
			let line = line.trim_end_matches('\r');
			let marker = *line.as_bytes().first()?;
			let afterward = Afterward::parse(marker)?;
			let path = &line[1..];
			(!path.is_empty()).then(|| Offered {
				path: PathBuf::from(path),
				afterward,
			})
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn session() -> Session {
		Session {
			sysop: "Stephen Hurd".to_owned(),
			akas: vec!["1:104/36@fidonet".to_owned(), "1:104/1@fidonet".to_owned()],
			our_aka: "1:104/36@fidonet".to_owned(),
			protected: true,
			listed: true,
		}
	}

	#[test]
	fn the_srif_carries_every_required_statement() {
		let text = write_srif(&session(), Path::new("/tmp/a.req"), Path::new("/tmp/a.rsp"));
		for required in [
			"Sysop Stephen Hurd",
			"AKA 1:104/36@fidonet",
			"Baud 0",
			"Time -1",
			"RequestList /tmp/a.req",
			"ResponseList /tmp/a.rsp",
			"RemoteStatus PROTECTED",
			"SystemStatus LISTED",
		] {
			assert!(
				text.contains(required),
				"{required} is missing from {text:?}"
			);
		}
		// One command plus parameter per line, and no comments.
		assert!(text.lines().all(|line| line.contains(' ')));
		// The two lists must not be equal.
		assert_ne!(
			text.lines().find(|l| l.starts_with("RequestList")),
			text.lines().find(|l| l.starts_with("ResponseList"))
		);

		let unprotected = Session {
			protected: false,
			listed: false,
			..session()
		};
		let text = write_srif(&unprotected, Path::new("/a"), Path::new("/b"));
		assert!(text.contains("RemoteStatus UNPROTECTED"));
		assert!(text.contains("SystemStatus UNLISTED"));
	}

	#[test]
	fn every_response_marker_is_understood() {
		let offered = parse_response_list("=/files/a.zip\r\n+/files/b.zip\n-/files/c.zip\n");
		assert_eq!(
			offered,
			[
				Offered {
					path: PathBuf::from("/files/a.zip"),
					afterward: Afterward::EraseIfSent
				},
				Offered {
					path: PathBuf::from("/files/b.zip"),
					afterward: Afterward::Keep
				},
				Offered {
					path: PathBuf::from("/files/c.zip"),
					afterward: Afterward::EraseAlways
				},
			]
		);
		// A line with no marker, or a marker with no path, is not a response.
		assert!(parse_response_list("/files/a.zip\n").is_empty());
		assert!(parse_response_list("=\n").is_empty());
		assert!(parse_response_list("").is_empty());
	}

	#[test]
	fn each_marker_maps_to_the_disposition_it_actually_authorizes() {
		// TSP-0006 Delete fires only after every delivery copy is Delivered, which
		// is exactly what "=" asks for. "-" wants erasure whatever happens, and
		// there is no native disposition for that, so it stays Keep and the
		// adapter owes the removal itself rather than overstating the obligation.
		assert_eq!(Afterward::EraseIfSent.disposition(), "Delete");
		assert!(!Afterward::EraseIfSent.needs_local_cleanup());
		assert_eq!(Afterward::Keep.disposition(), "Keep");
		assert!(!Afterward::Keep.needs_local_cleanup());
		assert_eq!(Afterward::EraseAlways.disposition(), "Keep");
		assert!(Afterward::EraseAlways.needs_local_cleanup());
	}
}
