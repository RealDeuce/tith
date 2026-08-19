//! The TITH client multiplexer.
//!
//! Rust links its internal crates statically, so every separate client binary
//! re-embeds the runtime and the shared protocol crates. One multiplexed
//! binary carries a single copy instead.
//!
//! TSP-0006 section 9 asks for a client named "tith-submit" invoked as
//! `tith-submit submit <file>`. Installing `tith-submit` as a link to this
//! binary satisfies that: the file stem of `argv[0]` selects the submit client
//! directly, so both spellings reach the same code.

#![forbid(unsafe_code)]

mod bso;
mod inbound;
mod netmail;
mod nodelist;

use std::error::Error;
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "usage: tith (submit ... | nodelist convert ... | netmail scan ... | bso scan ... | inbound run ...)";

fn main() -> ExitCode {
	let mut arguments = std::env::args();
	let program = arguments.next().unwrap_or_default();
	// A link named tith-submit dispatches straight to the submit client.
	let linked_as_submit = Path::new(&program)
		.file_stem()
		.is_some_and(|stem| stem == "tith-submit");
	// Diagnostics name the tool that failed rather than the spelling used to
	// reach it, so a `tith submit` error still points at the tith-submit usage
	// that TSP-0006 section 9 documents.
	let (name, result) = if linked_as_submit {
		("tith-submit", tith_submit::cli::run(&mut arguments))
	} else {
		run(&mut arguments)
	};
	match result {
		Ok(status) => ExitCode::from(u8::try_from(status).unwrap_or(2)),
		Err(error) => {
			eprintln!("{name}: {error}");
			ExitCode::from(2)
		}
	}
}

fn run(
	arguments: &mut impl Iterator<Item = String>,
) -> (&'static str, Result<i32, Box<dyn Error>>) {
	// Dispatch is an exact match with no abbreviations and no aliases.
	match arguments.next().as_deref() {
		Some("submit") => ("tith-submit", tith_submit::cli::run(arguments)),
		Some("nodelist") => ("tith nodelist", nodelist::run(arguments)),
		Some("netmail") => ("tith netmail", netmail::run(arguments)),
		Some("bso") => ("tith bso", bso::run(arguments)),
		Some("inbound") => ("tith inbound", inbound::run(arguments)),
		_ => ("tith", Err(USAGE.into())),
	}
}
