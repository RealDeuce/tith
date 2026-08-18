//! `tith nodelist` subcommands.

use std::error::Error;
use std::fs;
use std::io::{self, Read, Write};

use tith_nodelist::Nodelist;
use tith_nodelist_legacy::{Overrides, convert, load_overrides};

const USAGE: &str =
	"usage: tith nodelist convert [--verify DOMAIN] [OVERRIDES-FILE...] < FTS-5000 > TTS-5000";

pub fn run(arguments: &mut impl Iterator<Item = String>) -> Result<i32, Box<dyn Error>> {
	match arguments.next().as_deref() {
		Some("convert") => convert_command(arguments),
		_ => Err(USAGE.into()),
	}
}

fn convert_command(arguments: &mut impl Iterator<Item = String>) -> Result<i32, Box<dyn Error>> {
	let mut verify: Option<String> = None;
	let mut overrides = Overrides::default();
	let mut sources = Vec::new();
	while let Some(argument) = arguments.next() {
		if argument == "--verify" {
			if verify.is_some() {
				return Err(USAGE.into());
			}
			verify = Some(arguments.next().ok_or(USAGE)?);
		} else if argument.starts_with('-') && argument != "-" {
			return Err(USAGE.into());
		} else {
			sources.push(argument);
		}
	}
	for source in &sources {
		let bytes = fs::read(source)
			.map_err(|error| format!("cannot read overrides file {source}: {error}"))?;
		load_overrides(&bytes, &mut overrides).map_err(|error| format!("{source}: {error}"))?;
	}

	let mut input = Vec::new();
	io::stdin().read_to_end(&mut input)?;
	let mut warnings = 0_usize;
	let output = convert(&input, &overrides, &mut |warning| {
		warnings += 1;
		eprintln!("tith nodelist convert: {warning}");
	})?;

	// Self-check: the converter's whole purpose is to produce something the
	// native parser accepts, so let it say so rather than trusting the port.
	if let Some(domain) = verify.as_deref() {
		Nodelist::parse(domain, &output)
			.map_err(|error| format!("converted nodelist does not parse: {error}"))?;
	}

	io::stdout().write_all(output.as_bytes())?;
	io::stdout().flush()?;
	if warnings != 0 {
		eprintln!("tith nodelist convert: {warnings} warning(s)");
	}
	Ok(0)
}
