//! TIC file distribution, per TSP-0003 section 9.
//!
//! One FTS-5006.001 TIC and its named companion map to one standalone TTS-0005
//! distribution File. The transfer name lives here rather than in the legacy
//! crate because section 9 defines it as "a stable safe 8.3 DOS transfer name
//! generated and recorded by the TSP-0013 adapter" — generating it is ledger
//! work and cannot be separated from the record which keeps it stable.

use tith_wire::item::ReadFile;

use crate::address;
use crate::convert::{Context, ConvertError};

/// FTS-5006.001 section 3 CRC-32: reflected, polynomial `EDB88320`,
/// preconditioned to all ones and postconditioned by flipping every bit.
#[must_use]
pub fn crc32(bytes: &[u8]) -> u32 {
	let mut crc = 0xffff_ffff_u32;
	for byte in bytes {
		let mut k = (crc ^ u32::from(*byte)) & 0xff;
		for _ in 0..8 {
			k = if k & 1 != 0 {
				(k >> 1) ^ 0xedb8_8320
			} else {
				k >> 1
			};
		}
		crc = ((crc >> 8) & 0x00ff_ffff) ^ k;
	}
	!crc
}

/// Whether a name is already a safe 8.3 transfer name.
///
/// Kept deliberately narrow: TSP-0013 section 4 forbids a remote Filename from
/// becoming a local path component without the validation and name generation
/// the legacy format requires.
#[must_use]
pub fn is_safe_eight_three(name: &str) -> bool {
	let safe = |value: &str, maximum: usize| {
		(1..=maximum).contains(&value.len())
			&& value.bytes().all(|byte| {
				byte.is_ascii_alphanumeric()
					|| matches!(byte, b'-' | b'_' | b'$' | b'~' | b'!' | b'#')
			})
	};
	match name.split_once('.') {
		Some((base, extension)) => safe(base, 8) && safe(extension, 3),
		None => safe(name, 8),
	}
}

/// The stable 8.3 transfer name for a companion.
///
/// A Filename which is already a safe 8.3 name is kept, so the common case
/// needs no `Lfile`. Anything else is replaced by the caller's stable
/// identifier, which the ledger records; the remote name never reaches the
/// filesystem.
#[must_use]
pub fn transfer_name(filename: &str, identity: u32) -> String {
	let lowered = filename.to_ascii_lowercase();
	if is_safe_eight_three(&lowered) {
		return lowered;
	}
	let extension = lowered
		.rsplit_once('.')
		.map(|(_, extension)| extension)
		.filter(|extension| {
			(1..=3).contains(&extension.len())
				&& extension.bytes().all(|b| b.is_ascii_alphanumeric())
		})
		.unwrap_or("dat");
	format!("{identity:08x}.{extension}")
}

/// The legacy link values a TIC carries which the item does not.
#[derive(Clone, Debug, Default)]
pub struct TicOptions {
	/// The stable transfer name the ledger recorded for this companion.
	pub transfer_name: String,
	/// The immediate legacy destination, when the selected link requires one.
	pub to: Option<String>,
	/// The configured link password. TSP-0003 section 9: trusted legacy link
	/// policy only, never derived from a native key.
	pub password: Option<String>,
}

/// Writes the canonical TIC for a standalone distribution File.
pub fn to_tic(
	file: &ReadFile,
	context: &Context,
	options: &TicOptions,
) -> Result<String, ConvertError> {
	let mut lines: Vec<String> = Vec::new();
	let mut push = |keyword: &str, value: &str| -> Result<(), ConvertError> {
		// No line is folded; a value containing CR, LF, or NUL is not
		// representable.
		if value.contains(['\r', '\n', '\0']) {
			return Err(ConvertError::Unrepresentable(
				"a TIC value with a line break",
			));
		}
		lines.push(format!("{keyword} {value}"));
		Ok(())
	};

	// A peer-addressed File has no Area, so it has no TIC. TSP-0003 section 9
	// maps a TIC to a distribution File and nothing else.
	let area = file
		.data
		.area
		.as_ref()
		.ok_or(ConvertError::Unrepresentable(
			"a TIC for a File with no Area",
		))?;
	push("Area", context.area_tag(&area.name)?)?;
	push(
		"Origin",
		&address::five_dimensional(&context.legacy_address(&file.signing.origin)?)?,
	)?;
	push(
		"From",
		&address::five_dimensional(&context.legacy_address(&context.packet_origin)?)?,
	)?;
	if let Some(to) = &options.to {
		push("To", to)?;
	}
	if !is_safe_eight_three(&options.transfer_name) {
		return Err(ConvertError::Unrepresentable(
			"a transfer name which is not a safe 8.3 name",
		));
	}
	push("File", &options.transfer_name)?;
	let filename = file
		.data
		.filename
		.as_deref()
		.ok_or(ConvertError::Unrepresentable(
			"a TIC for a File without Filename",
		))?;
	if filename != options.transfer_name {
		push("Lfile", filename)?;
	}
	push("Size", &file.data.contents.len().to_string())?;
	if let Some(timestamp) = file.data.timestamp {
		push("Date", &timestamp.to_string())?;
	}
	if let Some(description) = &file.data.short_description {
		push("Desc", description)?;
	}
	for line in &file.data.long_description_lines {
		push("Ldesc", line)?;
	}
	if let Some(value) = &file.data.tear_line {
		push("Created", value)?;
	}
	if let Some(value) = &file.data.magic_word {
		push("Magic", value)?;
	}
	if let Some(value) = &file.data.replaces {
		push("Replaces", value)?;
	}
	push("Crc", &format!("{:08X}", crc32(&file.data.contents)))?;
	for via in &file.vias {
		// Each Path maps exactly to one Via: address, decimal POSIX timestamp,
		// then the software string.
		if via.address.is_anonymous() {
			return Err(ConvertError::Unrepresentable(
				"a Via whose anonymous address cannot carry its required PublicKey",
			));
		}
		push(
			"Path",
			&format!(
				"{} {} {}",
				address::five_dimensional(&context.legacy_address(&via.address)?)?,
				via.timestamp,
				via.software
			),
		)?;
	}
	for address in &file.seen_by {
		push(
			"Seenby",
			&address::five_dimensional(&context.legacy_address(address)?)?,
		)?;
	}
	if let Some(password) = &options.password {
		push("Pw", password)?;
	}
	let mut output = String::new();
	for line in lines {
		output.push_str(&line);
		output.push_str("\r\n");
	}
	Ok(output)
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::BTreeMap;
	use tith_crypto::SigningKeyPair;
	use tith_wire::Address;
	use tith_wire::bundle::Identity;
	use tith_wire::item::{
		AreaData, ItemProvenance, StandaloneFileData, build_originated_file, read_standalone_file,
	};

	fn context() -> Context {
		Context {
			packet_origin: "fidonet#1:104/36".parse().unwrap(),
			packet_destination: "fidonet#1:104/1".parse().unwrap(),
			domain: "fidonet".to_owned(),
			domain_case: crate::config::DomainCase::Preserve,
			product: "tith".to_owned(),
			version: "0.1".to_owned(),
			area_tags: BTreeMap::from([("SYNCDATA".to_owned(), "SYNCDATA".to_owned())]),
		}
	}

	fn file(filename: &str) -> ReadFile {
		let keys = SigningKeyPair::from_seed(&[95; 32]).unwrap();
		let origin: Address = "fidonet#1:104/36".parse().unwrap();
		let item = build_originated_file(
			StandaloneFileData {
				filename: Some(filename.to_owned()),
				timestamp: Some(1_755_400_000),
				contents: b"payload".to_vec(),
				area: Some(AreaData {
					name: "SYNCDATA".to_owned(),
					description: None,
				}),
				short_description: Some("A file".to_owned()),
				long_description_lines: vec!["First".to_owned(), "Second".to_owned()],
				tear_line: Some("TITH 0.1".to_owned()),
				magic_word: Some("GOODIES".to_owned()),
				replaces: Some("goodies.*".to_owned()),
			},
			&ItemProvenance {
				origin: origin.clone(),
				signer: Some(Identity {
					address: origin.clone(),
					public_key: keys.public,
				}),
			},
			&keys.secret,
			9,
			1_755_500_001,
			"tith 0.1",
			&["fidonet#1:104/1".parse().unwrap()],
		)
		.unwrap();
		read_standalone_file(&item).unwrap()
	}

	#[test]
	fn the_reference_crc_matches_known_vectors() {
		// The standard CRC-32 the FTS-5006 section 3 pseudocode computes.
		assert_eq!(crc32(b""), 0x0000_0000);
		assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
		assert_eq!(
			crc32(b"The quick brown fox jumps over the lazy dog"),
			0x414F_A339
		);
	}

	#[test]
	fn keywords_are_written_in_the_documented_order() {
		let tic = to_tic(
			&file("goodies.zip"),
			&context(),
			&TicOptions {
				transfer_name: "goodies.zip".to_owned(),
				to: Some("1:104/1@fidonet".to_owned()),
				password: Some("secret".to_owned()),
			},
		)
		.unwrap();
		let keywords: Vec<&str> = tic
			.lines()
			.map(|line| line.split(' ').next().unwrap())
			.collect();
		assert_eq!(
			keywords,
			[
				"Area", "Origin", "From", "To", "File", "Size", "Date", "Desc", "Ldesc", "Ldesc",
				"Created", "Magic", "Replaces", "Crc", "Path", "Seenby", "Pw"
			]
		);
		// CRLF line endings, and the CRC in eight uppercase hexadecimal digits.
		assert!(tic.contains("\r\n"));
		assert!(tic.contains(&format!("Crc {:08X}\r\n", crc32(b"payload"))));
		// No Lfile, because the Filename is already a safe 8.3 transfer name.
		assert!(!tic.contains("Lfile"));
		assert!(tic.contains("Size 7\r\n"));
		assert!(tic.contains("Origin 1:104/36@fidonet\r\n"));
	}

	#[test]
	fn an_unsafe_filename_is_replaced_and_recorded_as_lfile() {
		let name = transfer_name("longfilename.tar.gz", 0x0068_0024);
		assert_eq!(name, "00680024.gz");
		assert!(is_safe_eight_three(&name));

		let tic = to_tic(
			&file("longfilename.tar.gz"),
			&context(),
			&TicOptions {
				transfer_name: name.clone(),
				..TicOptions::default()
			},
		)
		.unwrap();
		assert!(tic.contains(&format!("File {name}\r\n")));
		assert!(tic.contains("Lfile longfilename.tar.gz\r\n"));
	}

	#[test]
	fn a_safe_name_is_kept_and_an_unsafe_one_is_recognised() {
		for name in ["goodies.zip", "a", "12345678.abc", "fil-1_$~.z"] {
			assert!(is_safe_eight_three(name), "{name}");
		}
		for name in [
			"",
			"toolongbase.zip",
			"name.abcd",
			"has space.zip",
			"a/b.zip",
			"..",
		] {
			assert!(!is_safe_eight_three(name), "{name}");
		}
		assert_eq!(transfer_name("GOODIES.ZIP", 1), "goodies.zip");
	}

	#[test]
	fn refuses_a_transfer_name_the_ledger_should_never_have_recorded() {
		let error = to_tic(
			&file("goodies.zip"),
			&context(),
			&TicOptions {
				transfer_name: "../escape.zip".to_owned(),
				..TicOptions::default()
			},
		)
		.unwrap_err();
		assert_eq!(
			error,
			ConvertError::Unrepresentable("a transfer name which is not a safe 8.3 name")
		);
	}
}
