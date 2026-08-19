//! Pairs packet messages with the reference file entries that carry their
//! payloads.
//!
//! A file attach in FTN is already a `NetMail`: `SBBSecho` packs the message into
//! the `.?ut` and writes the payload path into the `.?lo`. So the packet
//! supplies the message and the reference supplies both the file and its
//! post-send directive, and they pair by filename.

use std::collections::BTreeSet;
use std::path::Path;

use tith_bso::Reference;
use tith_message_legacy::{AttachStyle, Attachment, PackedMessage, file_list};

/// What a reference entry turned out to be.
///
/// The scan path reads `Correlation` directly; this is the classification the
/// tests assert against.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Resolution {
	/// Claimed by a `FileAttached` message in the packet.
	Attached,
	/// Accompanied by a TIC, so it is an area distribution `File`.
	Tic { area: String },
	/// Nothing claimed it, so it is a peer-addressed standalone `File` in its own
	/// right and is submitted as a TSP-0006 `Job Peer-File`.
	Unclaimed,
}

/// One message and the attachments it owns.
#[derive(Clone, Debug)]
pub struct CorrelatedMessage {
	pub message: PackedMessage,
	pub attachments: Vec<Attachment>,
	/// Reference lines this message consumed, for rewriting the flow file.
	pub consumed: Vec<String>,
}

/// The result of pairing one node's packets against one reference file.
#[derive(Clone, Debug, Default)]
pub struct Correlation {
	pub messages: Vec<CorrelatedMessage>,
	/// Entries that are area distributions, with the area their TIC names.
	pub distributions: Vec<(Reference, String)>,
	/// Entries nothing claimed. Each is a peer-addressed standalone `File`.
	pub unclaimed: Vec<Reference>,
}

/// Compares legacy filenames the way a filesystem-agnostic match must.
///
/// Only the final component is compared: a reference may carry a full path,
/// which section 3.1 recommends, while the Subject `FileList` carries a bare
/// name.
fn same_file(reference: &str, subject_name: &str) -> bool {
	let tail = |value: &str| {
		value
			.rsplit(['/', '\\'])
			.next()
			.unwrap_or(value)
			.to_ascii_lowercase()
	};
	tail(reference) == tail(subject_name)
}

/// Reads the area a TIC names, when one accompanies the file.
///
/// TSP-0003 section 9 maps one FTS-5006.001 TIC and its named companion to one
/// standalone distribution `File`, with the TIC `Area` becoming the `File`'s.
fn tic_area(payload: &Path) -> Option<String> {
	let tic = payload.with_extension("tic");
	let contents = std::fs::read_to_string(&tic).ok()?;
	contents.lines().find_map(|line| {
		let (keyword, value) = line.split_once(' ')?;
		keyword
			.eq_ignore_ascii_case("Area")
			.then(|| value.trim().to_owned())
	})
}

/// Correlates one node's messages and reference entries.
///
/// `beside` is the directory the reference file sits in, used to resolve a
/// bare filename.
#[must_use]
pub fn correlate(
	messages: Vec<PackedMessage>,
	references: &[Reference],
	beside: &Path,
	style: AttachStyle,
) -> Correlation {
	let mut claimed: BTreeSet<usize> = BTreeSet::new();
	let mut result = Correlation::default();

	for message in messages {
		let mut attachments = Vec::new();
		let mut consumed = Vec::new();
		if message.has_file_attached() {
			for wanted in file_list(&message.subject) {
				// Under the Binkley reading the Subject FileSpec may itself carry
				// a directive; the reference file's directive is authoritative
				// because that is what the mailer would have acted on.
				let bare = match style {
					AttachStyle::Binkley => {
						wanted.trim_start_matches(['#', '^', '-', '~', '!', '@'])
					}
					AttachStyle::Flags => wanted,
				};
				if bare.is_empty() {
					continue;
				}
				if let Some((index, reference)) =
					references.iter().enumerate().find(|(index, reference)| {
						!claimed.contains(index) && same_file(&reference.name, bare)
					}) {
					claimed.insert(index);
					attachments.push(tith_bso::as_attachment(reference));
					consumed.push(reference.line.clone());
				}
			}
		}
		result.messages.push(CorrelatedMessage {
			message,
			attachments,
			consumed,
		});
	}

	for (index, reference) in references.iter().enumerate() {
		if claimed.contains(&index) {
			continue;
		}
		match tic_area(&reference.resolve(beside)) {
			Some(area) => result.distributions.push((reference.clone(), area)),
			None => result.unclaimed.push(reference.clone()),
		}
	}
	result
}

/// Classifies one entry.
#[cfg(test)]
#[must_use]
pub fn resolution(correlation: &Correlation, reference: &Reference) -> Resolution {
	if correlation
		.messages
		.iter()
		.any(|message| message.consumed.contains(&reference.line))
	{
		return Resolution::Attached;
	}
	if let Some((_, area)) = correlation
		.distributions
		.iter()
		.find(|(entry, _)| entry.line == reference.line)
	{
		return Resolution::Tic { area: area.clone() };
	}
	Resolution::Unclaimed
}

#[cfg(test)]
mod tests {
	use super::*;
	use tith_bso::parse_reference;
	use tith_message_legacy::{Disposition, Endpoint, Packet};

	fn endpoint() -> Endpoint {
		Endpoint {
			zone: 1,
			net: 104,
			node: 36,
			point: 0,
		}
	}

	fn message(attributes: u16, subject: &str) -> PackedMessage {
		PackedMessage {
			origin: endpoint(),
			destination: endpoint(),
			attributes,
			date_time: "18 Aug 26  12:00:00".to_owned(),
			to_user: "Recipient".to_owned(),
			from_user: "Sender".to_owned(),
			subject: subject.to_owned(),
			controls: Vec::new(),
			text: "Body".to_owned(),
			area: None,
		}
	}

	fn temp_dir(name: &str) -> std::path::PathBuf {
		let path = std::env::temp_dir().join(format!(
			"tith-correlate-{name}-{}-{:?}",
			std::process::id(),
			std::thread::current().id()
		));
		let _ = std::fs::remove_dir_all(&path);
		std::fs::create_dir_all(&path).expect("temp directory");
		path
	}

	#[test]
	fn a_file_attached_message_claims_its_reference_entry() {
		let directory = temp_dir("attach");
		let references = parse_reference("^work.zip\n");
		let correlation = correlate(
			vec![message(1 << 4, "work.zip")],
			&references,
			&directory,
			AttachStyle::Flags,
		);
		assert_eq!(correlation.messages.len(), 1);
		let owned = &correlation.messages[0];
		assert_eq!(owned.attachments.len(), 1);
		assert_eq!(owned.attachments[0].name, "work.zip");
		// The reference file's directive wins, not the Subject's.
		assert_eq!(owned.attachments[0].disposition, Disposition::Delete);
		assert!(correlation.unclaimed.is_empty());
		assert_eq!(
			resolution(&correlation, &references[0]),
			Resolution::Attached
		);
		std::fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn a_reference_carrying_a_full_path_still_matches_a_bare_subject() {
		let directory = temp_dir("path");
		let references = parse_reference("#/spool/out/WORK.ZIP\n");
		let correlation = correlate(
			vec![message(1 << 4, "work.zip")],
			&references,
			&directory,
			AttachStyle::Flags,
		);
		assert_eq!(correlation.messages[0].attachments.len(), 1);
		assert_eq!(
			correlation.messages[0].attachments[0].disposition,
			Disposition::Truncate
		);
		std::fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn a_tic_accompanied_entry_becomes_an_area_distribution() {
		let directory = temp_dir("tic");
		std::fs::write(directory.join("goodies.zip"), b"payload").expect("payload");
		std::fs::write(
			directory.join("goodies.tic"),
			"Area SYNCDATA\r\nOrigin 1:104/36\r\n",
		)
		.expect("tic");
		let references = parse_reference("goodies.zip\n");
		let correlation = correlate(Vec::new(), &references, &directory, AttachStyle::Flags);
		assert_eq!(correlation.distributions.len(), 1);
		assert_eq!(correlation.distributions[0].1, "SYNCDATA");
		assert!(correlation.unclaimed.is_empty());
		assert_eq!(
			resolution(&correlation, &references[0]),
			Resolution::Tic {
				area: "SYNCDATA".to_owned()
			}
		);
		std::fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn an_arcmail_bundle_is_a_peer_addressed_file() {
		let directory = temp_dir("arcmail");
		let references = parse_reference("#0068002400.su0\n");
		let correlation = correlate(Vec::new(), &references, &directory, AttachStyle::Flags);
		assert!(correlation.distributions.is_empty());
		assert_eq!(correlation.unclaimed.len(), 1);
		assert_eq!(correlation.unclaimed[0].line, "#0068002400.su0");
		assert_eq!(
			resolution(&correlation, &references[0]),
			Resolution::Unclaimed
		);
		std::fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn a_message_without_the_attach_attribute_claims_nothing() {
		let directory = temp_dir("noattach");
		let references = parse_reference("work.zip\n");
		let correlation = correlate(
			vec![message(0, "work.zip")],
			&references,
			&directory,
			AttachStyle::Flags,
		);
		assert!(correlation.messages[0].attachments.is_empty());
		assert_eq!(correlation.unclaimed.len(), 1);
		std::fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn two_messages_do_not_claim_the_same_entry() {
		let directory = temp_dir("dup");
		let references = parse_reference("work.zip\n");
		let correlation = correlate(
			vec![message(1 << 4, "work.zip"), message(1 << 4, "work.zip")],
			&references,
			&directory,
			AttachStyle::Flags,
		);
		assert_eq!(correlation.messages[0].attachments.len(), 1);
		assert!(correlation.messages[1].attachments.is_empty());
		std::fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn packets_parse_into_messages_this_module_can_correlate() {
		// Guards the seam between the packet reader and correlation.
		let mut bytes = vec![0_u8; tith_message_legacy::PACKET_HEADER_BYTES];
		let put = |bytes: &mut Vec<u8>, offset: usize, value: u16| {
			bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
		};
		put(&mut bytes, 18, 2);
		put(&mut bytes, 40, 0x0100);
		put(&mut bytes, 44, 0x0001);
		put(&mut bytes, 46, 1);
		put(&mut bytes, 48, 1);
		let mut record = 2_u16.to_le_bytes().to_vec();
		let mut header = vec![0_u8; tith_message_legacy::PACKED_HEADER_BYTES - 2];
		header[8..10].copy_from_slice(&(1_u16 << 4).to_le_bytes());
		header[12..12 + 19].copy_from_slice(b"18 Aug 26  12:00:00");
		record.extend_from_slice(&header);
		record.extend_from_slice(b"To\0From\0work.zip\0Body\0");
		bytes.extend_from_slice(&record);
		bytes.extend_from_slice(&0_u16.to_le_bytes());

		let packet = Packet::parse(&bytes).expect("packet parses");
		let directory = temp_dir("seam");
		let references = parse_reference("^work.zip\n");
		let correlation = correlate(packet.messages, &references, &directory, AttachStyle::Flags);
		assert_eq!(correlation.messages[0].attachments.len(), 1);
		std::fs::remove_dir_all(directory).expect("cleanup");
	}
}
