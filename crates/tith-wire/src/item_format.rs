//! Carrier-independent TSP-0016 item data and value rules.

use crate::Identity;
use crate::address::Address;
use crate::tlv::OwnedTlv;

/// An Area value and its optional descriptive metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AreaData {
	pub name: String,
	pub description: Option<String>,
}

/// A File embedded in a Message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentData {
	pub filename: Option<String>,
	pub timestamp: Option<u64>,
	pub contents: Vec<u8>,
	pub short_description: Option<String>,
	pub long_description_lines: Vec<String>,
	pub tear_line: Option<String>,
	pub magic_word: Option<String>,
	pub replaces: Option<String>,
}

/// Semantic Message data, excluding the item authentication and mutable route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageData {
	pub destination: Option<Identity>,
	pub timestamp: u64,
	pub to_user: String,
	pub from_user: String,
	pub subject: String,
	pub text: String,
	pub area: Option<AreaData>,
	pub attachments: Vec<AttachmentData>,
	pub legacy_attributes: Option<u64>,
	pub timestamp_offset: Option<i64>,
	pub tear_line: Option<String>,
	pub origin_line: Option<String>,
	pub message_id: Option<String>,
	pub reply_to: Option<(Address, String)>,
	pub original_character_set: Option<String>,
	pub additional_kludge_lines: Vec<String>,
}

/// Semantic standalone File data, excluding authentication and mutable route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandaloneFileData {
	pub filename: Option<String>,
	pub timestamp: Option<u64>,
	pub contents: Vec<u8>,
	/// The distribution area, or `None` for a peer-addressed File.
	pub area: Option<AreaData>,
	pub short_description: Option<String>,
	pub long_description_lines: Vec<String>,
	pub tear_line: Option<String>,
	pub magic_word: Option<String>,
	pub replaces: Option<String>,
}

/// The canonical kind component of a validated signed-item identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignedItemKind {
	Message,
	File,
}

/// The child-sequence grammar represented by an [`ItemModel`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemModelKind {
	Message,
	StandaloneFile,
	FileRequest,
}

/// An ordered, lossless carrier-independent item representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemModel {
	pub(crate) kind: ItemModelKind,
	pub(crate) children: Vec<OwnedTlv>,
}

impl ItemModel {
	#[must_use]
	pub const fn kind(&self) -> ItemModelKind {
		self.kind
	}

	#[must_use]
	pub fn children(&self) -> &[OwnedTlv] {
		&self.children
	}

	/// Encodes the exact item Value without assigning an outer carrier Type.
	#[must_use]
	pub fn encode_value(&self) -> Vec<u8> {
		let mut output = Vec::new();
		for child in &self.children {
			child
				.write_to(&mut output)
				.expect("already parsed children remain representable");
		}
		output
	}
}

/// Whether a producer should use this Filename under TSP-0016 section 4.
#[must_use]
pub fn filename_is_portable(value: &str) -> bool {
	!value.chars().any(|character| {
		matches!(
			character,
			'\u{0000}'
				..='\u{001f}' | '\u{007f}' | '"' | '*' | '/' | ':' | '<' | '>' | '?' | '\\' | '|'
		)
	})
}

/// Whether a Filename contains an additional path component.
#[must_use]
pub fn filename_has_path_component(value: &str) -> bool {
	value.contains(['/', '\\'])
}

/// Matches one TSP-0016 `Replaces` pattern against a complete Filename.
#[must_use]
pub fn replaces_matches(pattern: &str, filename: &str) -> bool {
	let pattern: Vec<char> = pattern.chars().collect();
	let filename: Vec<char> = filename.chars().collect();
	let (mut pattern_index, mut filename_index) = (0, 0);
	let (mut star, mut retry) = (None, 0);

	while filename_index < filename.len() {
		if pattern_index < pattern.len()
			&& (pattern[pattern_index] == '?' || pattern[pattern_index] == filename[filename_index])
		{
			pattern_index += 1;
			filename_index += 1;
		} else if pattern_index < pattern.len() && pattern[pattern_index] == '*' {
			star = Some(pattern_index);
			pattern_index += 1;
			retry = filename_index;
		} else if let Some(star_index) = star {
			pattern_index = star_index + 1;
			retry += 1;
			filename_index = retry;
		} else {
			return false;
		}
	}
	while pattern_index < pattern.len() && pattern[pattern_index] == '*' {
		pattern_index += 1;
	}
	pattern_index == pattern.len()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn filename_portability_has_the_exact_recommended_set() {
		assert!(filename_is_portable("readme.txt"));
		for character in (0..=0x1f)
			.chain([0x7f, 0x22, 0x2a, 0x2f, 0x3a, 0x3c, 0x3e, 0x3f, 0x5c, 0x7c])
			.map(|value| char::from_u32(value).expect("listed scalar"))
		{
			assert!(!filename_is_portable(&format!("a{character}b")));
		}
		assert!(filename_is_portable("a=b"));
		assert!(filename_has_path_component("dir/file"));
		assert!(filename_has_path_component("dir\\file"));
		assert!(!filename_has_path_component("file"));
	}

	#[test]
	fn replaces_is_a_case_sensitive_whole_filename_unicode_glob() {
		for (pattern, filename) in [
			("", ""),
			("*", ""),
			("*", "anything"),
			("**", "anything"),
			("a?c", "a😀c"),
			("é*.txt", "écho.txt"),
			("file.*", "file.txt"),
		] {
			assert!(
				replaces_matches(pattern, filename),
				"{pattern:?} {filename:?}"
			);
		}
		for (pattern, filename) in [
			("", "x"),
			("?", ""),
			("?", "ab"),
			("a", "ba"),
			("a", "ab"),
			("*.TXT", "file.txt"),
			("é", "e\u{301}"),
		] {
			assert!(
				!replaces_matches(pattern, filename),
				"{pattern:?} {filename:?}"
			);
		}
	}
}
