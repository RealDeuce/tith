//! Attachment names and their post-send disposition.
//!
//! Two legacy conventions express what happens to an attached file after it is
//! sent, and they disagree about granularity as well as syntax.
//!
//! FTS-5005.003 puts a one character directive on each `FileSpec`. It is per
//! file. FSC-0053.002 puts KFS or TFS in a FLAGS control, covering every
//! attachment of the message at once.
//!
//! The same bytes read differently under each: a leading `^` is a directive in
//! one and an ordinary filename character in the other. The convention is
//! therefore selected by the caller and never guessed.

/// Which convention supplies the post-send directive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachStyle {
	/// FTS-5005.003 directives prefixed to each Subject `FileSpec`.
	Binkley,
	/// FSC-0053.002 FLAGS KFS and TFS, applying to every attachment.
	Flags,
}

/// What the sender asked to happen to the file after successful transmission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
	Keep,
	Delete,
	Truncate,
}

impl Disposition {
	/// The TSP-0006 `Source-Disposition` value.
	#[must_use]
	pub fn ipc_value(self) -> &'static str {
		match self {
			Self::Keep => "Keep",
			Self::Delete => "Delete",
			Self::Truncate => "Truncate",
		}
	}

	/// The TSP-0004 feature a service must advertise to honour this, if any.
	#[must_use]
	pub fn required_feature(self) -> Option<&'static str> {
		match self {
			Self::Keep => None,
			Self::Delete => Some("Submit.Delete"),
			Self::Truncate => Some("Submit.Truncate"),
		}
	}
}

/// One attached file and what to do with it afterwards.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attachment {
	pub name: String,
	pub disposition: Disposition,
}

/// Splits an FTS-0001.016 `FileList`.
///
/// Separators are a comma or one or more spaces, and a `FileSpec` contains no
/// NUL, comma, or space. Empty entries, including those from adjacent commas,
/// are dropped rather than becoming empty filenames.
#[must_use]
pub fn file_list(subject: &str) -> Vec<&str> {
	subject
		.split([',', ' '])
		.filter(|spec| !spec.is_empty())
		.collect()
}

/// Applies FTS-5005.003 directives, returning `None` for a skipped file.
///
/// The documented directives are `#` truncate and `^` delete, with `~` marking
/// an already processed entry. Software may also recognise `-` for `^`, `!`
/// for `~`, and `@` for send without truncating or deleting.
fn binkley_directive(spec: &str) -> Option<Attachment> {
	let (disposition, name) = match spec.as_bytes().first() {
		Some(b'#') => (Disposition::Truncate, &spec[1..]),
		Some(b'^' | b'-') => (Disposition::Delete, &spec[1..]),
		Some(b'~' | b'!') => return None,
		Some(b'@') => (Disposition::Keep, &spec[1..]),
		_ => (Disposition::Keep, spec),
	};
	(!name.is_empty()).then(|| Attachment {
		name: name.to_owned(),
		disposition,
	})
}

/// Why a message's attachments could not be resolved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachError {
	/// FLAGS carried both KFS and TFS. TSP-0003 requires that an export never
	/// emit both, so an input carrying both has no defined meaning and is not
	/// resolved to either.
	ConflictingFlags,
}

impl std::fmt::Display for AttachError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::ConflictingFlags => {
				f.write_str("FLAGS carries both KFS and TFS, which have no combined meaning")
			}
		}
	}
}

impl std::error::Error for AttachError {}

/// Resolves the attachment list and each file's disposition.
///
/// `flags` is the whitespace separated FLAGS control payload, used only by
/// [`AttachStyle::Flags`].
pub fn attachments(
	subject: &str,
	flags: &[String],
	style: AttachStyle,
) -> Result<Vec<Attachment>, AttachError> {
	let specs = file_list(subject);
	match style {
		AttachStyle::Binkley => Ok(specs.into_iter().filter_map(binkley_directive).collect()),
		AttachStyle::Flags => {
			let kill = flags.iter().any(|flag| flag == "KFS");
			let truncate = flags.iter().any(|flag| flag == "TFS");
			let disposition = match (kill, truncate) {
				(true, true) => return Err(AttachError::ConflictingFlags),
				(true, false) => Disposition::Delete,
				(false, true) => Disposition::Truncate,
				(false, false) => Disposition::Keep,
			};
			Ok(specs
				.into_iter()
				.map(|name| Attachment {
					name: name.to_owned(),
					disposition,
				})
				.collect())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn names(list: &[Attachment]) -> Vec<&str> {
		list.iter().map(|item| item.name.as_str()).collect()
	}

	#[test]
	fn splits_a_file_list_on_either_separator() {
		assert_eq!(file_list("a.zip b.zip"), ["a.zip", "b.zip"]);
		assert_eq!(file_list("a.zip,b.zip"), ["a.zip", "b.zip"]);
		assert_eq!(file_list("a.zip,   b.zip"), ["a.zip", "b.zip"]);
		assert_eq!(file_list("a.zip,,b.zip"), ["a.zip", "b.zip"]);
		assert!(file_list("").is_empty());
	}

	#[test]
	fn binkley_reads_a_directive_from_each_filespec() {
		let list = attachments(
			"#a.zip ^b.zip -c.zip @d.zip e.zip",
			&[],
			AttachStyle::Binkley,
		)
		.unwrap();
		assert_eq!(names(&list), ["a.zip", "b.zip", "c.zip", "d.zip", "e.zip"]);
		let dispositions: Vec<_> = list.iter().map(|item| item.disposition).collect();
		assert_eq!(
			dispositions,
			[
				Disposition::Truncate,
				Disposition::Delete,
				Disposition::Delete,
				Disposition::Keep,
				Disposition::Keep
			]
		);
	}

	#[test]
	fn binkley_skips_an_already_processed_entry() {
		let list = attachments("~a.zip !b.zip c.zip", &[], AttachStyle::Binkley).unwrap();
		assert_eq!(names(&list), ["c.zip"]);
	}

	#[test]
	fn flags_apply_one_disposition_to_every_attachment() {
		let flags = vec!["FIL".to_owned(), "KFS".to_owned()];
		let list = attachments("a.zip b.zip", &flags, AttachStyle::Flags).unwrap();
		assert_eq!(names(&list), ["a.zip", "b.zip"]);
		assert!(
			list.iter()
				.all(|item| item.disposition == Disposition::Delete)
		);

		let flags = vec!["TFS".to_owned()];
		let list = attachments("a.zip", &flags, AttachStyle::Flags).unwrap();
		assert_eq!(list[0].disposition, Disposition::Truncate);

		let list = attachments("a.zip", &[], AttachStyle::Flags).unwrap();
		assert_eq!(list[0].disposition, Disposition::Keep);
	}

	#[test]
	fn the_same_subject_yields_different_filenames_under_each_style() {
		// This is the whole reason the convention cannot be auto-detected.
		let subject = "^a.zip #b.zip";
		let binkley = attachments(subject, &[], AttachStyle::Binkley).unwrap();
		let flags = attachments(subject, &[], AttachStyle::Flags).unwrap();
		assert_eq!(names(&binkley), ["a.zip", "b.zip"]);
		assert_eq!(names(&flags), ["^a.zip", "#b.zip"]);
	}

	#[test]
	fn conflicting_flags_are_refused_rather_than_resolved() {
		let flags = vec!["KFS".to_owned(), "TFS".to_owned()];
		assert_eq!(
			attachments("a.zip", &flags, AttachStyle::Flags),
			Err(AttachError::ConflictingFlags)
		);
		// Binkley mode never consults FLAGS, so the same input is fine there.
		assert!(attachments("a.zip", &flags, AttachStyle::Binkley).is_ok());
	}

	#[test]
	fn a_bare_directive_character_is_not_an_attachment() {
		assert!(
			attachments("^", &[], AttachStyle::Binkley)
				.unwrap()
				.is_empty()
		);
	}

	#[test]
	fn dispositions_name_their_required_feature() {
		assert_eq!(Disposition::Keep.required_feature(), None);
		assert_eq!(
			Disposition::Delete.required_feature(),
			Some("Submit.Delete")
		);
		assert_eq!(
			Disposition::Truncate.required_feature(),
			Some("Submit.Truncate")
		);
	}
}
