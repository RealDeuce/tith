//! Files only their owner may read: the node signing key and the IPC key.
//!
//! POSIX spells that as mode 0600 and a check that no group or other bit is
//! set. Windows has no mode. Its equivalent is a protected DACL granting full
//! access only to `LocalSystem` and the object owner — the same descriptor the
//! named-pipe binding already builds for the service pipe — and a check that
//! the stored descriptor still says exactly that.
//!
//! Neither platform is served by skipping the other's mechanism, so each gets
//! its own rather than a key written with whatever the host happened to
//! inherit.

use std::io;
use std::path::Path;

/// Creates `path` reachable only by its owner and writes `bytes` durably.
///
/// The create fails when the file already exists, so a key is never replaced by
/// accident.
pub fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
	use io::Write as _;
	let mut file = platform::create(path)?;
	file.write_all(bytes)?;
	file.sync_all()?;
	Ok(())
}

/// Reads `path` once the host confirms nobody but its owner can reach it.
pub fn read(path: &Path) -> io::Result<Vec<u8>> {
	platform::check(path)?;
	std::fs::read(path)
}

#[cfg(unix)]
mod platform {
	use std::fs::{File, OpenOptions};
	use std::io;
	use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
	use std::path::Path;

	pub fn create(path: &Path) -> io::Result<File> {
		OpenOptions::new()
			.create_new(true)
			.write(true)
			.mode(0o600)
			.open(path)
	}

	pub fn check(path: &Path) -> io::Result<()> {
		// Every group and other bit clear, which is what mode 0600 leaves.
		if std::fs::metadata(path)?
			.permissions()
			.mode()
			.trailing_zeros()
			>= 6
		{
			return Ok(());
		}
		Err(io::Error::new(
			io::ErrorKind::PermissionDenied,
			format!(
				"{} is accessible by group or other users; it needs mode 0600",
				path.display()
			),
		))
	}
}

#[cfg(windows)]
mod platform {
	pub use crate::windows::{create_owner_only as create, owner_only_dacl as check};
}

/// Whether an SDDL DACL is protected and reaches nobody but `LocalSystem` and
/// the object owner.
///
/// This lives here rather than beside the Win32 calls that produce its input so
/// that it is ordinary safe Rust with tests which run on every host. Only the
/// two FFI calls that fetch the descriptor are Windows-only, and those are as
/// small as the API allows.
///
/// Rights are deliberately not compared. Windows may spell `FILE_ALL_ACCESS` as
/// "FA" or as its hexadecimal value, and which one it picks says nothing about
/// who can reach the key. The trustees do.
#[cfg(any(windows, test))]
pub(crate) fn permits_only_owner(sddl: &str) -> bool {
	// "SY" is LocalSystem and "OW" is OWNER RIGHTS, which Windows evaluates as
	// whoever currently owns the object. Either may appear as a raw SID.
	const ALLOWED: [&str; 4] = ["SY", "OW", "S-1-5-18", "S-1-3-4"];
	let Some(dacl) = sddl.strip_prefix("D:") else {
		return false;
	};
	let (flags, aces) = match dacl.find('(') {
		Some(position) => dacl.split_at(position),
		None => (dacl, ""),
	};
	// "P" is protected, so nothing is inherited from the containing directory.
	// "AI" would mean inherited entries are present after all.
	if !flags.contains('P') || flags.contains("AI") {
		return false;
	}
	let mut remaining = aces;
	let mut seen = 0;
	while let Some(rest) = remaining.strip_prefix('(') {
		let Some(end) = rest.find(')') else {
			return false;
		};
		let fields: Vec<&str> = rest[..end].split(';').collect();
		// type;flags;rights;object;inherited-object;trustee
		let [kind, ace_flags, _rights, _object, _inherited, trustee] = fields.as_slice() else {
			return false;
		};
		if *kind != "A" || !ace_flags.is_empty() || !ALLOWED.contains(trustee) {
			return false;
		}
		seen += 1;
		remaining = &rest[end + 1..];
	}
	remaining.is_empty() && seen > 0
}

#[cfg(test)]
mod tests {
	use super::permits_only_owner;

	#[test]
	fn accepts_only_a_protected_owner_and_system_dacl() {
		// What `create` writes, in both spellings Windows may return.
		assert!(permits_only_owner("D:P(A;;FA;;;SY)(A;;FA;;;OW)"));
		assert!(permits_only_owner("D:P(A;;0x1f01ff;;;SY)(A;;FA;;;OW)"));
		assert!(permits_only_owner("D:P(A;;FA;;;S-1-5-18)(A;;FA;;;S-1-3-4)"));
		assert!(permits_only_owner("D:P(A;;FA;;;OW)"));

		// Any other trustee can reach the key, whoever it is.
		assert!(!permits_only_owner("D:P(A;;FA;;;SY)(A;;FA;;;WD)"));
		assert!(!permits_only_owner("D:P(A;;FA;;;BA)"));
		assert!(!permits_only_owner("D:P(A;;FR;;;S-1-5-21-1-2-3-1001)"));
		// An unprotected DACL inherits whatever the directory grants.
		assert!(!permits_only_owner("D:(A;;FA;;;OW)"));
		assert!(!permits_only_owner("D:AI(A;;FA;;;OW)"));
		// A deny entry is not an allow entry, and neither is a malformed one.
		assert!(!permits_only_owner("D:P(D;;FA;;;WD)(A;;FA;;;OW)"));
		assert!(!permits_only_owner("D:P(A;OICI;FA;;;OW)"));
		assert!(!permits_only_owner("D:P(A;;FA;;;OW"));
		assert!(!permits_only_owner("D:P(A;;FA;OW)"));
		assert!(!permits_only_owner("D:P(A;;FA;;;OW)junk"));
		// No entries at all is not owner-only; it is unreadable or inherited.
		assert!(!permits_only_owner("D:P"));
		assert!(!permits_only_owner(""));
		assert!(!permits_only_owner("O:BAG:BAD:P(A;;FA;;;OW)"));
	}
}
