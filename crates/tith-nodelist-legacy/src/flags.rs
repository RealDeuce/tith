//! Flag classification into the five TTS-5000 flag fields.
//!
//! TTS-5000 section 5.2 fields 7 through 11 define which flags belong in each
//! field, mostly by delegating to FTS-5001.006 sections. Every table below
//! names the section it comes from so a reviewer can check it against the
//! standard rather than against this port's ancestor, `poc/nodelist.c`.

/// The field a flag is written to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Field {
	/// TTS-5000 field 7.
	System,
	/// TTS-5000 field 8.
	PstnIsdn,
	/// TTS-5000 field 9.
	Internet,
	/// TTS-5000 field 10.
	Email,
	/// TTS-5000 field 11.
	Other,
}

// TTS-5000 field 7. It names the contents explicitly rather than by reference:
// the operating condition flags other than MO, the ICM flag which section 5.9.3
// defines but TTS-5000 field 9 excludes, the file and update request flags, and
// the `#nn`, `!nn`, and `Tyz` shapes matched further below.

/// FTS-5001.006 section 5.1, less MO which TTS-5000 field 11 carries.
const OPERATING_CONDITION: &[&str] = &["CM", "LO", "MN"];

/// FTS-5001.006 section 5.9.3, placed in field 7 by TTS-5000 field 9.
const INTERNET_CONDITION: &[&str] = &["ICM"];

/// FTS-5001.006 section 5.4.
const FILE_REQUEST: &[&str] = &["XA", "XB", "XC", "XP", "XR", "XW", "XX"];

// TTS-5000 field 8 cites FTS-5001.006 sections 5.2, 5.3, and 5.8.

/// FTS-5001.006 section 5.2.
const MODEM_PROTOCOL: &[&str] = &[
	"V22", "V29", "V32", "V32b", "V34", "V90C", "V90S", "V32T", "VFC", "HST", "H14", "H16", "X2C",
	"X2S", "ZYX", "Z19", "H96", "PEP", "CSP",
];

/// FTS-5001.006 section 5.3.
const ERROR_CORRECTION: &[&str] = &["MNP", "V42", "V42b"];

/// FTS-5001.006 section 5.8.
const ISDN_CAPABILITY: &[&str] = &["V110L", "V110H", "V120L", "V120H", "X75", "ISDN"];

/// Spellings FTS-5001.006 does not print but which occur widely in deployed
/// nodelists; `poc/nodelist.c` accepts them too. Tolerating a known input
/// spelling is appropriate at a conversion boundary. These are accepted as
/// input only and are never emitted in place of the standard spelling.
const MODEM_DEPLOYED_VARIANTS: &[&str] = &["V22B", "V32B", "V42B"];

// TTS-5000 field 9 cites FTS-5001.006 sections 5.9.1, 5.9.2, and 5.9.3 less
// ICM, and adds the TITH IIH flag.

/// FTS-5001.006 section 5.9.1. Each takes an optional colon argument.
const INTERNET_PROTOCOL: &[&str] = &["IBN", "IFC", "IFT", "ITN", "IVM", "IP"];

/// FTS-5001.006 section 5.9.2. Takes a colon argument.
const SERVER_ADDRESS: &[&str] = &["INA"];

/// TTS-5000 field 9. Takes a colon argument.
const TITH_SERVICE: &[&str] = &["IIH"];

/// FTS-5001.006 section 5.9.3, less ICM. Takes no argument.
const INTERNET_INFORMATION: &[&str] = &["INO4"];

// TTS-5000 field 10 cites FTS-5001.006 sections 5.9.4 and 5.9.5.

/// FTS-5001.006 section 5.9.4. Each takes an optional colon argument.
const EMAIL_PROTOCOL: &[&str] = &["ITX", "IUC", "IMI", "ISE", "EVY", "EMA"];

/// FTS-5001.006 section 5.9.5. Takes an optional colon argument.
const EMAIL_ADDRESS: &[&str] = &["IEM"];

// TTS-5000 field 11 names MO, GUUCP, and PING plus the section 6.2 mail
// oriented user flags. Anything unrecognised lands here too, so these tables
// exist only to tell "known" from "unknown" for diagnostics.

/// FTS-5001.006 section 5.1 MO, section 5.5 GUUCP, and section 5.10 robot flags.
const OTHER_KNOWN: &[&str] = &["MO", "GUUCP", "PING", "TRACE"];

/// FTS-5001.006 section 6.2.
const MAIL_ORIENTED_USER: &[&str] = &[
	"ZEC", "REC", "NEC", "NC", "SDS", "SMH", "RPK", "NPK", "ENC", "CDP",
];

/// True when `flag` is `name` alone or `name` followed by a colon argument.
fn matches_prefix(flag: &str, name: &str) -> bool {
	flag.strip_prefix(name)
		.is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
}

/// FTS-5001.006 section 5.6: `#nn` or `!nn`, and section 5.6 also permits them
/// to be strung together with no intervening comma, such as `#02#09`.
fn is_mail_period(flag: &str) -> bool {
	let bytes = flag.as_bytes();
	if bytes.is_empty() || !bytes.len().is_multiple_of(3) {
		return false;
	}
	bytes.chunks(3).all(|chunk| {
		matches!(chunk[0], b'#' | b'!') && chunk[1].is_ascii_digit() && chunk[2].is_ascii_digit()
	})
}

/// FTS-5001.006 section 5.7: `Tyz`, where each of `y` and `z` is one of the
/// half-hour letters `A` through `X` or `a` through `x`.
fn is_online_period(flag: &str) -> bool {
	let bytes = flag.as_bytes();
	bytes.len() == 3
		&& bytes[0] == b'T'
		&& bytes[1..]
			.iter()
			.all(|byte| byte.is_ascii_alphabetic() && byte.to_ascii_uppercase() <= b'X')
}

/// Classifies one flag, or returns `None` when no table or shape rule matches.
///
/// An unmatched flag still belongs in TTS-5000 field 11, which catches "any
/// flag not carried in another flags field"; returning `None` lets the caller
/// report it as unrecognised before writing it there.
#[must_use]
pub fn classify(flag: &str) -> Option<Field> {
	let exact = |tables: &[&[&str]]| tables.iter().any(|table| table.contains(&flag));
	let prefix = |tables: &[&[&str]]| {
		tables
			.iter()
			.flat_map(|table| table.iter())
			.any(|name| matches_prefix(flag, name))
	};

	if exact(&[OPERATING_CONDITION, INTERNET_CONDITION, FILE_REQUEST])
		|| is_mail_period(flag)
		|| is_online_period(flag)
	{
		return Some(Field::System);
	}
	if exact(&[
		MODEM_PROTOCOL,
		ERROR_CORRECTION,
		ISDN_CAPABILITY,
		MODEM_DEPLOYED_VARIANTS,
	]) {
		return Some(Field::PstnIsdn);
	}
	if exact(&[INTERNET_INFORMATION]) || prefix(&[INTERNET_PROTOCOL, SERVER_ADDRESS, TITH_SERVICE])
	{
		return Some(Field::Internet);
	}
	if prefix(&[EMAIL_PROTOCOL, EMAIL_ADDRESS]) {
		return Some(Field::Email);
	}
	if exact(&[OTHER_KNOWN, MAIL_ORIENTED_USER]) {
		return Some(Field::Other);
	}
	None
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn classifies_each_field_from_its_standard_section() {
		for (flag, field) in [
			("CM", Field::System),
			("ICM", Field::System),
			("XX", Field::System),
			("#02", Field::System),
			("!17", Field::System),
			("#02#09", Field::System),
			("TuB", Field::System),
			("V32b", Field::PstnIsdn),
			("V42B", Field::PstnIsdn),
			("X75", Field::PstnIsdn),
			("ISDN", Field::PstnIsdn),
			("INO4", Field::Internet),
			("IBN", Field::Internet),
			("IBN:example.org", Field::Internet),
			("IBN:example.org:24554", Field::Internet),
			("INA:example.org", Field::Internet),
			("IIH:[2001:db8::1]:24555:abc", Field::Internet),
			("IEM:sysop@example.org", Field::Email),
			("ITX", Field::Email),
			("MO", Field::Other),
			("GUUCP", Field::Other),
			("PING", Field::Other),
			("NEC", Field::Other),
		] {
			assert_eq!(classify(flag), Some(field), "flag {flag}");
		}
	}

	#[test]
	fn reports_unrecognised_flags() {
		// "TAB" is deliberately absent: it is a valid Tyz flag for 00:00 to 01:00.
		for flag in ["WIDGET", "IBNX", "T", "TYZ", "#0", "#0a", "V32c"] {
			assert_eq!(classify(flag), None, "flag {flag}");
		}
	}

	#[test]
	fn does_not_confuse_a_prefix_with_a_longer_name() {
		// IP is a section 5.9.1 flag; IPv6ish names must not match it.
		assert_eq!(classify("IP"), Some(Field::Internet));
		assert_eq!(classify("IP:10.0.0.1"), Some(Field::Internet));
		assert_eq!(classify("IPX"), None);
	}
}
