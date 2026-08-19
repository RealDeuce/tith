//! Bundle header framing shared by both ends of a mail exchange.
//!
//! A Bundle arrives as an Origin value, an optional `PublicKey`, and then the
//! Header `SignedTLV`, with payload values following one at a time. Both the
//! listener and the outbound driver have to read exactly that much before they
//! know who they are talking to, so the reader lives here rather than being
//! written twice with two chances to diverge.

use std::error::Error;
use std::io::Read;

use tith_crypto::{TlvHash, hash_tlv};
use tith_wire::bundle::{Bundle, KeyResolver};
use tith_wire::tlv::{OwnedTlv, TlvReader};
use tith_wire::types;

pub struct IncomingBundle {
	pub bundle: Bundle,
	pub header_hash: TlvHash,
	/// The encoded Origin, optional `PublicKey`, and Header `SignedTLV`.
	///
	/// A payload can only be verified as part of a Bundle, and the reply
	/// payloads arrive one at a time, so the reader keeps the prefix to parse
	/// each arriving payload as a Bundle of its own.
	pub prefix: Vec<u8>,
}

/// Reads a Bundle prefix up to and including its Header `SignedTLV`.
///
/// `first` supplies a top-level value the caller has already read, which is how
/// the listener recognises that a final Reply Bundle has begun. Returns `Ok(None)`
/// only when the connection ends before anything at all is read.
///
/// # Errors
///
/// Returns an error when the stream does not begin with Origin, when it ends
/// before the Header `SignedTLV`, or when the Bundle does not parse and verify.
pub fn read_header<R: Read>(
	reader: &mut TlvReader<R>,
	first: Option<OwnedTlv>,
	resolver: &impl KeyResolver,
) -> Result<Option<IncomingBundle>, Box<dyn Error>> {
	let first = if let Some(value) = first {
		value
	} else {
		let Some(value) = reader.read_next()? else {
			return Ok(None);
		};
		value.read_owned()?
	};
	if first.type_code != types::ORIGIN {
		return Err("Bundle does not begin with Origin".into());
	}
	let mut prefix = first.encode();
	loop {
		let value = reader
			.read_next()?
			.ok_or("connection ended before the Header SignedTLV")?
			.read_owned()?;
		prefix.extend_from_slice(&value.encode());
		if value.type_code == types::SIGNED_TLV {
			let bundle = Bundle::parse(&prefix, resolver)?;
			let header_hash = hash_tlv(&bundle.header.encoded)?;
			return Ok(Some(IncomingBundle {
				bundle,
				header_hash,
				prefix,
			}));
		}
	}
}
