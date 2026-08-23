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
			let bundle = Bundle::parse_header_prefix(&prefix, resolver)?;
			let header_hash = hash_tlv(&bundle.header.encoded)?;
			return Ok(Some(IncomingBundle {
				bundle,
				header_hash,
				prefix,
			}));
		}
	}
}

#[cfg(test)]
mod tests {
	use std::io::Cursor;

	use tith_crypto::SigningKeyPair;
	use tith_wire::address::Address;
	use tith_wire::bundle::{Identity, build_bundle};

	use super::*;

	fn fixture() -> (Vec<u8>, Identity, Identity) {
		let origin_keys = SigningKeyPair::from_seed(&[71; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[72; 32]).unwrap();
		let origin = Identity {
			address: "fidonet#1/71".parse().unwrap(),
			public_key: origin_keys.public,
		};
		let destination = Identity {
			address: "fidonet#1/72".parse().unwrap(),
			public_key: destination_keys.public,
		};
		(
			build_bundle(&origin, &origin_keys.secret, &destination, 1, Vec::new()).unwrap(),
			origin,
			destination,
		)
	}

	#[test]
	fn reads_a_header_from_the_stream_or_a_supplied_origin() {
		let (encoded, origin, destination) = fixture();
		let resolver = |address: &Address| {
			(address == &origin.address)
				.then_some(origin.public_key)
				.or_else(|| (address == &destination.address).then_some(destination.public_key))
		};
		let mut reader = TlvReader::new(Cursor::new(encoded.clone()));
		let incoming = read_header(&mut reader, None, &resolver).unwrap().unwrap();
		assert_eq!(incoming.bundle.origin, origin);
		assert_eq!(incoming.bundle.destination, destination);

		let mut split = TlvReader::new(Cursor::new(encoded));
		let first = split.read_next().unwrap().unwrap().read_owned().unwrap();
		let incoming = read_header(&mut split, Some(first), &resolver)
			.unwrap()
			.unwrap();
		assert_eq!(incoming.bundle.origin, origin);
	}

	#[test]
	fn distinguishes_clean_eof_from_each_incomplete_prefix() {
		let (_, origin, _) = fixture();
		let resolver =
			|address: &Address| (address == &origin.address).then_some(origin.public_key);
		let mut empty = TlvReader::new(Cursor::new(Vec::new()));
		assert!(read_header(&mut empty, None, &resolver).unwrap().is_none());

		let wrong = OwnedTlv::new(types::TIMESTAMP, vec![1]).unwrap();
		let mut no_more = TlvReader::new(Cursor::new(Vec::new()));
		assert!(read_header(&mut no_more, Some(wrong), &resolver).is_err());

		let origin_value =
			OwnedTlv::new(types::ORIGIN, origin.address.to_string().into_bytes()).unwrap();
		let mut no_header = TlvReader::new(Cursor::new(Vec::new()));
		assert!(read_header(&mut no_header, Some(origin_value), &resolver).is_err());
	}
}
