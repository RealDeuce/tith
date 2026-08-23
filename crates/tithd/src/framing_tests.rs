use std::io::Cursor;

use tith_crypto::SigningKeyPair;
use tith_wire::address::Address;
use tith_wire::bundle::{Identity, build_bundle};
use tith_wire::tlv::{OwnedTlv, TlvReader, parse_sequence};
use tith_wire::types;

use crate::framing::read_header;

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

	let mut values = parse_sequence(&encoded).unwrap();
	let header = values.pop().unwrap();
	values.push(OwnedTlv::new(31, b"extension".to_vec()).unwrap());
	values.push(header);
	let mut extended = Vec::new();
	for value in values {
		value.write_to(&mut extended).unwrap();
	}
	let mut split = TlvReader::new(Cursor::new(extended));
	let first = split.read_next().unwrap().unwrap().read_owned().unwrap();
	let incoming = read_header(&mut split, Some(first), &resolver)
		.unwrap()
		.unwrap();
	assert_eq!(incoming.bundle.origin, origin);
}

#[test]
fn distinguishes_clean_eof_from_each_invalid_prefix() {
	let (_, origin, _) = fixture();
	let resolver = |address: &Address| (address == &origin.address).then_some(origin.public_key);
	let mut empty = TlvReader::new(Cursor::new(Vec::new()));
	assert!(read_header(&mut empty, None, &resolver).unwrap().is_none());

	let wrong = OwnedTlv::new(types::TIMESTAMP, vec![1]).unwrap();
	let mut no_more = TlvReader::new(Cursor::new(Vec::new()));
	assert!(read_header(&mut no_more, Some(wrong), &resolver).is_err());

	let origin_value =
		OwnedTlv::new(types::ORIGIN, origin.address.to_string().into_bytes()).unwrap();
	let mut no_header = TlvReader::new(Cursor::new(Vec::new()));
	assert!(read_header(&mut no_header, Some(origin_value.clone()), &resolver).is_err());

	let mut truncated_bytes = OwnedTlv::new(types::SIGNED_TLV, vec![1]).unwrap().encode();
	truncated_bytes.pop();
	let mut truncated = TlvReader::new(Cursor::new(truncated_bytes));
	assert!(read_header(&mut truncated, Some(origin_value), &resolver).is_err());
}
