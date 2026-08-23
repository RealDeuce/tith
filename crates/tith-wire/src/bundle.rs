//! TTS-0005 bundles built from the TTS-0003 common values.

use tith_crypto::{PublicKey, SecretKey, TlvHash, hash_tlv};

use crate::address::Address;
pub use crate::common::{
	KeyResolver, VerifiedSignedTlv, build_signed_tlv, unauthenticated_signed_data,
	verify_signed_tlv,
};
use crate::common::{address_value, concatenate, identity, public_key_value};
pub use crate::error::BundleError;
pub use crate::identity::Identity;
use crate::integer::{decode_u64, encode_u64};
use crate::tlv::{OwnedTlv, parse_sequence};
use crate::types;

fn assigned(type_code: u64, value: Vec<u8>) -> OwnedTlv {
	OwnedTlv::new(type_code, value).expect("assigned TITH type is nonzero")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bundle {
	pub encoded: Vec<u8>,
	pub origin: Identity,
	/// A non-anonymous outer Origin key carried only by a `PublicKeyRequest` reply.
	pub advertised_origin_key: Option<PublicKey>,
	pub destination: Identity,
	/// A non-anonymous Header Destination predecessor key requested by a key probe.
	pub requested_destination_key: Option<PublicKey>,
	pub timestamp: u64,
	pub header: VerifiedSignedTlv,
	pub payloads: Vec<VerifiedSignedTlv>,
	pub unknown_top_level: Vec<OwnedTlv>,
}

impl Bundle {
	pub fn parse(encoded: &[u8], resolver: &dyn KeyResolver) -> Result<Self, BundleError> {
		Self::parse_internal(encoded, resolver, NonAnonymousOriginKey::Prohibited, false)
	}

	/// Parses only the Origin and Header prefix while deferring rules which
	/// depend on seeing the payload.
	pub fn parse_header_prefix(
		encoded: &[u8],
		resolver: &dyn KeyResolver,
	) -> Result<Self, BundleError> {
		Self::parse_internal(encoded, resolver, NonAnonymousOriginKey::Prohibited, true)
	}

	/// Parses a probe reply whose non-anonymous outer Origin carries the key that
	/// authenticated the reply. `expected` pins that key when a predecessor is
	/// already trusted; `None` is the explicit first-contact TOFU case.
	pub fn parse_public_key_reply(
		encoded: &[u8],
		resolver: &dyn KeyResolver,
		expected: Option<PublicKey>,
	) -> Result<Self, BundleError> {
		let mode = expected.map_or(NonAnonymousOriginKey::Any, NonAnonymousOriginKey::Exact);
		let bundle = Self::parse_internal(encoded, resolver, mode, false)?;
		if bundle.advertised_origin_key.is_none()
			|| bundle.payloads.len() != 1
			|| bundle.payloads[0].data.len() != 2
			|| bundle.payloads[0].data[1].type_code != types::ACCEPTED
		{
			return Err(BundleError::Unexpected("PublicKeyRequest reply grammar"));
		}
		let accepted = crate::item::validate_item(&bundle.payloads[0].data[1], resolver)?
			.ok_or(BundleError::Unexpected("PublicKeyRequest Accepted"))?;
		let current = accepted
			.response_public_key
			.ok_or(BundleError::Missing("Accepted current PublicKey"))?;
		if expected.is_none() && bundle.advertised_origin_key != Some(current) {
			return Err(BundleError::InvalidSignature);
		}
		Ok(bundle)
	}

	fn parse_internal(
		encoded: &[u8],
		resolver: &dyn KeyResolver,
		non_anonymous_origin_key: NonAnonymousOriginKey,
		allow_header_only: bool,
	) -> Result<Self, BundleError> {
		let top = parse_sequence(encoded)?;
		let origin_tlv = top.first().ok_or(BundleError::Missing("Origin"))?;
		if origin_tlv.type_code != types::ORIGIN {
			return Err(BundleError::Missing("initial Origin"));
		}
		let origin_address = address_value(origin_tlv)?;
		let mut index = 1;
		let mut advertised_origin_key = None;
		let origin_public_key = if origin_address.is_anonymous() {
			let value = top
				.get(index)
				.ok_or(BundleError::Missing("Origin PublicKey"))?;
			if value.type_code != types::PUBLIC_KEY {
				return Err(BundleError::Missing("Origin PublicKey"));
			}
			index += 1;
			Some(value)
		} else if top
			.get(index)
			.is_some_and(|value| value.type_code == types::PUBLIC_KEY)
		{
			let value = &top[index];
			let key = public_key_value(value)?;
			match non_anonymous_origin_key {
				NonAnonymousOriginKey::Prohibited => {
					return Err(BundleError::Unexpected("non-anonymous Origin PublicKey"));
				}
				NonAnonymousOriginKey::Exact(expected) if key != expected => {
					return Err(BundleError::InvalidSignature);
				}
				NonAnonymousOriginKey::Any | NonAnonymousOriginKey::Exact(_) => {}
			}
			index += 1;
			advertised_origin_key = Some(key);
			Some(value)
		} else {
			None
		};
		let origin = if let Some(key) = advertised_origin_key {
			Identity {
				address: origin_address,
				public_key: key,
			}
		} else {
			identity(origin_tlv, origin_public_key, resolver)?
		};

		let header_tlv = next_defined(&top, &mut index)
			.filter(|value| value.type_code == types::SIGNED_TLV)
			.ok_or(BundleError::Missing("Header SignedTLV"))?;
		let header = verify_signed_tlv(header_tlv, Some(&origin), resolver)?;
		let (destination, requested_destination_key, timestamp) =
			validate_header(&header.data, resolver)?;
		let expected_hash = hash_tlv(&header.encoded)?;

		let mut payloads = Vec::new();
		let mut unknown_top_level = top[1..index - 1]
			.iter()
			.filter(|value| !types::is_defined(value.type_code))
			.cloned()
			.collect::<Vec<_>>();
		for value in &top[index..] {
			if value.type_code == types::SIGNED_TLV {
				let payload = verify_signed_tlv(value, Some(&origin), resolver)?;
				let Some(first) = payload.data.first() else {
					return Err(BundleError::Missing("payload Header TLVHash"));
				};
				if first.type_code != types::TLV_HASH {
					return Err(BundleError::Missing("initial payload Header TLVHash"));
				}
				let actual: [u8; 32] = first
					.value
					.as_slice()
					.try_into()
					.map_err(|_| BundleError::WrongLength("TLVHash"))?;
				if TlvHash::from_bytes(actual) != expected_hash {
					return Err(BundleError::IncorrectHeaderHash);
				}
				payloads.push(payload);
			} else if types::is_defined(value.type_code) {
				return Err(BundleError::Unexpected("defined top-level value"));
			} else {
				unknown_top_level.push(value.clone());
			}
		}
		let dedicated_public_key_request = payloads.len() == 1
			&& payloads[0].data.len() == 2
			&& payloads[0].data[1].type_code == types::PUBLIC_KEY_REQUEST;
		let contains_public_key_request = payloads.iter().any(|payload| {
			payload
				.data
				.iter()
				.any(|value| value.type_code == types::PUBLIC_KEY_REQUEST)
		});
		if (requested_destination_key.is_some() || contains_public_key_request)
			&& !(allow_header_only && payloads.is_empty())
			&& !dedicated_public_key_request
		{
			return Err(BundleError::Unexpected(
				"PublicKeyRequest outside its dedicated Bundle",
			));
		}

		Ok(Self {
			encoded: encoded.to_vec(),
			origin,
			advertised_origin_key,
			destination,
			requested_destination_key,
			timestamp,
			header,
			payloads,
			unknown_top_level,
		})
	}

	/// Returns the request identifier and precise payload hash for a dedicated
	/// key probe, or `None` for an ordinary or incomplete Bundle.
	pub fn public_key_request(&self) -> Result<Option<(u64, TlvHash)>, BundleError> {
		if self.payloads.len() != 1
			|| self.payloads[0].data.len() != 2
			|| self.payloads[0].data[1].type_code != types::PUBLIC_KEY_REQUEST
		{
			return Ok(None);
		}
		let item = crate::item::validate_public_key_request(&self.payloads[0].data[1])?;
		Ok(Some((
			item.request_identifier,
			hash_tlv(&self.payloads[0].encoded)?,
		)))
	}
}

#[derive(Clone, Copy)]
enum NonAnonymousOriginKey {
	Prohibited,
	Any,
	Exact(PublicKey),
}

fn next_defined<'a>(values: &'a [OwnedTlv], index: &mut usize) -> Option<&'a OwnedTlv> {
	while let Some(value) = values.get(*index) {
		*index += 1;
		if types::is_defined(value.type_code) {
			return Some(value);
		}
	}
	None
}

fn validate_header(
	children: &[OwnedTlv],
	resolver: &dyn KeyResolver,
) -> Result<(Identity, Option<PublicKey>, u64), BundleError> {
	let mut index = 0;
	let destination_tlv = next_defined(children, &mut index)
		.filter(|value| value.type_code == types::DESTINATION)
		.ok_or(BundleError::Missing("Destination"))?;
	let destination_address = address_value(destination_tlv)?;
	let mut requested_destination_key = None;
	let destination_key = if destination_address.is_anonymous() {
		let value = children
			.get(index)
			.ok_or(BundleError::Missing("Destination PublicKey"))?;
		if value.type_code != types::PUBLIC_KEY {
			return Err(BundleError::Missing("Destination PublicKey"));
		}
		index += 1;
		Some(value)
	} else if children
		.get(index)
		.is_some_and(|value| value.type_code == types::PUBLIC_KEY)
	{
		let value = &children[index];
		requested_destination_key = Some(public_key_value(value)?);
		index += 1;
		Some(value)
	} else {
		None
	};
	let destination = if let Some(key) = requested_destination_key {
		Identity {
			address: destination_address,
			public_key: key,
		}
	} else {
		identity(destination_tlv, destination_key, resolver)?
	};
	let timestamp = next_defined(children, &mut index)
		.filter(|value| value.type_code == types::TIMESTAMP)
		.ok_or(BundleError::Missing("Timestamp after Destination"))?;
	if next_defined(children, &mut index).is_some() {
		return Err(BundleError::Unexpected("defined Header value"));
	}
	Ok((
		destination,
		requested_destination_key,
		decode_u64(&timestamp.value)?,
	))
}

pub fn build_bundle(
	origin: &Identity,
	origin_secret: &SecretKey,
	destination: &Identity,
	timestamp: u64,
	payload_groups: Vec<Vec<OwnedTlv>>,
) -> Result<Vec<u8>, BundleError> {
	let mut top = vec![assigned(
		types::ORIGIN,
		origin.address.to_string().into_bytes(),
	)];
	if origin.address.is_anonymous() {
		top.push(assigned(
			types::PUBLIC_KEY,
			origin.public_key.as_bytes().to_vec(),
		));
	}
	let mut header_data = vec![assigned(
		types::DESTINATION,
		destination.address.to_string().into_bytes(),
	)];
	if destination.address.is_anonymous() {
		header_data.push(assigned(
			types::PUBLIC_KEY,
			destination.public_key.as_bytes().to_vec(),
		));
	}
	header_data.push(assigned(types::TIMESTAMP, encode_u64(timestamp)));
	let header = build_signed_tlv(&header_data, None, origin_secret)?;
	let header_hash = hash_tlv(&header.encode())?;
	top.push(header);
	for mut payload in payload_groups {
		payload.insert(
			0,
			assigned(types::TLV_HASH, header_hash.as_bytes().to_vec()),
		);
		top.push(build_signed_tlv(&payload, None, origin_secret)?);
	}
	Ok(concatenate(&top))
}

/// Builds the dedicated initial Bundle which asks a server for its current
/// signing key. No operational request may share this Bundle.
pub fn build_public_key_probe(
	origin: &Identity,
	origin_secret: &SecretKey,
	destination: &Address,
	requested_key: Option<PublicKey>,
	timestamp: u64,
	request_identifier: u64,
) -> Result<Vec<u8>, BundleError> {
	if destination.is_anonymous() {
		return Err(BundleError::Unexpected(
			"PublicKeyRequest for an anonymous Destination",
		));
	}
	let mut top = vec![assigned(
		types::ORIGIN,
		origin.address.to_string().into_bytes(),
	)];
	if origin.address.is_anonymous() {
		top.push(assigned(
			types::PUBLIC_KEY,
			origin.public_key.as_bytes().to_vec(),
		));
	}
	let mut header_data = vec![assigned(
		types::DESTINATION,
		destination.to_string().into_bytes(),
	)];
	if let Some(key) = requested_key {
		header_data.push(assigned(types::PUBLIC_KEY, key.as_bytes().to_vec()));
	}
	header_data.push(assigned(types::TIMESTAMP, encode_u64(timestamp)));
	let header = build_signed_tlv(&header_data, None, origin_secret)?;
	let header_hash = hash_tlv(&header.encode())?;
	let payload = [
		assigned(types::TLV_HASH, header_hash.as_bytes().to_vec()),
		crate::item::public_key_request(request_identifier)?,
	];
	top.push(header);
	top.push(build_signed_tlv(&payload, None, origin_secret)?);
	Ok(concatenate(&top))
}

/// Builds the reply to one `PublicKeyRequest`.
///
/// `signing_origin` is the requested predecessor identity and may use a
/// retained secret. Its key is repeated after the non-anonymous outer Origin so the
/// client can select it before authenticating the Header. `current_key` is
/// inside Accepted and is therefore certified by that predecessor signature.
pub fn build_public_key_reply(
	signing_origin: &Identity,
	signing_secret: &SecretKey,
	destination: &Identity,
	timestamp: u64,
	request_identifier: u64,
	response_to: TlvHash,
	current_key: PublicKey,
) -> Result<Vec<u8>, BundleError> {
	let mut top = vec![assigned(
		types::ORIGIN,
		signing_origin.address.to_string().into_bytes(),
	)];
	// A probe reply always states its signing key, including for a non-anonymous Origin.
	top.push(assigned(
		types::PUBLIC_KEY,
		signing_origin.public_key.as_bytes().to_vec(),
	));
	let mut header_data = vec![assigned(
		types::DESTINATION,
		destination.address.to_string().into_bytes(),
	)];
	if destination.address.is_anonymous() {
		header_data.push(assigned(
			types::PUBLIC_KEY,
			destination.public_key.as_bytes().to_vec(),
		));
	}
	header_data.push(assigned(types::TIMESTAMP, encode_u64(timestamp)));
	let header = build_signed_tlv(&header_data, None, signing_secret)?;
	let header_hash = hash_tlv(&header.encode())?;
	let payload = [
		assigned(types::TLV_HASH, header_hash.as_bytes().to_vec()),
		crate::item::accepted_public_key(request_identifier, response_to, current_key)?,
	];
	top.push(header);
	top.push(build_signed_tlv(&payload, None, signing_secret)?);
	Ok(concatenate(&top))
}

/// Builds the required permanent refusal when the requested predecessor
/// private key is unavailable.
///
/// The current key signs and is advertised by this reply. A client which
/// requested another predecessor consequently cannot authenticate it and must
/// leave that request outstanding.
pub fn build_public_key_unavailable_reply(
	current_origin: &Identity,
	current_secret: &SecretKey,
	destination: &Identity,
	timestamp: u64,
	request_identifier: u64,
	response_to: TlvHash,
) -> Result<Vec<u8>, BundleError> {
	let mut top = vec![assigned(
		types::ORIGIN,
		current_origin.address.to_string().into_bytes(),
	)];
	top.push(assigned(
		types::PUBLIC_KEY,
		current_origin.public_key.as_bytes().to_vec(),
	));
	let mut header_data = vec![assigned(
		types::DESTINATION,
		destination.address.to_string().into_bytes(),
	)];
	if destination.address.is_anonymous() {
		header_data.push(assigned(
			types::PUBLIC_KEY,
			destination.public_key.as_bytes().to_vec(),
		));
	}
	header_data.push(assigned(types::TIMESTAMP, encode_u64(timestamp)));
	let header = build_signed_tlv(&header_data, None, current_secret)?;
	let header_hash = hash_tlv(&header.encode())?;
	let payload = [
		assigned(types::TLV_HASH, header_hash.as_bytes().to_vec()),
		crate::item::rejected(
			request_identifier,
			response_to,
			None,
			crate::item::RejectionReason::Permanent,
			"requested predecessor private key is unavailable",
		)
		.expect("a permanent refusal has no retry Timestamp"),
	];
	top.push(header);
	top.push(build_signed_tlv(&payload, None, current_secret)?);
	Ok(concatenate(&top))
}

#[cfg(test)]
mod tests {
	use tith_crypto::SigningKeyPair;

	use super::*;

	#[test]
	fn non_anonymous_bundle_round_trip_and_exact_hash() {
		let origin_keys = SigningKeyPair::from_seed(&[1; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[2; 32]).unwrap();
		let origin = Identity {
			address: "fidonet#1:2/3".parse().unwrap(),
			public_key: origin_keys.public,
		};
		let destination = Identity {
			address: "fidonet#1:4/5".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let payload = OwnedTlv::new(types::POLL_MESSAGES, vec![98, 1, 7]).unwrap();
		let encoded = build_bundle(
			&origin,
			&origin_keys.secret,
			&destination,
			1_700_000_000,
			vec![vec![payload]],
		)
		.unwrap();
		let resolver = |address: &Address| {
			if address == &origin.address {
				Some(origin.public_key)
			} else if address == &destination.address {
				Some(destination.public_key)
			} else {
				None
			}
		};
		let parsed = Bundle::parse(&encoded, &resolver).unwrap();
		assert_eq!(resolver(&"fidonet#99".parse().unwrap()), None);
		assert_eq!(parsed.origin, origin);
		assert_eq!(parsed.destination, destination);
		assert_eq!(parsed.timestamp, 1_700_000_000);
		assert_eq!(parsed.payloads.len(), 1);
	}

	#[test]
	fn predecessor_key_certifies_a_successor_in_a_probe_reply() {
		let client_keys = SigningKeyPair::from_seed(&[21; 32]).unwrap();
		let old_server_keys = SigningKeyPair::from_seed(&[22; 32]).unwrap();
		let new_server_keys = SigningKeyPair::from_seed(&[23; 32]).unwrap();
		let client = Identity {
			address: "fidonet#1:2/3".parse().unwrap(),
			public_key: client_keys.public,
		};
		let server_address: Address = "fidonet#1:2/4".parse().unwrap();
		let old_server = Identity {
			address: server_address.clone(),
			public_key: old_server_keys.public,
		};
		let probe = build_public_key_probe(
			&client,
			&client_keys.secret,
			&server_address,
			Some(old_server.public_key),
			1,
			77,
		)
		.unwrap();
		let resolver = |address: &Address| {
			(address == &client.address)
				.then_some(client.public_key)
				.or_else(|| (address == &server_address).then_some(new_server_keys.public))
		};
		let parsed_probe = Bundle::parse(&probe, &resolver).unwrap();
		assert_eq!(
			parsed_probe.requested_destination_key,
			Some(old_server.public_key)
		);
		let probe_values = parse_sequence(&probe).unwrap();
		let prefix = concatenate(&probe_values[..2]);
		assert!(Bundle::parse(&prefix, &resolver).is_err());
		assert!(Bundle::parse_header_prefix(&prefix, &resolver).is_ok());
		let (request_identifier, response_to) = parsed_probe.public_key_request().unwrap().unwrap();
		let reply = build_public_key_reply(
			&old_server,
			&old_server_keys.secret,
			&client,
			2,
			request_identifier,
			response_to,
			new_server_keys.public,
		)
		.unwrap();
		let parsed =
			Bundle::parse_public_key_reply(&reply, &resolver, Some(old_server.public_key)).unwrap();
		let accepted = crate::item::validate_item(&parsed.payloads[0].data[1], &resolver)
			.unwrap()
			.unwrap();
		assert_eq!(accepted.response_public_key, Some(new_server_keys.public));

		assert!(
			Bundle::parse_public_key_reply(&reply, &resolver, Some(new_server_keys.public),)
				.is_err()
		);
		let mut tampered = reply;
		let last = tampered.last_mut().unwrap();
		*last ^= 1;
		assert!(
			Bundle::parse_public_key_reply(&tampered, &resolver, Some(old_server.public_key),)
				.is_err()
		);
	}

	#[test]
	fn anonymous_keys_are_carried_and_bad_signatures_are_rejected() {
		let origin_keys = SigningKeyPair::from_seed(&[3; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[4; 32]).unwrap();
		let origin = Identity {
			address: Address::anonymous("p2p".into()).unwrap(),
			public_key: origin_keys.public,
		};
		let destination = Identity {
			address: Address::anonymous("p2p".into()).unwrap(),
			public_key: destination_keys.public,
		};
		let mut encoded =
			build_bundle(&origin, &origin_keys.secret, &destination, 42, Vec::new()).unwrap();
		let parsed = Bundle::parse(&encoded, &|_: &Address| None).unwrap();
		assert_eq!(parsed.origin, origin);
		*encoded.last_mut().unwrap() ^= 1;
		assert!(matches!(
			Bundle::parse(&encoded, &|_: &Address| None),
			Err(BundleError::InvalidSignature)
		));
	}

	#[test]
	fn bundle_retains_unknown_values_after_its_origin() {
		let origin_keys = SigningKeyPair::from_seed(&[7; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[8; 32]).unwrap();
		let origin = Identity {
			address: "fidonet#1/7".parse().unwrap(),
			public_key: origin_keys.public,
		};
		let destination = Identity {
			address: "fidonet#1/8".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let encoded =
			build_bundle(&origin, &origin_keys.secret, &destination, 7, Vec::new()).unwrap();
		let mut top = parse_sequence(&encoded).unwrap();
		let extension = OwnedTlv::new(200, b"retained".to_vec()).unwrap();
		top.insert(1, extension.clone());
		let encoded = concatenate(&top);
		let resolver = |address: &Address| {
			if address == &origin.address {
				Some(origin.public_key)
			} else if address == &destination.address {
				Some(destination.public_key)
			} else {
				None
			}
		};
		let parsed = Bundle::parse(&encoded, &resolver).unwrap();
		assert_eq!(resolver(&"fidonet#99".parse().unwrap()), None);
		assert_eq!(parsed.unknown_top_level, vec![extension]);
	}

	#[test]
	fn header_allows_unknown_values_around_defined_children() {
		let origin_keys = SigningKeyPair::from_seed(&[9; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[10; 32]).unwrap();
		let origin = Identity {
			address: "fidonet#1/9".parse().unwrap(),
			public_key: origin_keys.public,
		};
		let destination = Identity {
			address: "fidonet#1/10".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let header_data = [
			OwnedTlv::new(200, Vec::new()).unwrap(),
			OwnedTlv::new(
				types::DESTINATION,
				destination.address.to_string().into_bytes(),
			)
			.unwrap(),
			OwnedTlv::new(201, Vec::new()).unwrap(),
			OwnedTlv::new(types::TIMESTAMP, encode_u64(9)).unwrap(),
			OwnedTlv::new(202, Vec::new()).unwrap(),
		];
		let header = build_signed_tlv(&header_data, None, &origin_keys.secret).unwrap();
		let top = [
			OwnedTlv::new(types::ORIGIN, origin.address.to_string().into_bytes()).unwrap(),
			header,
		];
		let resolver = |address: &Address| {
			if address == &origin.address {
				Some(origin.public_key)
			} else if address == &destination.address {
				Some(destination.public_key)
			} else {
				None
			}
		};
		let parsed = Bundle::parse(&concatenate(&top), &resolver).unwrap();
		assert_eq!(resolver(&"fidonet#99".parse().unwrap()), None);
		assert_eq!(parsed.destination, destination);
		assert_eq!(parsed.timestamp, 9);
	}

	#[test]
	fn payload_hash_is_the_literal_first_child() {
		let origin_keys = SigningKeyPair::from_seed(&[11; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[12; 32]).unwrap();
		let origin = Identity {
			address: "fidonet#1/11".parse().unwrap(),
			public_key: origin_keys.public,
		};
		let destination = Identity {
			address: "fidonet#1/12".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let encoded =
			build_bundle(&origin, &origin_keys.secret, &destination, 11, Vec::new()).unwrap();
		let mut top = parse_sequence(&encoded).unwrap();
		let header_hash = hash_tlv(&top[1].encode()).unwrap();
		let payload_data = [
			OwnedTlv::new(200, Vec::new()).unwrap(),
			OwnedTlv::new(types::TLV_HASH, header_hash.as_bytes().to_vec()).unwrap(),
		];
		top.push(build_signed_tlv(&payload_data, None, &origin_keys.secret).unwrap());
		let resolver = |address: &Address| {
			if address == &origin.address {
				Some(origin.public_key)
			} else if address == &destination.address {
				Some(destination.public_key)
			} else {
				None
			}
		};
		assert!(matches!(
			Bundle::parse(&concatenate(&top), &resolver),
			Err(BundleError::Missing("initial payload Header TLVHash"))
		));
		assert_eq!(resolver(&"fidonet#99".parse().unwrap()), None);
	}

	#[test]
	fn unknown_value_cannot_precede_bundle_origin() {
		let encoded = OwnedTlv::new(200, Vec::new()).unwrap().encode();
		assert!(matches!(
			Bundle::parse(&encoded, &|_: &Address| None),
			Err(BundleError::Missing("initial Origin"))
		));
	}

	#[test]
	fn first_contact_requires_the_advertised_and_accepted_keys_to_match() {
		let client_keys = SigningKeyPair::from_seed(&[31; 32]).unwrap();
		let server_keys = SigningKeyPair::from_seed(&[32; 32]).unwrap();
		let other_keys = SigningKeyPair::from_seed(&[33; 32]).unwrap();
		let client = Identity {
			address: "fidonet#1/31".parse().unwrap(),
			public_key: client_keys.public,
		};
		let server = Identity {
			address: "fidonet#1/32".parse().unwrap(),
			public_key: server_keys.public,
		};
		let resolver =
			|address: &Address| (address == &client.address).then_some(client.public_key);
		let response_to = hash_tlv(b"probe").unwrap();
		let valid = build_public_key_reply(
			&server,
			&server_keys.secret,
			&client,
			2,
			1,
			response_to,
			server.public_key,
		)
		.unwrap();
		assert!(Bundle::parse_public_key_reply(&valid, &resolver, None).is_ok());

		let mismatched = build_public_key_reply(
			&server,
			&server_keys.secret,
			&client,
			2,
			1,
			response_to,
			other_keys.public,
		)
		.unwrap();
		assert!(matches!(
			Bundle::parse_public_key_reply(&mismatched, &resolver, None),
			Err(BundleError::InvalidSignature)
		));
	}

	#[test]
	fn public_key_reply_requires_its_advertised_key_and_exact_payload_shape() {
		let client_keys = SigningKeyPair::from_seed(&[41; 32]).unwrap();
		let server_keys = SigningKeyPair::from_seed(&[42; 32]).unwrap();
		let client = Identity {
			address: "fidonet#1/41".parse().unwrap(),
			public_key: client_keys.public,
		};
		let server = Identity {
			address: "fidonet#1/42".parse().unwrap(),
			public_key: server_keys.public,
		};
		let resolver = |address: &Address| {
			(address == &client.address)
				.then_some(client.public_key)
				.or_else(|| (address == &server.address).then_some(server.public_key))
		};
		let response_to = hash_tlv(b"reply-shape").unwrap();

		let no_advertised_key = build_bundle(
			&server,
			&server_keys.secret,
			&client,
			1,
			vec![vec![
				crate::item::accepted_public_key(1, response_to, server.public_key).unwrap(),
			]],
		)
		.unwrap();
		let ordinary_reply = Bundle::parse(&no_advertised_key, &resolver).unwrap();
		assert_eq!(ordinary_reply.public_key_request().unwrap(), None);
		assert!(matches!(
			Bundle::parse_public_key_reply(&no_advertised_key, &resolver, Some(server.public_key)),
			Err(BundleError::Unexpected("PublicKeyRequest reply grammar"))
		));

		let valid = build_public_key_reply(
			&server,
			&server_keys.secret,
			&client,
			2,
			1,
			response_to,
			server.public_key,
		)
		.unwrap();
		let mut top = parse_sequence(&valid).unwrap();
		let no_payload = Bundle::parse_internal(
			&concatenate(&top[..3]),
			&resolver,
			NonAnonymousOriginKey::Exact(server.public_key),
			false,
		)
		.unwrap();
		assert_eq!(no_payload.public_key_request().unwrap(), None);
		assert!(matches!(
			Bundle::parse_public_key_reply(
				&concatenate(&top[..3]),
				&resolver,
				Some(server.public_key)
			),
			Err(BundleError::Unexpected("PublicKeyRequest reply grammar"))
		));

		let header_hash = hash_tlv(&top[2].encode()).unwrap();
		let extended_payload = [
			assigned(types::TLV_HASH, header_hash.as_bytes().to_vec()),
			crate::item::accepted_public_key(1, response_to, server.public_key).unwrap(),
			OwnedTlv::new(200, Vec::new()).unwrap(),
		];
		top[3] = build_signed_tlv(&extended_payload, None, &server_keys.secret).unwrap();
		let extended = Bundle::parse_internal(
			&concatenate(&top),
			&resolver,
			NonAnonymousOriginKey::Exact(server.public_key),
			false,
		)
		.unwrap();
		assert_eq!(extended.public_key_request().unwrap(), None);
		assert!(matches!(
			Bundle::parse_public_key_reply(&concatenate(&top), &resolver, Some(server.public_key)),
			Err(BundleError::Unexpected("PublicKeyRequest reply grammar"))
		));
	}

	#[test]
	fn public_key_request_is_rejected_when_mixed_or_repeated() {
		let origin_keys = SigningKeyPair::from_seed(&[34; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[35; 32]).unwrap();
		let origin = Identity {
			address: "fidonet#1/34".parse().unwrap(),
			public_key: origin_keys.public,
		};
		let destination = Identity {
			address: "fidonet#1/35".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let resolver = |address: &Address| {
			if address == &origin.address {
				Some(origin.public_key)
			} else if address == &destination.address {
				Some(destination.public_key)
			} else {
				None
			}
		};
		let request = crate::item::public_key_request(1).unwrap();
		let poll = OwnedTlv::new(
			types::POLL_MESSAGES,
			OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(2))
				.unwrap()
				.encode(),
		)
		.unwrap();
		for payload_groups in [
			vec![vec![request.clone(), poll]],
			vec![vec![request.clone()], vec![request]],
		] {
			let encoded = build_bundle(
				&origin,
				&origin_keys.secret,
				&destination,
				1,
				payload_groups,
			)
			.unwrap();
			assert!(matches!(
				Bundle::parse(&encoded, &resolver),
				Err(BundleError::Unexpected(
					"PublicKeyRequest outside its dedicated Bundle"
				))
			));
			assert!(matches!(
				Bundle::parse_header_prefix(&encoded, &resolver),
				Err(BundleError::Unexpected(
					"PublicKeyRequest outside its dedicated Bundle"
				))
			));
		}
		assert_eq!(resolver(&"fidonet#99".parse().unwrap()), None);
	}

	#[test]
	fn unavailable_predecessor_reply_is_signed_by_the_current_key() {
		let client_keys = SigningKeyPair::from_seed(&[36; 32]).unwrap();
		let old_server_keys = SigningKeyPair::from_seed(&[37; 32]).unwrap();
		let current_server_keys = SigningKeyPair::from_seed(&[38; 32]).unwrap();
		let client = Identity {
			address: "fidonet#1/36".parse().unwrap(),
			public_key: client_keys.public,
		};
		let current_server = Identity {
			address: "fidonet#1/37".parse().unwrap(),
			public_key: current_server_keys.public,
		};
		let response_to = hash_tlv(b"unavailable").unwrap();
		let reply = build_public_key_unavailable_reply(
			&current_server,
			&current_server_keys.secret,
			&client,
			2,
			7,
			response_to,
		)
		.unwrap();
		let resolver =
			|address: &Address| (address == &client.address).then_some(client.public_key);
		assert!(matches!(
			Bundle::parse_public_key_reply(&reply, &resolver, Some(old_server_keys.public)),
			Err(BundleError::InvalidSignature)
		));
		assert!(matches!(
			Bundle::parse_public_key_reply(&reply, &resolver, Some(current_server.public_key)),
			Err(BundleError::Unexpected("PublicKeyRequest reply grammar"))
		));
		let parsed = Bundle::parse_internal(
			&reply,
			&resolver,
			NonAnonymousOriginKey::Exact(current_server.public_key),
			false,
		)
		.unwrap();
		let rejected = crate::item::validate_item(&parsed.payloads[0].data[1], &resolver)
			.unwrap()
			.unwrap();
		assert_eq!(rejected.kind, crate::item::ItemKind::Rejected);
		assert_eq!(
			rejected.rejection.unwrap().reason,
			crate::item::RejectionReason::Permanent
		);
	}

	#[test]
	fn bundle_parser_rejects_each_header_and_payload_boundary() {
		let origin_keys = SigningKeyPair::from_seed(&[51; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[52; 32]).unwrap();
		let origin = Identity {
			address: "fidonet#1/51".parse().unwrap(),
			public_key: origin_keys.public,
		};
		let destination = Identity {
			address: "fidonet#1/52".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let anonymous = Identity {
			address: Address::anonymous("p2p".to_owned()).unwrap(),
			public_key: destination_keys.public,
		};
		let resolver = |address: &Address| {
			if address == &origin.address {
				Some(origin.public_key)
			} else if address == &destination.address {
				Some(destination.public_key)
			} else {
				None
			}
		};
		let outer_origin =
			OwnedTlv::new(types::ORIGIN, origin.address.to_string().into_bytes()).unwrap();
		let signed_header =
			|data: Vec<OwnedTlv>| build_signed_tlv(&data, None, &origin_keys.secret).unwrap();
		let valid_header_data = vec![
			OwnedTlv::new(
				types::DESTINATION,
				destination.address.to_string().into_bytes(),
			)
			.unwrap(),
			OwnedTlv::new(types::TIMESTAMP, encode_u64(1)).unwrap(),
		];
		assert_eq!(resolver(&"fidonet#99".parse().unwrap()), None);

		assert!(matches!(
			Bundle::parse(&[], &resolver),
			Err(BundleError::Missing("Origin"))
		));
		let anonymous_origin =
			OwnedTlv::new(types::ORIGIN, anonymous.address.to_string().into_bytes()).unwrap();
		assert!(matches!(
			Bundle::parse(&anonymous_origin.encode(), &resolver),
			Err(BundleError::Missing("Origin PublicKey"))
		));
		let wrong_after_anonymous = concatenate(&[
			anonymous_origin,
			OwnedTlv::new(types::TIMESTAMP, encode_u64(1)).unwrap(),
		]);
		assert!(matches!(
			Bundle::parse(&wrong_after_anonymous, &resolver),
			Err(BundleError::Missing("Origin PublicKey"))
		));
		let prohibited_key = concatenate(&[
			outer_origin.clone(),
			OwnedTlv::new(types::PUBLIC_KEY, origin.public_key.as_bytes().to_vec()).unwrap(),
		]);
		assert!(matches!(
			Bundle::parse(&prohibited_key, &resolver),
			Err(BundleError::Unexpected("non-anonymous Origin PublicKey"))
		));

		for header_data in [
			Vec::new(),
			vec![OwnedTlv::new(types::TIMESTAMP, encode_u64(1)).unwrap()],
			vec![
				OwnedTlv::new(
					types::DESTINATION,
					anonymous.address.to_string().into_bytes(),
				)
				.unwrap(),
				OwnedTlv::new(types::TIMESTAMP, encode_u64(1)).unwrap(),
			],
			vec![
				OwnedTlv::new(
					types::DESTINATION,
					anonymous.address.to_string().into_bytes(),
				)
				.unwrap(),
				OwnedTlv::new(types::ADDRESS, b"p2p#-1".to_vec()).unwrap(),
				OwnedTlv::new(types::TIMESTAMP, encode_u64(1)).unwrap(),
			],
			vec![
				OwnedTlv::new(
					types::DESTINATION,
					destination.address.to_string().into_bytes(),
				)
				.unwrap(),
			],
			{
				let mut values = valid_header_data.clone();
				values.push(OwnedTlv::new(types::ADDRESS, b"fidonet#1/52".to_vec()).unwrap());
				values
			},
		] {
			let encoded = concatenate(&[outer_origin.clone(), signed_header(header_data)]);
			assert!(Bundle::parse(&encoded, &resolver).is_err());
		}

		let header = signed_header(valid_header_data);
		let header_hash = hash_tlv(&header.encode()).unwrap();
		let payloads = [
			Vec::new(),
			vec![OwnedTlv::new(types::ADDRESS, Vec::new()).unwrap()],
			vec![OwnedTlv::new(types::TLV_HASH, vec![0; 31]).unwrap()],
			vec![OwnedTlv::new(types::TLV_HASH, vec![0; 32]).unwrap()],
		];
		for data in payloads {
			let encoded = concatenate(&[
				outer_origin.clone(),
				header.clone(),
				build_signed_tlv(&data, None, &origin_keys.secret).unwrap(),
			]);
			assert!(Bundle::parse(&encoded, &resolver).is_err());
		}
		let valid_payload = build_signed_tlv(
			&[OwnedTlv::new(types::TLV_HASH, header_hash.as_bytes().to_vec()).unwrap()],
			None,
			&origin_keys.secret,
		)
		.unwrap();
		let defined_top = concatenate(&[
			outer_origin.clone(),
			header.clone(),
			valid_payload.clone(),
			OwnedTlv::new(types::TIMESTAMP, encode_u64(2)).unwrap(),
		]);
		assert!(Bundle::parse(&defined_top, &resolver).is_err());
		let extension = OwnedTlv::new(200, b"tail".to_vec()).unwrap();
		let extended = concatenate(&[outer_origin, header, valid_payload, extension.clone()]);
		let parsed = Bundle::parse(&extended, &resolver).unwrap();
		assert_eq!(parsed.unknown_top_level, vec![extension]);
		assert_eq!(parsed.public_key_request().unwrap(), None);
	}

	#[test]
	fn probe_builders_cover_first_contact_and_anonymous_requesters() {
		let origin_keys = SigningKeyPair::from_seed(&[53; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[54; 32]).unwrap();
		let anonymous_origin = Identity {
			address: Address::anonymous("p2p".to_owned()).unwrap(),
			public_key: origin_keys.public,
		};
		let destination = Identity {
			address: "fidonet#1/54".parse().unwrap(),
			public_key: destination_keys.public,
		};
		let probe = build_public_key_probe(
			&anonymous_origin,
			&origin_keys.secret,
			&destination.address,
			None,
			1,
			4,
		)
		.unwrap();
		let parsed = Bundle::parse(&probe, &|address: &Address| {
			(address == &destination.address).then_some(destination.public_key)
		})
		.unwrap();
		assert_eq!(parsed.origin, anonymous_origin);
		assert_eq!(parsed.requested_destination_key, None);
		assert!(parsed.public_key_request().unwrap().is_some());
		assert!(
			build_public_key_probe(
				&parsed.origin,
				&origin_keys.secret,
				&Address::anonymous("p2p".to_owned()).unwrap(),
				None,
				1,
				4,
			)
			.is_err()
		);

		let response_to = hash_tlv(b"request").unwrap();
		let accepted = build_public_key_reply(
			&destination,
			&destination_keys.secret,
			&anonymous_origin,
			2,
			4,
			response_to,
			destination.public_key,
		)
		.unwrap();
		assert!(Bundle::parse_public_key_reply(&accepted, &|_: &Address| None, None).is_ok());
		let unavailable = build_public_key_unavailable_reply(
			&destination,
			&destination_keys.secret,
			&anonymous_origin,
			2,
			4,
			response_to,
		)
		.unwrap();
		assert!(!unavailable.is_empty());
	}
}
