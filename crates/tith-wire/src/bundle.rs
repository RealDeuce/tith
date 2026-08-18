//! TTS-0003 signed containers and TTS-0005 bundles.

use std::fmt;
use std::str::FromStr;

use tith_crypto::{
	CryptoError, PublicKey, SIGNATURE_BYTES, SecretKey, Signature, TlvHash, hash_tlv, sign_tlv,
	verify_tlv,
};

use crate::address::{Address, AddressError};
use crate::integer::{IntegerError, decode_u64, encode_u64};
use crate::tlv::{FramingError, OwnedTlv, parse_sequence};
use crate::types;

#[derive(Debug)]
pub enum BundleError {
	Framing(FramingError),
	Address(AddressError),
	Integer(IntegerError),
	Crypto(CryptoError),
	InvalidUtf8,
	Missing(&'static str),
	Unexpected(&'static str),
	WrongLength(&'static str),
	UnknownKey(Address),
	InvalidSignature,
	IncorrectHeaderHash,
}

impl fmt::Display for BundleError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Framing(error) => write!(f, "bundle framing error: {error}"),
			Self::Address(error) => write!(f, "invalid address: {error}"),
			Self::Integer(error) => write!(f, "invalid integer value: {error}"),
			Self::Crypto(error) => write!(f, "cryptographic error: {error}"),
			Self::InvalidUtf8 => f.write_str("value is not valid UTF-8"),
			Self::Missing(name) => write!(f, "missing required {name}"),
			Self::Unexpected(name) => write!(f, "unexpected or misplaced {name}"),
			Self::WrongLength(name) => write!(f, "{name} has the wrong length"),
			Self::UnknownKey(address) => write!(f, "no public key for {address}"),
			Self::InvalidSignature => f.write_str("signature verification failed"),
			Self::IncorrectHeaderHash => f.write_str("payload has the wrong Header TLVHash"),
		}
	}
}

impl std::error::Error for BundleError {}

impl From<FramingError> for BundleError {
	fn from(value: FramingError) -> Self {
		Self::Framing(value)
	}
}

impl From<AddressError> for BundleError {
	fn from(value: AddressError) -> Self {
		Self::Address(value)
	}
}

impl From<IntegerError> for BundleError {
	fn from(value: IntegerError) -> Self {
		Self::Integer(value)
	}
}

impl From<CryptoError> for BundleError {
	fn from(value: CryptoError) -> Self {
		Self::Crypto(value)
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
	pub address: Address,
	pub public_key: PublicKey,
}

pub trait KeyResolver {
	fn public_key(&self, address: &Address) -> Option<PublicKey>;
}

impl<F> KeyResolver for F
where
	F: Fn(&Address) -> Option<PublicKey>,
{
	fn public_key(&self, address: &Address) -> Option<PublicKey> {
		self(address)
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSignedTlv {
	pub encoded: Vec<u8>,
	pub identity: Identity,
	pub data: Vec<OwnedTlv>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bundle {
	pub encoded: Vec<u8>,
	pub origin: Identity,
	pub destination: Identity,
	pub timestamp: u64,
	pub header: VerifiedSignedTlv,
	pub payloads: Vec<VerifiedSignedTlv>,
	pub unknown_top_level: Vec<OwnedTlv>,
}

fn address_value(value: &OwnedTlv) -> Result<Address, BundleError> {
	let text = std::str::from_utf8(&value.value).map_err(|_| BundleError::InvalidUtf8)?;
	Address::from_str(text).map_err(Into::into)
}

fn public_key_value(value: &OwnedTlv) -> Result<PublicKey, BundleError> {
	let bytes: [u8; 32] = value
		.value
		.as_slice()
		.try_into()
		.map_err(|_| BundleError::WrongLength("PublicKey"))?;
	Ok(PublicKey::from_bytes(bytes))
}

fn signature_value(value: &OwnedTlv) -> Result<Signature, BundleError> {
	let bytes: [u8; SIGNATURE_BYTES] = value
		.value
		.as_slice()
		.try_into()
		.map_err(|_| BundleError::WrongLength("Signature"))?;
	Ok(Signature::from_bytes(bytes))
}

fn identity(
	address_tlv: &OwnedTlv,
	public_key_tlv: Option<&OwnedTlv>,
	resolver: &impl KeyResolver,
) -> Result<Identity, BundleError> {
	let address = address_value(address_tlv)?;
	let public_key = if address.is_unlisted() {
		public_key_tlv
			.ok_or(BundleError::Missing("PublicKey for unlisted address"))
			.and_then(public_key_value)?
	} else {
		if public_key_tlv.is_some() {
			return Err(BundleError::Unexpected("PublicKey for listed address"));
		}
		resolver
			.public_key(&address)
			.ok_or_else(|| BundleError::UnknownKey(address.clone()))?
	};
	Ok(Identity {
		address,
		public_key,
	})
}

fn signed_tlv_parts(
	value: &OwnedTlv,
) -> Result<(Option<OwnedTlv>, Option<OwnedTlv>, OwnedTlv, OwnedTlv), BundleError> {
	if value.type_code != types::SIGNED_TLV {
		return Err(BundleError::Unexpected("non-SignedTLV"));
	}
	let children = parse_sequence(&value.value)?;
	let mut index = 0;
	let origin = children
		.first()
		.filter(|child| child.type_code == types::ORIGIN)
		.cloned();
	let public_key = if let Some(origin) = origin.as_ref() {
		index += 1;
		let address = address_value(origin)?;
		let next = children.get(index);
		if address.is_unlisted() {
			let key = next
				.filter(|child| child.type_code == types::PUBLIC_KEY)
				.ok_or(BundleError::Missing("PublicKey after unlisted Origin"))?
				.clone();
			index += 1;
			Some(key)
		} else {
			if next.is_some_and(|child| child.type_code == types::PUBLIC_KEY) {
				return Err(BundleError::Unexpected("PublicKey after listed Origin"));
			}
			None
		}
	} else {
		None
	};
	let mut signed_data = None;
	let mut signature = None;
	let mut stage = 0;
	for child in children.into_iter().skip(index) {
		match child.type_code {
			types::SIGNED_DATA if stage == 0 && signed_data.is_none() => {
				signed_data = Some(child);
				stage = 1;
			}
			types::SIGNATURE if stage == 1 && signature.is_none() => {
				signature = Some(child);
				stage = 2;
			}
			type_code if types::is_defined(type_code) => {
				return Err(BundleError::Unexpected("defined SignedTLV child"));
			}
			_ => {}
		}
	}
	let signed_data = signed_data.ok_or(BundleError::Missing("SignedData"))?;
	let signature = signature.ok_or(BundleError::Missing("Signature"))?;
	Ok((origin, public_key, signed_data, signature))
}

pub fn verify_signed_tlv(
	value: &OwnedTlv,
	inherited: Option<&Identity>,
	resolver: &impl KeyResolver,
) -> Result<VerifiedSignedTlv, BundleError> {
	let (origin_tlv, public_key_tlv, signed_data, signature_tlv) = signed_tlv_parts(value)?;
	let identity = if let Some(origin_tlv) = origin_tlv.as_ref() {
		identity(origin_tlv, public_key_tlv.as_ref(), resolver)?
	} else {
		if public_key_tlv.is_some() {
			return Err(BundleError::Unexpected("PublicKey without Origin"));
		}
		inherited
			.cloned()
			.ok_or(BundleError::Missing("applicable Origin"))?
	};
	let signature = signature_value(&signature_tlv)?;
	if !verify_tlv(&signed_data.value, &signature, &identity.public_key)? {
		return Err(BundleError::InvalidSignature);
	}
	Ok(VerifiedSignedTlv {
		encoded: value.encode(),
		identity,
		data: parse_sequence(&signed_data.value)?,
	})
}

impl Bundle {
	pub fn parse(encoded: &[u8], resolver: &impl KeyResolver) -> Result<Self, BundleError> {
		let top = parse_sequence(encoded)?;
		let origin_tlv = top.first().ok_or(BundleError::Missing("Origin"))?;
		if origin_tlv.type_code != types::ORIGIN {
			return Err(BundleError::Missing("initial Origin"));
		}
		let origin_address = address_value(origin_tlv)?;
		let mut index = 1;
		let origin_public_key = if origin_address.is_unlisted() {
			let value = top
				.get(index)
				.ok_or(BundleError::Missing("Origin PublicKey"))?;
			if value.type_code != types::PUBLIC_KEY {
				return Err(BundleError::Missing("Origin PublicKey"));
			}
			index += 1;
			Some(value)
		} else {
			if top
				.get(index)
				.is_some_and(|value| value.type_code == types::PUBLIC_KEY)
			{
				return Err(BundleError::Unexpected("Origin PublicKey"));
			}
			None
		};
		let origin = identity(origin_tlv, origin_public_key, resolver)?;

		let header_tlv = next_defined(&top, &mut index)
			.filter(|value| value.type_code == types::SIGNED_TLV)
			.ok_or(BundleError::Missing("Header SignedTLV"))?;
		let header = verify_signed_tlv(header_tlv, Some(&origin), resolver)?;
		if header.identity != origin {
			return Err(BundleError::Unexpected("Header Origin"));
		}
		let (destination, timestamp) = validate_header(&header.data, resolver)?;
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

		Ok(Self {
			encoded: encoded.to_vec(),
			origin,
			destination,
			timestamp,
			header,
			payloads,
			unknown_top_level,
		})
	}
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
	resolver: &impl KeyResolver,
) -> Result<(Identity, u64), BundleError> {
	let mut index = 0;
	let destination_tlv = next_defined(children, &mut index)
		.filter(|value| value.type_code == types::DESTINATION)
		.ok_or(BundleError::Missing("Destination"))?;
	let destination_address = address_value(destination_tlv)?;
	let destination_key = if destination_address.is_unlisted() {
		let value = children
			.get(index)
			.ok_or(BundleError::Missing("Destination PublicKey"))?;
		if value.type_code != types::PUBLIC_KEY {
			return Err(BundleError::Missing("Destination PublicKey"));
		}
		index += 1;
		Some(value)
	} else {
		if children
			.get(index)
			.is_some_and(|value| value.type_code == types::PUBLIC_KEY)
		{
			return Err(BundleError::Unexpected("Destination PublicKey"));
		}
		None
	};
	let destination = identity(destination_tlv, destination_key, resolver)?;
	let timestamp = next_defined(children, &mut index)
		.filter(|value| value.type_code == types::TIMESTAMP)
		.ok_or(BundleError::Missing("Timestamp after Destination"))?;
	if next_defined(children, &mut index).is_some() {
		return Err(BundleError::Unexpected("defined Header value"));
	}
	Ok((destination, decode_u64(&timestamp.value)?))
}

fn concatenate(values: &[OwnedTlv]) -> Vec<u8> {
	let capacity = values.iter().map(OwnedTlv::encoded_len).sum();
	let mut output = Vec::with_capacity(capacity);
	for value in values {
		value.write_to(&mut output).expect("Vec writes cannot fail");
	}
	output
}

pub fn build_signed_tlv(
	data: &[OwnedTlv],
	origin: Option<&Identity>,
	secret: &SecretKey,
) -> Result<OwnedTlv, BundleError> {
	let data_bytes = concatenate(data);
	let signature = sign_tlv(&data_bytes, secret)?;
	let mut children = Vec::new();
	if let Some(origin) = origin {
		children.push(OwnedTlv::new(
			types::ORIGIN,
			origin.address.to_string().into_bytes(),
		)?);
		if origin.address.is_unlisted() {
			children.push(OwnedTlv::new(
				types::PUBLIC_KEY,
				origin.public_key.as_bytes().to_vec(),
			)?);
		}
	}
	children.push(OwnedTlv::new(types::SIGNED_DATA, data_bytes)?);
	children.push(OwnedTlv::new(
		types::SIGNATURE,
		signature.as_bytes().to_vec(),
	)?);
	OwnedTlv::new(types::SIGNED_TLV, concatenate(&children)).map_err(Into::into)
}

pub fn build_bundle(
	origin: &Identity,
	origin_secret: &SecretKey,
	destination: &Identity,
	timestamp: u64,
	payload_groups: Vec<Vec<OwnedTlv>>,
) -> Result<Vec<u8>, BundleError> {
	let mut top = vec![OwnedTlv::new(
		types::ORIGIN,
		origin.address.to_string().into_bytes(),
	)?];
	if origin.address.is_unlisted() {
		top.push(OwnedTlv::new(
			types::PUBLIC_KEY,
			origin.public_key.as_bytes().to_vec(),
		)?);
	}
	let mut header_data = vec![OwnedTlv::new(
		types::DESTINATION,
		destination.address.to_string().into_bytes(),
	)?];
	if destination.address.is_unlisted() {
		header_data.push(OwnedTlv::new(
			types::PUBLIC_KEY,
			destination.public_key.as_bytes().to_vec(),
		)?);
	}
	header_data.push(OwnedTlv::new(types::TIMESTAMP, encode_u64(timestamp))?);
	let header = build_signed_tlv(&header_data, None, origin_secret)?;
	let header_hash = hash_tlv(&header.encode())?;
	top.push(header);
	for mut payload in payload_groups {
		payload.insert(
			0,
			OwnedTlv::new(types::TLV_HASH, header_hash.as_bytes().to_vec())?,
		);
		top.push(build_signed_tlv(&payload, None, origin_secret)?);
	}
	Ok(concatenate(&top))
}

#[cfg(test)]
mod tests {
	use tith_crypto::SigningKeyPair;

	use super::*;

	#[test]
	fn listed_bundle_round_trip_and_exact_hash() {
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
		assert_eq!(parsed.origin, origin);
		assert_eq!(parsed.destination, destination);
		assert_eq!(parsed.timestamp, 1_700_000_000);
		assert_eq!(parsed.payloads.len(), 1);
	}

	#[test]
	fn unlisted_keys_are_carried_and_bad_signatures_are_rejected() {
		let origin_keys = SigningKeyPair::from_seed(&[3; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[4; 32]).unwrap();
		let origin = Identity {
			address: Address::unlisted("p2p".into()).unwrap(),
			public_key: origin_keys.public,
		};
		let destination = Identity {
			address: Address::unlisted("p2p".into()).unwrap(),
			public_key: destination_keys.public,
		};
		let mut encoded =
			build_bundle(&origin, &origin_keys.secret, &destination, 42, Vec::new()).unwrap();
		let parsed = Bundle::parse(&encoded, &|_: &Address| None).unwrap();
		assert_eq!(parsed.origin, origin);
		if let Some(byte) = encoded.last_mut() {
			*byte ^= 1;
		}
		assert!(matches!(
			Bundle::parse(&encoded, &|_: &Address| None),
			Err(BundleError::InvalidSignature)
		));
	}

	#[test]
	fn signed_tlv_carries_an_unlisted_origin_key() {
		let keys = SigningKeyPair::from_seed(&[5; 32]).unwrap();
		let origin = Identity {
			address: Address::unlisted("p2p".into()).unwrap(),
			public_key: keys.public,
		};
		let data = [OwnedTlv::new(200, b"extension".to_vec()).unwrap()];
		let signed = build_signed_tlv(&data, Some(&origin), &keys.secret).unwrap();
		let mut children = parse_sequence(&signed.value).unwrap();
		children.insert(2, OwnedTlv::new(201, b"wrapper".to_vec()).unwrap());
		let signed = OwnedTlv::new(types::SIGNED_TLV, concatenate(&children)).unwrap();
		let verified = verify_signed_tlv(&signed, None, &|_: &Address| None).unwrap();
		assert_eq!(verified.identity, origin);
		assert_eq!(verified.data, data);
	}

	#[test]
	fn unknown_value_cannot_separate_an_unlisted_origin_and_key() {
		let keys = SigningKeyPair::from_seed(&[6; 32]).unwrap();
		let origin = Address::unlisted("p2p".into()).unwrap();
		let children = [
			OwnedTlv::new(types::ORIGIN, origin.to_string().into_bytes()).unwrap(),
			OwnedTlv::new(200, Vec::new()).unwrap(),
			OwnedTlv::new(types::PUBLIC_KEY, keys.public.as_bytes().to_vec()).unwrap(),
			OwnedTlv::new(types::SIGNED_DATA, Vec::new()).unwrap(),
			OwnedTlv::new(types::SIGNATURE, vec![0; SIGNATURE_BYTES]).unwrap(),
		];
		let signed = OwnedTlv::new(types::SIGNED_TLV, concatenate(&children)).unwrap();
		assert!(matches!(
			verify_signed_tlv(&signed, None, &|_: &Address| None),
			Err(BundleError::Missing("PublicKey after unlisted Origin"))
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
	}

	#[test]
	fn unknown_value_cannot_precede_bundle_origin() {
		let encoded = OwnedTlv::new(200, Vec::new()).unwrap().encode();
		assert!(matches!(
			Bundle::parse(&encoded, &|_: &Address| None),
			Err(BundleError::Missing("initial Origin"))
		));
	}
}
