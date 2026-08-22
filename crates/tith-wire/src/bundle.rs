//! TTS-0003 signed containers and TTS-0005 bundles.

use std::fmt;
use std::str::FromStr;

use tith_crypto::{
	CryptoError, PublicKey, SIGNATURE_BYTES, SecretKey, Signature, TlvHash, hash_tlv, sign_tlv,
	verify_tlv,
};

use crate::address::{Address, AddressError};
pub use crate::identity::Identity;
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
	Duplicate(&'static str),
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
			Self::Duplicate(name) => write!(f, "duplicate {name}"),
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

fn address_value(value: &OwnedTlv) -> Result<Address, BundleError> {
	let text = std::str::from_utf8(&value.value).map_err(|_| BundleError::InvalidUtf8)?;
	Address::from_str(text).map_err(Into::into)
}

fn public_key_value(value: &OwnedTlv) -> Result<PublicKey, BundleError> {
	PublicKey::try_from(value.value.as_slice()).map_err(|_| BundleError::WrongLength("PublicKey"))
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
	let public_key = if address.is_anonymous() {
		public_key_tlv
			.ok_or(BundleError::Missing("PublicKey for anonymous address"))
			.and_then(public_key_value)?
	} else {
		if public_key_tlv.is_some() {
			return Err(BundleError::Unexpected(
				"PublicKey for non-anonymous address",
			));
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
		if address.is_anonymous() {
			let key = next
				.filter(|child| child.type_code == types::PUBLIC_KEY)
				.ok_or(BundleError::Missing("PublicKey after anonymous Origin"))?
				.clone();
			index += 1;
			Some(key)
		} else {
			if next.is_some_and(|child| child.type_code == types::PUBLIC_KEY) {
				return Err(BundleError::Unexpected(
					"PublicKey after non-anonymous Origin",
				));
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

pub fn unauthenticated_signed_data(value: &OwnedTlv) -> Result<Vec<OwnedTlv>, BundleError> {
	let (_, _, signed_data, _) = signed_tlv_parts(value)?;
	parse_sequence(&signed_data.value).map_err(Into::into)
}

impl Bundle {
	pub fn parse(encoded: &[u8], resolver: &impl KeyResolver) -> Result<Self, BundleError> {
		Self::parse_internal(encoded, resolver, NonAnonymousOriginKey::Prohibited, false)
	}

	/// Parses only the Origin and Header prefix while deferring rules which
	/// depend on seeing the payload.
	pub fn parse_header_prefix(
		encoded: &[u8],
		resolver: &impl KeyResolver,
	) -> Result<Self, BundleError> {
		Self::parse_internal(encoded, resolver, NonAnonymousOriginKey::Prohibited, true)
	}

	/// Parses a probe reply whose non-anonymous outer Origin carries the key that
	/// authenticated the reply. `expected` pins that key when a predecessor is
	/// already trusted; `None` is the explicit first-contact TOFU case.
	pub fn parse_public_key_reply(
		encoded: &[u8],
		resolver: &impl KeyResolver,
		expected: Option<PublicKey>,
	) -> Result<Self, BundleError> {
		let mode = expected.map_or(NonAnonymousOriginKey::Any, NonAnonymousOriginKey::Exact);
		let bundle = Self::parse_internal(encoded, resolver, mode, false)?;
		if bundle.advertised_origin_key.is_none()
			|| bundle.payloads.len() != 1
			|| bundle.payloads[0].data.len() != 2
			|| bundle.payloads[0].data[0].type_code != types::TLV_HASH
			|| bundle.payloads[0].data[1].type_code != types::ACCEPTED
		{
			return Err(BundleError::Unexpected("PublicKeyRequest reply grammar"));
		}
		let accepted = crate::item::validate_item(&bundle.payloads[0].data[1], resolver)?
			.ok_or(BundleError::Unexpected("PublicKeyRequest Accepted"))?;
		if accepted.response_public_key.is_none() {
			return Err(BundleError::Missing("Accepted current PublicKey"));
		}
		Ok(bundle)
	}

	fn parse_internal(
		encoded: &[u8],
		resolver: &impl KeyResolver,
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
		if header.identity != origin {
			return Err(BundleError::Unexpected("Header Origin"));
		}
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
		if requested_destination_key.is_some()
			&& !(allow_header_only && payloads.is_empty())
			&& !(payloads.len() == 1
				&& payloads[0].data.len() == 2
				&& payloads[0].data[0].type_code == types::TLV_HASH
				&& payloads[0].data[1].type_code == types::PUBLIC_KEY_REQUEST)
		{
			return Err(BundleError::Unexpected(
				"non-anonymous Destination PublicKey outside a sole PublicKeyRequest",
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
			|| self.payloads[0].data[0].type_code != types::TLV_HASH
			|| self.payloads[0].data[1].type_code != types::PUBLIC_KEY_REQUEST
		{
			return Ok(None);
		}
		let item = crate::item::validate_item(&self.payloads[0].data[1], &|_: &Address| None)?
			.ok_or(BundleError::Unexpected("PublicKeyRequest"))?;
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
	resolver: &impl KeyResolver,
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
		if origin.address.is_anonymous() {
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
	if origin.address.is_anonymous() {
		top.push(OwnedTlv::new(
			types::PUBLIC_KEY,
			origin.public_key.as_bytes().to_vec(),
		)?);
	}
	let mut header_data = vec![OwnedTlv::new(
		types::DESTINATION,
		destination.address.to_string().into_bytes(),
	)?];
	if destination.address.is_anonymous() {
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
	let mut top = vec![OwnedTlv::new(
		types::ORIGIN,
		origin.address.to_string().into_bytes(),
	)?];
	if origin.address.is_anonymous() {
		top.push(OwnedTlv::new(
			types::PUBLIC_KEY,
			origin.public_key.as_bytes().to_vec(),
		)?);
	}
	let mut header_data = vec![OwnedTlv::new(
		types::DESTINATION,
		destination.to_string().into_bytes(),
	)?];
	if let Some(key) = requested_key {
		header_data.push(OwnedTlv::new(types::PUBLIC_KEY, key.as_bytes().to_vec())?);
	}
	header_data.push(OwnedTlv::new(types::TIMESTAMP, encode_u64(timestamp))?);
	let header = build_signed_tlv(&header_data, None, origin_secret)?;
	let header_hash = hash_tlv(&header.encode())?;
	let payload = [
		OwnedTlv::new(types::TLV_HASH, header_hash.as_bytes().to_vec())?,
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
	let mut top = vec![OwnedTlv::new(
		types::ORIGIN,
		signing_origin.address.to_string().into_bytes(),
	)?];
	// A probe reply always states its signing key, including for a non-anonymous Origin.
	top.push(OwnedTlv::new(
		types::PUBLIC_KEY,
		signing_origin.public_key.as_bytes().to_vec(),
	)?);
	let mut header_data = vec![OwnedTlv::new(
		types::DESTINATION,
		destination.address.to_string().into_bytes(),
	)?];
	if destination.address.is_anonymous() {
		header_data.push(OwnedTlv::new(
			types::PUBLIC_KEY,
			destination.public_key.as_bytes().to_vec(),
		)?);
	}
	header_data.push(OwnedTlv::new(types::TIMESTAMP, encode_u64(timestamp))?);
	let header = build_signed_tlv(&header_data, None, signing_secret)?;
	let header_hash = hash_tlv(&header.encode())?;
	let payload = [
		OwnedTlv::new(types::TLV_HASH, header_hash.as_bytes().to_vec())?,
		crate::item::accepted_public_key(request_identifier, response_to, current_key)?,
	];
	top.push(header);
	top.push(build_signed_tlv(&payload, None, signing_secret)?);
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
		if let Some(byte) = encoded.last_mut() {
			*byte ^= 1;
		}
		assert!(matches!(
			Bundle::parse(&encoded, &|_: &Address| None),
			Err(BundleError::InvalidSignature)
		));
	}

	#[test]
	fn signed_tlv_carries_an_anonymous_origin_key() {
		let keys = SigningKeyPair::from_seed(&[5; 32]).unwrap();
		let origin = Identity {
			address: Address::anonymous("p2p".into()).unwrap(),
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
	fn unknown_value_cannot_separate_an_anonymous_origin_and_key() {
		let keys = SigningKeyPair::from_seed(&[6; 32]).unwrap();
		let origin = Address::anonymous("p2p".into()).unwrap();
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
			Err(BundleError::Missing("PublicKey after anonymous Origin"))
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
