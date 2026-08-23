//! TTS-0003 common values and signed-container processing.

use std::str::FromStr;

use tith_crypto::{PublicKey, SecretKey, Signature, sign_tlv, verify_tlv};

use crate::address::Address;
use crate::error::BundleError;
pub use crate::identity::Identity;
use crate::tlv::{OwnedTlv, parse_sequence};
use crate::types;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnknownChildren {
	Allow,
	Reject,
}

pub(crate) fn address_value(value: &OwnedTlv) -> Result<Address, BundleError> {
	let text = std::str::from_utf8(&value.value).map_err(|_| BundleError::InvalidUtf8)?;
	Address::from_str(text).map_err(Into::into)
}

pub(crate) fn public_key_value(value: &OwnedTlv) -> Result<PublicKey, BundleError> {
	PublicKey::try_from(value.value.as_slice()).map_err(|_| BundleError::WrongLength("PublicKey"))
}

fn signature_value(value: &OwnedTlv) -> Result<Signature, BundleError> {
	Signature::try_from(value.value.as_slice()).map_err(|()| BundleError::WrongLength("Signature"))
}

pub(crate) fn identity(
	address_tlv: &OwnedTlv,
	public_key_tlv: Option<&OwnedTlv>,
	resolver: &dyn KeyResolver,
) -> Result<Identity, BundleError> {
	let address = address_value(address_tlv)?;
	let public_key = if address.is_anonymous() {
		public_key_tlv
			.ok_or(BundleError::Missing("PublicKey for anonymous address"))
			.and_then(public_key_value)?
	} else {
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
	unknown_children: UnknownChildren,
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
			_ if unknown_children == UnknownChildren::Reject => {
				return Err(BundleError::Unexpected("unknown SignedTLV child"));
			}
			_ => {}
		}
	}
	let signed_data = signed_data.ok_or(BundleError::Missing("SignedData"))?;
	let signature = signature.ok_or(BundleError::Missing("Signature"))?;
	Ok((origin, public_key, signed_data, signature))
}

fn verify_signed_tlv_with_policy(
	value: &OwnedTlv,
	inherited: Option<&Identity>,
	resolver: &dyn KeyResolver,
	unknown_children: UnknownChildren,
) -> Result<VerifiedSignedTlv, BundleError> {
	let (origin_tlv, public_key_tlv, signed_data, signature_tlv) =
		signed_tlv_parts(value, unknown_children)?;
	let identity = if let Some(origin_tlv) = origin_tlv.as_ref() {
		identity(origin_tlv, public_key_tlv.as_ref(), resolver)?
	} else {
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

pub fn verify_signed_tlv(
	value: &OwnedTlv,
	inherited: Option<&Identity>,
	resolver: &dyn KeyResolver,
) -> Result<VerifiedSignedTlv, BundleError> {
	verify_signed_tlv_with_policy(value, inherited, resolver, UnknownChildren::Allow)
}

pub fn unauthenticated_signed_data(value: &OwnedTlv) -> Result<Vec<OwnedTlv>, BundleError> {
	let (_, _, signed_data, _) = signed_tlv_parts(value, UnknownChildren::Allow)?;
	parse_sequence(&signed_data.value).map_err(Into::into)
}

pub(crate) fn concatenate(values: &[OwnedTlv]) -> Vec<u8> {
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
		children.push(OwnedTlv {
			type_code: types::ORIGIN,
			value: origin.address.to_string().into_bytes(),
		});
		if origin.address.is_anonymous() {
			children.push(OwnedTlv {
				type_code: types::PUBLIC_KEY,
				value: origin.public_key.as_bytes().to_vec(),
			});
		}
	}
	children.push(OwnedTlv {
		type_code: types::SIGNED_DATA,
		value: data_bytes,
	});
	children.push(OwnedTlv {
		type_code: types::SIGNATURE,
		value: signature.as_bytes().to_vec(),
	});
	Ok(OwnedTlv {
		type_code: types::SIGNED_TLV,
		value: concatenate(&children),
	})
}

#[cfg(test)]
mod tests {
	use tith_crypto::{SIGNATURE_BYTES, SigningKeyPair};

	use super::*;

	fn signed_children(data: &[OwnedTlv], keys: &SigningKeyPair) -> Vec<OwnedTlv> {
		let signed = build_signed_tlv(data, None, &keys.secret).unwrap();
		parse_sequence(&signed.value).unwrap()
	}

	#[test]
	fn signed_tlv_carries_an_anonymous_origin_key_and_unknown_extension() {
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
		assert!(matches!(
			verify_signed_tlv_with_policy(
				&signed,
				None,
				&|_: &Address| None,
				UnknownChildren::Reject,
			),
			Err(BundleError::Unexpected("unknown SignedTLV child"))
		));
	}

	#[test]
	fn anonymous_origin_and_key_must_be_adjacent() {
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
	fn signed_container_rejects_each_invalid_defined_ordering() {
		let keys = SigningKeyPair::from_seed(&[30; 32]).unwrap();
		let data = [OwnedTlv::new(200, Vec::new()).unwrap()];
		let valid = signed_children(&data, &keys);
		for children in [
			vec![valid[1].clone(), valid[0].clone()],
			vec![valid[0].clone(), valid[0].clone(), valid[1].clone()],
			vec![valid[0].clone()],
			vec![valid[1].clone()],
		] {
			let signed = OwnedTlv::new(types::SIGNED_TLV, concatenate(&children)).unwrap();
			assert!(verify_signed_tlv(&signed, None, &|_: &Address| None).is_err());
		}
	}

	#[test]
	fn signed_container_requires_an_origin_source_and_exact_signature_length() {
		let keys = SigningKeyPair::from_seed(&[31; 32]).unwrap();
		let data = [OwnedTlv::new(200, Vec::new()).unwrap()];
		let signed = build_signed_tlv(&data, None, &keys.secret).unwrap();
		assert!(matches!(
			verify_signed_tlv(&signed, None, &|_: &Address| None),
			Err(BundleError::Missing("applicable Origin"))
		));

		let identity = Identity {
			address: "fidonet#1/2".parse().unwrap(),
			public_key: keys.public,
		};
		let mut children = parse_sequence(&signed.value).unwrap();
		children[1].value.pop();
		let malformed = OwnedTlv::new(types::SIGNED_TLV, concatenate(&children)).unwrap();
		assert!(matches!(
			verify_signed_tlv(&malformed, Some(&identity), &|_: &Address| None),
			Err(BundleError::WrongLength("Signature"))
		));
	}

	#[test]
	fn non_anonymous_origin_uses_only_the_resolver_key() {
		let keys = SigningKeyPair::from_seed(&[32; 32]).unwrap();
		let origin = Identity {
			address: "fidonet#1/2".parse().unwrap(),
			public_key: keys.public,
		};
		let data = [OwnedTlv::new(200, Vec::new()).unwrap()];
		let signed = build_signed_tlv(&data, Some(&origin), &keys.secret).unwrap();
		let verified = verify_signed_tlv(&signed, None, &|address: &Address| {
			(address == &origin.address).then_some(keys.public)
		})
		.unwrap();
		assert_eq!(verified.identity, origin);

		let mut children = parse_sequence(&signed.value).unwrap();
		children.insert(
			1,
			OwnedTlv::new(types::PUBLIC_KEY, keys.public.as_bytes().to_vec()).unwrap(),
		);
		let malformed = OwnedTlv::new(types::SIGNED_TLV, concatenate(&children)).unwrap();
		assert!(matches!(
			verify_signed_tlv(&malformed, None, &|_: &Address| Some(keys.public)),
			Err(BundleError::Unexpected(
				"PublicKey after non-anonymous Origin"
			))
		));
	}

	#[test]
	fn unauthenticated_access_checks_structure_but_not_signature() {
		let keys = SigningKeyPair::from_seed(&[33; 32]).unwrap();
		let data = [OwnedTlv::new(200, b"opaque".to_vec()).unwrap()];
		let mut signed = build_signed_tlv(&data, None, &keys.secret).unwrap();
		*signed.value.last_mut().unwrap() ^= 1;
		assert_eq!(unauthenticated_signed_data(&signed).unwrap(), data);
		assert!(matches!(
			unauthenticated_signed_data(&OwnedTlv::new(200, Vec::new()).unwrap()),
			Err(BundleError::Unexpected("non-SignedTLV"))
		));
	}

	#[test]
	fn malformed_common_values_fail_at_their_exact_boundary() {
		let keys = SigningKeyPair::from_seed(&[34; 32]).unwrap();
		let no_key = |_: &Address| None;

		let invalid_utf8 = OwnedTlv::new(types::ORIGIN, vec![0xff]).unwrap();
		assert!(matches!(
			identity(&invalid_utf8, None, &no_key),
			Err(BundleError::InvalidUtf8)
		));
		let invalid_address = OwnedTlv::new(types::ORIGIN, b"not-an-address".to_vec()).unwrap();
		assert!(matches!(
			identity(&invalid_address, None, &no_key),
			Err(BundleError::Address(_))
		));

		let anonymous = OwnedTlv::new(types::ORIGIN, b"p2p#-1".to_vec()).unwrap();
		assert!(matches!(
			identity(&anonymous, None, &no_key),
			Err(BundleError::Missing("PublicKey for anonymous address"))
		));
		let short_key = OwnedTlv::new(types::PUBLIC_KEY, vec![0; 31]).unwrap();
		assert!(matches!(
			identity(&anonymous, Some(&short_key), &no_key),
			Err(BundleError::WrongLength("PublicKey"))
		));

		let ordinary = OwnedTlv::new(types::ORIGIN, b"fidonet#1/2".to_vec()).unwrap();
		assert!(matches!(
			identity(&ordinary, None, &no_key),
			Err(BundleError::UnknownKey(_))
		));

		let malformed_children = OwnedTlv::new(types::SIGNED_TLV, vec![0, 0]).unwrap();
		assert!(matches!(
			verify_signed_tlv(&malformed_children, None, &no_key),
			Err(BundleError::Framing(_))
		));

		let malformed_data = vec![0, 0];
		let signature = sign_tlv(&malformed_data, &keys.secret).unwrap();
		let signed = OwnedTlv::new(
			types::SIGNED_TLV,
			concatenate(&[
				OwnedTlv::new(types::SIGNED_DATA, malformed_data).unwrap(),
				OwnedTlv::new(types::SIGNATURE, signature.as_bytes().to_vec()).unwrap(),
			]),
		)
		.unwrap();
		let inherited = Identity {
			address: "fidonet#1/2".parse().unwrap(),
			public_key: keys.public,
		};
		assert!(matches!(
			verify_signed_tlv(&signed, Some(&inherited), &no_key),
			Err(BundleError::Framing(_))
		));
		assert!(matches!(
			unauthenticated_signed_data(&signed),
			Err(BundleError::Framing(_))
		));
	}
}
