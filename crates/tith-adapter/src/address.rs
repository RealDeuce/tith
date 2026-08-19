//! Mapping between TTS-0004 addresses and their legacy forms.
//!
//! A native address is `domain#zone:net/node.point` with defaulted components
//! omitted. The legacy forms are the FTS-5006 5D `zone:net/node[.point]@domain`,
//! the FTS-0001 3D `zone:net/node` used by INTL, and the four unsigned 16-bit
//! fields a packet header carries.

use std::fmt;

use tith_message_legacy::Endpoint;
use tith_wire::Address;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AddressError {
	/// The unlisted address has no legacy representation at all: its zone, net,
	/// and node are all -1, which no legacy field can hold.
	Unlisted,
	/// A component does not fit the unsigned 16-bit legacy field.
	OutOfRange,
	/// Not a legacy address.
	Malformed,
}

impl fmt::Display for AddressError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Self::Unlisted => "the unlisted address has no legacy representation",
			Self::OutOfRange => "an address component does not fit its legacy field",
			Self::Malformed => "not a legacy address",
		})
	}
}

impl std::error::Error for AddressError {}

/// The FTS-5006 5D form `zone:net/node[.point]@domain`.
///
/// TSP-0003 section 9 requires this form with no omitted zone, net, or node,
/// which is the opposite of the native form's omit-the-default rule.
pub fn five_dimensional(address: &Address) -> Result<String, AddressError> {
	let parts = components(address)?;
	let point = if parts.point == 0 {
		String::new()
	} else {
		format!(".{}", parts.point)
	};
	Ok(format!(
		"{}:{}/{}{point}@{}",
		parts.zone,
		parts.net,
		parts.node,
		address.domain()
	))
}

/// The FTS-0001 3D form `zone:net/node`, which INTL carries.
pub fn three_dimensional(address: &Address) -> Result<String, AddressError> {
	let parts = components(address)?;
	Ok(format!("{}:{}/{}", parts.zone, parts.net, parts.node))
}

/// The packet header fields for an address.
pub fn endpoint(address: &Address) -> Result<Endpoint, AddressError> {
	components(address)
}

fn components(address: &Address) -> Result<Endpoint, AddressError> {
	if address.is_unlisted() {
		return Err(AddressError::Unlisted);
	}
	let field = |value: i32| u16::try_from(value).map_err(|_| AddressError::OutOfRange);
	Ok(Endpoint {
		zone: field(address.zone())?,
		net: field(address.net())?,
		node: field(address.node())?,
		point: address.point(),
	})
}

/// Reads a 5D legacy address back into its native form.
///
/// The domain is required: a packet has no domain field, so a bare 4D address
/// is only meaningful with the trusted context which supplies one, and this
/// refuses rather than guessing. Use [`with_domain`] for that case.
pub fn from_five_dimensional(value: &str) -> Result<Address, AddressError> {
	let (address, domain) = value.rsplit_once('@').ok_or(AddressError::Malformed)?;
	with_domain(address, domain)
}

/// Reads a 3D or 4D legacy address under a trusted domain.
pub fn with_domain(value: &str, domain: &str) -> Result<Address, AddressError> {
	let (zone, rest) = value.split_once(':').ok_or(AddressError::Malformed)?;
	let (net, rest) = rest.split_once('/').ok_or(AddressError::Malformed)?;
	let (node, point) = match rest.split_once('.') {
		Some((node, point)) => (node, Some(point)),
		None => (rest, None),
	};
	let number = |text: &str| -> Result<i32, AddressError> {
		if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
			return Err(AddressError::Malformed);
		}
		text.parse().map_err(|_| AddressError::OutOfRange)
	};
	let point = match point {
		Some(text) => u16::try_from(number(text)?).map_err(|_| AddressError::OutOfRange)?,
		None => 0,
	};
	Address::new(
		domain.to_owned(),
		number(zone)?,
		number(net)?,
		number(node)?,
		point,
	)
	.map_err(|_| AddressError::OutOfRange)
}

/// The native address for a packet header endpoint under a trusted domain.
pub fn from_endpoint(endpoint: Endpoint, domain: &str) -> Result<Address, AddressError> {
	Address::new(
		domain.to_owned(),
		i32::from(endpoint.zone),
		i32::from(endpoint.net),
		i32::from(endpoint.node),
		endpoint.point,
	)
	.map_err(|_| AddressError::OutOfRange)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn address(text: &str) -> Address {
		text.parse().unwrap()
	}

	#[test]
	fn legacy_forms_never_omit_a_component() {
		// The native form omits net when it equals zone and node when it is zero;
		// the legacy forms must state all three.
		let bare = address("fidonet#1");
		assert_eq!(five_dimensional(&bare).unwrap(), "1:1/0@fidonet");
		assert_eq!(three_dimensional(&bare).unwrap(), "1:1/0");

		let point = address("fidonet#1:104/36.45");
		assert_eq!(five_dimensional(&point).unwrap(), "1:104/36.45@fidonet");
		assert_eq!(three_dimensional(&point).unwrap(), "1:104/36");
		assert_eq!(
			endpoint(&point).unwrap(),
			Endpoint {
				zone: 1,
				net: 104,
				node: 36,
				point: 45
			}
		);
	}

	#[test]
	fn every_listed_address_round_trips() {
		for text in [
			"fidonet#1:104/36",
			"fidonet#1:104/36.45",
			"fidonet#1",
			// Net equal to zone is omitted in the canonical native form and must
			// still be stated in the legacy one.
			"fidonet#32767/32767",
			"BBSDev#885:1/1",
		] {
			let native = address(text);
			let legacy = five_dimensional(&native).unwrap();
			assert_eq!(from_five_dimensional(&legacy).unwrap(), native, "{legacy}");
			assert_eq!(
				from_endpoint(endpoint(&native).unwrap(), native.domain()).unwrap(),
				native,
				"{text}"
			);
		}
	}

	#[test]
	fn the_unlisted_address_has_no_legacy_form() {
		let unlisted = Address::unlisted("p2p".to_owned()).unwrap();
		assert_eq!(five_dimensional(&unlisted), Err(AddressError::Unlisted));
		assert_eq!(three_dimensional(&unlisted), Err(AddressError::Unlisted));
		assert_eq!(endpoint(&unlisted), Err(AddressError::Unlisted));
	}

	#[test]
	fn refuses_a_malformed_legacy_address() {
		for text in ["1:104/36", "", "@fidonet", "1:104@fidonet", "x:y/z@fidonet"] {
			assert!(from_five_dimensional(text).is_err(), "{text}");
		}
		// A domain containing "@" still resolves, because the split is from the
		// right and a domain may not contain "#" but may contain other bytes.
		assert!(with_domain("1:104/36", "fidonet").is_ok());
	}
}
