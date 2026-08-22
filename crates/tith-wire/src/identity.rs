//! Node identity semantics from TTS-0004.

use tith_crypto::PublicKey;

use crate::address::Address;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
	pub address: Address,
	pub public_key: PublicKey,
}

impl Identity {
	/// Whether both values identify the same system under TTS-0004.
	///
	/// The effective key remains part of the structural value because other
	/// standards use it for authentication. It distinguishes systems only when
	/// the shared address is anonymous.
	#[must_use]
	pub fn same_system_as(&self, other: &Self) -> bool {
		self.address == other.address
			&& (!self.address.is_anonymous() || self.public_key == other.public_key)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn identity(address: &str, key: u8) -> Identity {
		Identity {
			address: address.parse().unwrap(),
			public_key: PublicKey::from_bytes([key; 32]),
		}
	}

	#[test]
	fn identity_uses_a_key_only_for_an_anonymous_address() {
		assert!(identity("fidonet#1/2", 1).same_system_as(&identity("fidonet#1/2", 2)));
		assert!(!identity("fidonet#1/2", 1).same_system_as(&identity("fidonet#1/3", 1)));
		assert!(identity("p2p#-1", 1).same_system_as(&identity("p2p#-1", 1)));
		assert!(!identity("p2p#-1", 1).same_system_as(&identity("p2p#-1", 2)));
	}
}
