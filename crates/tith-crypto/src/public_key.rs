//! Fixed-size Libhydrogen signing public keys from TTS-0004.

use std::array::TryFromSliceError;

use crate::raw as hydro;

pub const PUBLIC_KEY_BYTES: usize = hydro::hydro_sign_PUBLICKEYBYTES as usize;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PublicKey([u8; PUBLIC_KEY_BYTES]);

impl PublicKey {
	#[must_use]
	pub const fn from_bytes(bytes: [u8; PUBLIC_KEY_BYTES]) -> Self {
		Self(bytes)
	}

	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] {
		&self.0
	}
}

impl<'a> TryFrom<&'a [u8]> for PublicKey {
	type Error = TryFromSliceError;

	fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
		Ok(Self::from_bytes(bytes.try_into()?))
	}
}
