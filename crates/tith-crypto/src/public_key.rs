//! Fixed-size Libhydrogen signing public keys from TTS-0004.

use libhydrogen_sys as hydro;

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
