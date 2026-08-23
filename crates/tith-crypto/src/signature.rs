//! Libhydrogen signing values and the TTS-0003 `SignTLV` operation.

use std::fmt;
use std::mem::MaybeUninit;
use std::sync::OnceLock;

use libhydrogen_sys as hydro;

use crate::PublicKey;

pub const SECRET_KEY_BYTES: usize = hydro::hydro_sign_SECRETKEYBYTES as usize;
pub const SIGNATURE_BYTES: usize = hydro::hydro_sign_BYTES as usize;

const SIGN_TLV_CONTEXT: &[u8; 8] = b"SignTLV\0";

static INITIALIZED: OnceLock<Result<(), CryptoError>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
	Initialization,
	Operation,
	InvalidCiphertext,
	LengthOverflow,
}

impl fmt::Display for CryptoError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Self::Initialization => "libhydrogen initialization failed",
			Self::Operation => "libhydrogen operation failed",
			Self::InvalidCiphertext => "ciphertext authentication failed",
			Self::LengthOverflow => "ciphertext length overflow",
		})
	}
}

impl std::error::Error for CryptoError {}

fn operation_result(result: i32, error: CryptoError) -> Result<(), CryptoError> {
	if result == 0 { Ok(()) } else { Err(error) }
}

pub(crate) fn initialize() -> Result<(), CryptoError> {
	*INITIALIZED.get_or_init(|| {
		// SAFETY: hydro_init has no arguments and libhydrogen documents it as
		// safe to call more than once. OnceLock nevertheless calls it once.
		operation_result(unsafe { hydro::hydro_init() }, CryptoError::Initialization)
	})
}

pub struct SecretKey(pub(crate) [u8; SECRET_KEY_BYTES]);

impl SecretKey {
	#[must_use]
	pub const fn from_bytes(bytes: [u8; SECRET_KEY_BYTES]) -> Self {
		Self(bytes)
	}

	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; SECRET_KEY_BYTES] {
		&self.0
	}

	/// Returns the public half which libhydrogen stores in a signing secret.
	#[must_use]
	pub fn public_key(&self) -> PublicKey {
		let bytes: [u8; crate::PUBLIC_KEY_BYTES] = self.0
			[SECRET_KEY_BYTES - crate::PUBLIC_KEY_BYTES..]
			.try_into()
			.expect("libhydrogen signing-key sizes are fixed");
		PublicKey::from_bytes(bytes)
	}
}

impl Drop for SecretKey {
	fn drop(&mut self) {
		// SAFETY: the pointer and length describe self's live byte array.
		unsafe { hydro::hydro_memzero(self.0.as_mut_ptr().cast(), self.0.len()) };
	}
}

impl fmt::Debug for SecretKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("SecretKey([REDACTED])")
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature([u8; SIGNATURE_BYTES]);

impl Signature {
	#[must_use]
	pub const fn from_bytes(bytes: [u8; SIGNATURE_BYTES]) -> Self {
		Self(bytes)
	}

	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; SIGNATURE_BYTES] {
		&self.0
	}
}

impl TryFrom<&[u8]> for Signature {
	type Error = ();

	fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
		Ok(Self(value.try_into().map_err(|_| ())?))
	}
}

#[derive(Debug)]
pub struct SigningKeyPair {
	pub public: PublicKey,
	pub secret: SecretKey,
}

impl SigningKeyPair {
	pub fn generate() -> Result<Self, CryptoError> {
		initialize()?;
		let mut raw = MaybeUninit::<hydro::hydro_sign_keypair>::uninit();
		// SAFETY: libhydrogen initializes the complete keypair.
		unsafe { hydro::hydro_sign_keygen(raw.as_mut_ptr()) };
		// SAFETY: hydro_sign_keygen initialized the value.
		let raw = unsafe { raw.assume_init() };
		Ok(Self {
			public: PublicKey::from_bytes(raw.pk),
			secret: SecretKey(raw.sk),
		})
	}

	pub fn from_seed(seed: &[u8; 32]) -> Result<Self, CryptoError> {
		initialize()?;
		let mut raw = MaybeUninit::<hydro::hydro_sign_keypair>::uninit();
		// SAFETY: seed has exactly hydro_sign_SEEDBYTES bytes and the output
		// pointer is valid for the complete keypair.
		unsafe { hydro::hydro_sign_keygen_deterministic(raw.as_mut_ptr(), seed.as_ptr()) };
		// SAFETY: hydro_sign_keygen_deterministic initialized the value.
		let raw = unsafe { raw.assume_init() };
		Ok(Self {
			public: PublicKey::from_bytes(raw.pk),
			secret: SecretKey(raw.sk),
		})
	}
}

pub struct TlvSigner {
	state: hydro::hydro_sign_state,
}

impl TlvSigner {
	pub fn new() -> Result<Self, CryptoError> {
		initialize()?;
		let mut state = MaybeUninit::<hydro::hydro_sign_state>::uninit();
		// SAFETY: state is valid output storage and context is exactly eight
		// bytes including its NUL.
		let result =
			unsafe { hydro::hydro_sign_init(state.as_mut_ptr(), SIGN_TLV_CONTEXT.as_ptr().cast()) };
		operation_result(result, CryptoError::Operation)?;
		// SAFETY: a successful call initialized state.
		Ok(Self {
			state: unsafe { state.assume_init() },
		})
	}

	pub fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
		// SAFETY: both pointers remain valid for the duration of the call.
		let result = unsafe {
			hydro::hydro_sign_update(&mut self.state, bytes.as_ptr().cast(), bytes.len())
		};
		operation_result(result, CryptoError::Operation)
	}

	pub fn sign(mut self, secret: &SecretKey) -> Result<Signature, CryptoError> {
		let mut signature = [0; SIGNATURE_BYTES];
		// SAFETY: all pointers describe correctly sized live values.
		let result = unsafe {
			hydro::hydro_sign_final_create(
				&mut self.state,
				signature.as_mut_ptr(),
				secret.0.as_ptr(),
			)
		};
		operation_result(result, CryptoError::Operation)?;
		Ok(Signature(signature))
	}

	pub fn verify(
		mut self,
		signature: &Signature,
		public: &PublicKey,
	) -> Result<bool, CryptoError> {
		// SAFETY: all pointers describe correctly sized live values.
		let result = unsafe {
			hydro::hydro_sign_final_verify(
				&mut self.state,
				signature.0.as_ptr(),
				public.as_bytes().as_ptr(),
			)
		};
		Ok(result == 0)
	}
}

pub fn sign_tlv(bytes: &[u8], secret: &SecretKey) -> Result<Signature, CryptoError> {
	let mut signer = TlvSigner::new()?;
	signer.update(bytes)?;
	signer.sign(secret)
}

pub fn verify_tlv(
	bytes: &[u8],
	signature: &Signature,
	public: &PublicKey,
) -> Result<bool, CryptoError> {
	let mut verifier = TlvSigner::new()?;
	verifier.update(bytes)?;
	verifier.verify(signature, public)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn deterministic_signing_and_streaming_verification_cover_the_exact_context() {
		let keys = SigningKeyPair::from_seed(&[7; 32]).unwrap();
		assert_eq!(keys.secret.public_key(), keys.public);
		assert_eq!(format!("{:?}", keys.secret), "SecretKey([REDACTED])");
		let mut signer = TlvSigner::new().unwrap();
		signer.update(b"first").unwrap();
		signer.update(b"second").unwrap();
		let signature = signer.sign(&keys.secret).unwrap();
		assert!(verify_tlv(b"firstsecond", &signature, &keys.public).unwrap());
		assert!(!verify_tlv(b"first-third", &signature, &keys.public).unwrap());
		assert_eq!(
			Signature::try_from(signature.as_bytes().as_slice()).unwrap(),
			signature
		);
		assert!(Signature::try_from(&signature.as_bytes()[..63]).is_err());
	}

	#[test]
	fn generated_and_imported_keys_use_the_signing_key_sizes() {
		let generated = SigningKeyPair::generate().unwrap();
		assert_eq!(generated.secret.public_key(), generated.public);
		let imported = SecretKey::from_bytes(*generated.secret.as_bytes());
		assert_eq!(imported.public_key(), generated.public);
	}

	#[test]
	fn native_results_and_every_public_error_are_distinct() {
		assert_eq!(operation_result(0, CryptoError::Operation), Ok(()));
		assert_eq!(
			operation_result(-1, CryptoError::Operation),
			Err(CryptoError::Operation)
		);
		for (error, text) in [
			(
				CryptoError::Initialization,
				"libhydrogen initialization failed",
			),
			(CryptoError::Operation, "libhydrogen operation failed"),
			(
				CryptoError::InvalidCiphertext,
				"ciphertext authentication failed",
			),
			(CryptoError::LengthOverflow, "ciphertext length overflow"),
		] {
			assert_eq!(error.to_string(), text);
		}
	}
}
