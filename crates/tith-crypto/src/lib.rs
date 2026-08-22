//! Safe, TITH-specific access to libhydrogen.
//!
//! This is the only protocol crate permitted to call the C API.  Context
//! strings are intentionally private so callers cannot accidentally sign a
//! TITH value with the wrong domain separation.

#![allow(unsafe_code)]

use std::fmt;
use std::mem::MaybeUninit;
use std::sync::OnceLock;

use libhydrogen_sys as hydro;

mod public_key;

pub use public_key::{PUBLIC_KEY_BYTES, PublicKey};

pub const SECRET_KEY_BYTES: usize = hydro::hydro_sign_SECRETKEYBYTES as usize;
pub const SIGNATURE_BYTES: usize = hydro::hydro_sign_BYTES as usize;
pub const HASH_BYTES: usize = hydro::hydro_hash_BYTES as usize;
pub const KX_PUBLIC_KEY_BYTES: usize = hydro::hydro_kx_PUBLICKEYBYTES as usize;
pub const KX_SECRET_KEY_BYTES: usize = hydro::hydro_kx_SECRETKEYBYTES as usize;
pub const KX_PACKET_BYTES: usize = hydro::hydro_kx_KK_PACKET1BYTES as usize;
pub const SESSION_KEY_BYTES: usize = hydro::hydro_kx_SESSIONKEYBYTES as usize;
pub const SECRETBOX_HEADER_BYTES: usize = hydro::hydro_secretbox_HEADERBYTES as usize;

const SIGN_TLV_CONTEXT: &[u8; 8] = b"SignTLV\0";
const HASH_TLV_CONTEXT: &[u8; 8] = b"HashTLV\0";
const INBOUND_ITEM_CONTEXT: &[u8; 8] = b"InItem1\0";
const SUBMISSION_JOB_CONTEXT: &[u8; 8] = b"SubJob1\0";
const SUBMISSION_FILE_CONTEXT: &[u8; 8] = b"SubFile\0";
const TITH_IPC_CONTEXT: &[u8; 8] = b"TITHIPC\0";

static INITIALIZED: OnceLock<bool> = OnceLock::new();

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

fn initialize() -> Result<(), CryptoError> {
	let initialized = INITIALIZED.get_or_init(|| {
		// SAFETY: hydro_init has no arguments and libhydrogen documents it as
		// safe to call more than once. OnceLock nevertheless calls it once.
		unsafe { hydro::hydro_init() == 0 }
	});
	if *initialized {
		Ok(())
	} else {
		Err(CryptoError::Initialization)
	}
}

pub struct SecretKey([u8; SECRET_KEY_BYTES]);

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
		let bytes: [u8; PUBLIC_KEY_BYTES] = self.0[SECRET_KEY_BYTES - PUBLIC_KEY_BYTES..]
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TlvHash([u8; HASH_BYTES]);

impl TlvHash {
	#[must_use]
	pub const fn from_bytes(bytes: [u8; HASH_BYTES]) -> Self {
		Self(bytes)
	}

	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; HASH_BYTES] {
		&self.0
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
		if result != 0 {
			return Err(CryptoError::Operation);
		}
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
		if result == 0 {
			Ok(())
		} else {
			Err(CryptoError::Operation)
		}
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
		if result == 0 {
			Ok(Signature(signature))
		} else {
			Err(CryptoError::Operation)
		}
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

pub struct TlvHasher {
	state: hydro::hydro_hash_state,
}

impl TlvHasher {
	pub fn new() -> Result<Self, CryptoError> {
		Self::with_context(HASH_TLV_CONTEXT)
	}

	fn with_context(context: &[u8; 8]) -> Result<Self, CryptoError> {
		initialize()?;
		let mut state = MaybeUninit::<hydro::hydro_hash_state>::uninit();
		// SAFETY: output storage and the fixed context are valid; a null key
		// selects unkeyed hashing.
		let result = unsafe {
			hydro::hydro_hash_init(
				state.as_mut_ptr(),
				context.as_ptr().cast(),
				std::ptr::null(),
			)
		};
		if result != 0 {
			return Err(CryptoError::Operation);
		}
		// SAFETY: a successful call initialized state.
		Ok(Self {
			state: unsafe { state.assume_init() },
		})
	}

	pub fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
		// SAFETY: both pointers remain valid for the duration of the call.
		let result = unsafe {
			hydro::hydro_hash_update(&mut self.state, bytes.as_ptr().cast(), bytes.len())
		};
		if result == 0 {
			Ok(())
		} else {
			Err(CryptoError::Operation)
		}
	}

	pub fn finish(mut self) -> Result<TlvHash, CryptoError> {
		let mut hash = [0; HASH_BYTES];
		// SAFETY: output has exactly the requested length.
		let result =
			unsafe { hydro::hydro_hash_final(&mut self.state, hash.as_mut_ptr(), hash.len()) };
		if result == 0 {
			Ok(TlvHash(hash))
		} else {
			Err(CryptoError::Operation)
		}
	}
}

pub fn hash_tlv(bytes: &[u8]) -> Result<TlvHash, CryptoError> {
	let mut hasher = TlvHasher::new()?;
	hasher.update(bytes)?;
	hasher.finish()
}

pub fn hash_inbound_item(bytes: &[u8]) -> Result<TlvHash, CryptoError> {
	let mut hasher = TlvHasher::with_context(INBOUND_ITEM_CONTEXT)?;
	hasher.update(bytes)?;
	hasher.finish()
}

pub fn hash_submission_job(bytes: &[u8]) -> Result<TlvHash, CryptoError> {
	let mut hasher = TlvHasher::with_context(SUBMISSION_JOB_CONTEXT)?;
	hasher.update(bytes)?;
	hasher.finish()
}

pub fn hash_submission_file(bytes: &[u8]) -> Result<TlvHash, CryptoError> {
	let mut hasher = TlvHasher::with_context(SUBMISSION_FILE_CONTEXT)?;
	hasher.update(bytes)?;
	hasher.finish()
}

pub fn random_bytes(bytes: &mut [u8]) -> Result<(), CryptoError> {
	initialize()?;
	// SAFETY: the output slice is valid and writable for its length.
	unsafe { hydro::hydro_random_buf(bytes.as_mut_ptr().cast(), bytes.len()) };
	Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KxPublicKey([u8; KX_PUBLIC_KEY_BYTES]);

impl KxPublicKey {
	#[must_use]
	pub const fn from_bytes(bytes: [u8; KX_PUBLIC_KEY_BYTES]) -> Self {
		Self(bytes)
	}

	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; KX_PUBLIC_KEY_BYTES] {
		&self.0
	}
}

pub struct KxSecretKey([u8; KX_SECRET_KEY_BYTES]);

impl KxSecretKey {
	#[must_use]
	pub const fn from_bytes(bytes: [u8; KX_SECRET_KEY_BYTES]) -> Self {
		Self(bytes)
	}

	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; KX_SECRET_KEY_BYTES] {
		&self.0
	}
}

impl Drop for KxSecretKey {
	fn drop(&mut self) {
		// SAFETY: the pointer and length describe self's live byte array.
		unsafe { hydro::hydro_memzero(self.0.as_mut_ptr().cast(), self.0.len()) };
	}
}

pub struct KxKeyPair {
	pub public: KxPublicKey,
	pub secret: KxSecretKey,
}

struct RawKxKeyPair(hydro::hydro_kx_keypair);

impl Drop for RawKxKeyPair {
	fn drop(&mut self) {
		// SAFETY: the pointer and length cover this live temporary keypair.
		unsafe {
			hydro::hydro_memzero(
				std::ptr::from_mut(&mut self.0).cast(),
				std::mem::size_of_val(&self.0),
			);
		};
	}
}

impl KxKeyPair {
	pub fn generate() -> Result<Self, CryptoError> {
		initialize()?;
		let mut raw = MaybeUninit::<hydro::hydro_kx_keypair>::uninit();
		// SAFETY: libhydrogen initializes the complete keypair.
		unsafe { hydro::hydro_kx_keygen(raw.as_mut_ptr()) };
		// SAFETY: hydro_kx_keygen initialized the value.
		let raw = unsafe { raw.assume_init() };
		Ok(Self {
			public: KxPublicKey(raw.pk),
			secret: KxSecretKey(raw.sk),
		})
	}

	fn as_raw(&self) -> RawKxKeyPair {
		RawKxKeyPair(hydro::hydro_kx_keypair {
			pk: self.public.0,
			sk: self.secret.0,
		})
	}
}

pub struct SessionKey([u8; SESSION_KEY_BYTES]);

impl SessionKey {
	fn from_bytes(bytes: [u8; SESSION_KEY_BYTES]) -> Self {
		Self(bytes)
	}
}

impl Drop for SessionKey {
	fn drop(&mut self) {
		// SAFETY: the pointer and length describe self's live byte array.
		unsafe { hydro::hydro_memzero(self.0.as_mut_ptr().cast(), self.0.len()) };
	}
}

pub struct SessionKeys {
	pub receive: SessionKey,
	pub transmit: SessionKey,
}

fn session_keys(raw: hydro::hydro_kx_session_keypair) -> SessionKeys {
	SessionKeys {
		receive: SessionKey::from_bytes(raw.rx),
		transmit: SessionKey::from_bytes(raw.tx),
	}
}

pub struct KkInitiator {
	state: hydro::hydro_kx_state,
}

impl KkInitiator {
	pub fn start(
		local: &KxKeyPair,
		peer: &KxPublicKey,
	) -> Result<(Self, [u8; KX_PACKET_BYTES]), CryptoError> {
		initialize()?;
		let local = local.as_raw();
		let mut state = MaybeUninit::<hydro::hydro_kx_state>::uninit();
		let mut packet = [0; KX_PACKET_BYTES];
		// SAFETY: output buffers and fixed-size input keys are valid.
		let result = unsafe {
			hydro::hydro_kx_kk_1(
				state.as_mut_ptr(),
				packet.as_mut_ptr(),
				peer.0.as_ptr(),
				&local.0,
			)
		};
		if result != 0 {
			return Err(CryptoError::Operation);
		}
		// SAFETY: a successful call initialized state.
		Ok((
			Self {
				state: unsafe { state.assume_init() },
			},
			packet,
		))
	}

	pub fn finish(
		mut self,
		packet: &[u8; KX_PACKET_BYTES],
		local: &KxKeyPair,
	) -> Result<SessionKeys, CryptoError> {
		let local = local.as_raw();
		let mut keys = MaybeUninit::<hydro::hydro_kx_session_keypair>::uninit();
		// SAFETY: inputs and output have the sizes required by KK packet 2.
		let result = unsafe {
			hydro::hydro_kx_kk_3(
				&mut self.state,
				keys.as_mut_ptr(),
				packet.as_ptr(),
				&local.0,
			)
		};
		if result != 0 {
			return Err(CryptoError::Operation);
		}
		// SAFETY: a successful call initialized keys.
		Ok(session_keys(unsafe { keys.assume_init() }))
	}
}

pub fn kk_respond(
	packet_one: &[u8; KX_PACKET_BYTES],
	local: &KxKeyPair,
	peer: &KxPublicKey,
) -> Result<(SessionKeys, [u8; KX_PACKET_BYTES]), CryptoError> {
	initialize()?;
	let local = local.as_raw();
	let mut keys = MaybeUninit::<hydro::hydro_kx_session_keypair>::uninit();
	let mut packet_two = [0; KX_PACKET_BYTES];
	// SAFETY: inputs and outputs have the fixed sizes required by KK.
	let result = unsafe {
		hydro::hydro_kx_kk_2(
			keys.as_mut_ptr(),
			packet_two.as_mut_ptr(),
			packet_one.as_ptr(),
			peer.0.as_ptr(),
			&local.0,
		)
	};
	if result != 0 {
		return Err(CryptoError::Operation);
	}
	// SAFETY: a successful call initialized keys.
	Ok((session_keys(unsafe { keys.assume_init() }), packet_two))
}

pub fn encrypt_ipc_line(
	plain: &[u8],
	message_id: u64,
	key: &SessionKey,
) -> Result<Vec<u8>, CryptoError> {
	initialize()?;
	let length = plain
		.len()
		.checked_add(SECRETBOX_HEADER_BYTES)
		.ok_or(CryptoError::LengthOverflow)?;
	let mut cipher = vec![0; length];
	// SAFETY: all pointers are valid for their supplied lengths.
	let result = unsafe {
		hydro::hydro_secretbox_encrypt(
			cipher.as_mut_ptr(),
			plain.as_ptr().cast(),
			plain.len(),
			message_id,
			TITH_IPC_CONTEXT.as_ptr().cast(),
			key.0.as_ptr(),
		)
	};
	if result == 0 {
		Ok(cipher)
	} else {
		Err(CryptoError::Operation)
	}
}

pub fn decrypt_ipc_line(
	cipher: &[u8],
	message_id: u64,
	key: &SessionKey,
) -> Result<Vec<u8>, CryptoError> {
	initialize()?;
	let length = cipher
		.len()
		.checked_sub(SECRETBOX_HEADER_BYTES)
		.ok_or(CryptoError::InvalidCiphertext)?;
	let mut plain = vec![0; length];
	// SAFETY: all pointers are valid for their supplied lengths.
	let result = unsafe {
		hydro::hydro_secretbox_decrypt(
			plain.as_mut_ptr().cast(),
			cipher.as_ptr(),
			cipher.len(),
			message_id,
			TITH_IPC_CONTEXT.as_ptr().cast(),
			key.0.as_ptr(),
		)
	};
	if result == 0 {
		Ok(plain)
	} else {
		Err(CryptoError::InvalidCiphertext)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn deterministic_sign_and_streaming_verify() {
		let keys = SigningKeyPair::from_seed(&[7; 32]).unwrap();
		assert_eq!(keys.secret.public_key(), keys.public);
		let mut signer = TlvSigner::new().unwrap();
		signer.update(b"first").unwrap();
		signer.update(b"second").unwrap();
		let signature = signer.sign(&keys.secret).unwrap();
		assert!(verify_tlv(b"firstsecond", &signature, &keys.public).unwrap());
		assert!(!verify_tlv(b"first-third", &signature, &keys.public).unwrap());
	}

	#[test]
	fn hash_is_stream_independent() {
		let expected = hash_tlv(b"one two three").unwrap();
		let mut hasher = TlvHasher::new().unwrap();
		hasher.update(b"one ").unwrap();
		hasher.update(b"two ").unwrap();
		hasher.update(b"three").unwrap();
		assert_eq!(hasher.finish().unwrap(), expected);
	}

	#[test]
	fn kk_keys_encrypt_in_both_directions() {
		let client = KxKeyPair::generate().unwrap();
		let server = KxKeyPair::generate().unwrap();
		let (state, packet_one) = KkInitiator::start(&client, &server.public).unwrap();
		let (server_keys, packet_two) = kk_respond(&packet_one, &server, &client.public).unwrap();
		let client_keys = state.finish(&packet_two, &client).unwrap();

		let cipher = encrypt_ipc_line(b"Capabilities\n", 0, &client_keys.transmit).unwrap();
		assert_eq!(
			decrypt_ipc_line(&cipher, 0, &server_keys.receive).unwrap(),
			b"Capabilities\n"
		);
		assert!(decrypt_ipc_line(&cipher, 1, &server_keys.receive).is_err());
	}
}
