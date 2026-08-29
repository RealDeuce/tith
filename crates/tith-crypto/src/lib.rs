//! Safe, TITH-specific access to libhydrogen.
//!
//! This is the only protocol crate permitted to call the C API.  Context
//! strings are intentionally private so callers cannot accidentally sign a
//! TITH value with the wrong domain separation.

#![allow(unsafe_code)]

use std::mem::MaybeUninit;

mod hash;
mod public_key;
mod raw;
mod signature;

use raw as hydro;

pub use hash::{
	TlvHash, TlvHasher, hash_inbound_item, hash_submission_file, hash_submission_job, hash_tlv,
};
pub use public_key::{PUBLIC_KEY_BYTES, PublicKey};
use signature::initialize;
pub use signature::{
	CryptoError, SECRET_KEY_BYTES, SIGNATURE_BYTES, SecretKey, Signature, SigningKeyPair,
	TlvSigner, sign_tlv, verify_tlv,
};

pub const HASH_BYTES: usize = hydro::hydro_hash_BYTES as usize;
pub const KX_PUBLIC_KEY_BYTES: usize = hydro::hydro_kx_PUBLICKEYBYTES as usize;
pub const KX_SECRET_KEY_BYTES: usize = hydro::hydro_kx_SECRETKEYBYTES as usize;
pub const KX_PACKET_BYTES: usize = hydro::hydro_kx_KK_PACKET1BYTES as usize;
pub const SESSION_KEY_BYTES: usize = hydro::hydro_kx_SESSIONKEYBYTES as usize;
pub const SECRETBOX_HEADER_BYTES: usize = hydro::hydro_secretbox_HEADERBYTES as usize;

const TITH_IPC_CONTEXT: &[u8; 8] = b"TITHIPC\0";

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

	fn hex<const N: usize>(encoded: &str) -> [u8; N] {
		assert_eq!(encoded.len(), N * 2);
		let mut bytes = [0; N];
		for (index, byte) in bytes.iter_mut().enumerate() {
			*byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).unwrap();
		}
		bytes
	}

	fn pinned_kx_keys() -> (KxKeyPair, KxKeyPair) {
		let client = KxKeyPair {
			public: KxPublicKey::from_bytes(hex(
				"2f12b6f411373a823e1a9d14b25323f917564ae00035cce5ccb7a778f4684b5e",
			)),
			secret: KxSecretKey::from_bytes(hex(
				"a25e12a4eeb53d096d9a2d2f92ecf05e44d81f6e42c61a9804002779bcd439df",
			)),
		};
		let server = KxKeyPair {
			public: KxPublicKey::from_bytes(hex(
				"d1724f0b3728b5c4917c955c8003f9cc337dcac2b4acc1ef070f8bf0d4cd237d",
			)),
			secret: KxSecretKey::from_bytes(hex(
				"8caae477be9d31fd195c237f44cbec9246bd8d4526c6648989741c33bb039385",
			)),
		};
		(client, server)
	}

	#[test]
	fn hash_final_accepts_zero_length_state_finalization() {
		initialize().unwrap();
		let mut state = MaybeUninit::<hydro::hydro_hash_state>::uninit();
		let context = b"HashTLV\0";
		// SAFETY: state is valid output storage and context has eight bytes.
		assert_eq!(
			unsafe {
				hydro::hydro_hash_init(
					state.as_mut_ptr(),
					context.as_ptr().cast(),
					std::ptr::null(),
				)
			},
			0
		);
		// SAFETY: initialization succeeded and a null output is valid when the
		// requested output length is zero in the pinned profile.
		assert_eq!(
			unsafe { hydro::hydro_hash_final(state.as_mut_ptr(), std::ptr::null_mut(), 0) },
			0
		);
	}

	#[test]
	fn accepts_a_packet_from_the_pinned_external_kk_initiator() {
		let (client, server) = pinned_kx_keys();
		let packet = hex::<KX_PACKET_BYTES>(
			"8788f97243bb415742d75cfaa6a9d8630fd3649e15dac99226d2040549333e2a\
			 01d0e7b273a9c2648cd4370f728d0991"
				.replace(' ', "")
				.as_str(),
		);
		assert!(kk_respond(&packet, &server, &client.public).is_ok());
	}

	#[test]
	fn decrypts_the_pinned_external_secretbox_vector() {
		let key = SessionKey::from_bytes(hex(
			"8caae477be9d31fd195c237f44cbec9246bd8d4526c6648989741c33bb039385",
		));
		let cipher = hex::<49>(
			"28f151837402b8d91d71831880db432228981e0ac3986ba8362b097e1be9618b\
			 62c97bbe955470380d09bc2f7dacf0c731"
				.replace(' ', "")
				.as_str(),
		);
		assert_eq!(
			decrypt_ipc_line(&cipher, 0, &key).unwrap(),
			b"Capabilities\n"
		);
		assert!(decrypt_ipc_line(&cipher, 1, &key).is_err());
		let mut altered = cipher;
		altered[SECRETBOX_HEADER_BYTES] ^= 1;
		assert!(decrypt_ipc_line(&altered, 0, &key).is_err());
	}

	#[test]
	fn safe_and_raw_kk_roles_interoperate() {
		initialize().unwrap();
		let (client, server) = pinned_kx_keys();

		let raw_client = client.as_raw();
		let mut raw_state = MaybeUninit::<hydro::hydro_kx_state>::uninit();
		let mut packet_one = [0; KX_PACKET_BYTES];
		// SAFETY: every pointer refers to a correctly sized live value.
		assert_eq!(
			unsafe {
				hydro::hydro_kx_kk_1(
					raw_state.as_mut_ptr(),
					packet_one.as_mut_ptr(),
					server.public.0.as_ptr(),
					&raw_client.0,
				)
			},
			0
		);
		let (safe_server_keys, packet_two) =
			kk_respond(&packet_one, &server, &client.public).unwrap();
		let mut raw_client_keys = MaybeUninit::<hydro::hydro_kx_session_keypair>::uninit();
		// SAFETY: kk_1 initialized state and all remaining values have the
		// exact sizes required by kk_3.
		assert_eq!(
			unsafe {
				hydro::hydro_kx_kk_3(
					raw_state.as_mut_ptr(),
					raw_client_keys.as_mut_ptr(),
					packet_two.as_ptr(),
					&raw_client.0,
				)
			},
			0
		);
		// SAFETY: kk_3 succeeded and initialized both session keys.
		let raw_client_keys = unsafe { raw_client_keys.assume_init() };
		assert_eq!(raw_client_keys.tx, safe_server_keys.receive.0);
		assert_eq!(raw_client_keys.rx, safe_server_keys.transmit.0);

		let (safe_state, packet_one) = KkInitiator::start(&client, &server.public).unwrap();
		let raw_server = server.as_raw();
		let mut raw_server_keys = MaybeUninit::<hydro::hydro_kx_session_keypair>::uninit();
		let mut packet_two = [0; KX_PACKET_BYTES];
		// SAFETY: every pointer refers to a correctly sized live value.
		assert_eq!(
			unsafe {
				hydro::hydro_kx_kk_2(
					raw_server_keys.as_mut_ptr(),
					packet_two.as_mut_ptr(),
					packet_one.as_ptr(),
					client.public.0.as_ptr(),
					&raw_server.0,
				)
			},
			0
		);
		// SAFETY: kk_2 succeeded and initialized both session keys.
		let raw_server_keys = unsafe { raw_server_keys.assume_init() };
		let safe_client_keys = safe_state.finish(&packet_two, &client).unwrap();
		assert_eq!(safe_client_keys.transmit.0, raw_server_keys.rx);
		assert_eq!(safe_client_keys.receive.0, raw_server_keys.tx);
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
