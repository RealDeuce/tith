//! Private minimal ABI for the Libhydrogen snapshot owned by TTS-0020.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(unsafe_code)]

use std::ffi::{c_char, c_int, c_void};

pub const hydro_hash_BYTES: usize = 32;
pub const hydro_secretbox_HEADERBYTES: usize = 36;
pub const hydro_sign_BYTES: usize = 64;
pub const hydro_sign_PUBLICKEYBYTES: usize = 32;
pub const hydro_sign_SECRETKEYBYTES: usize = 64;
pub const hydro_kx_SESSIONKEYBYTES: usize = 32;
pub const hydro_kx_PUBLICKEYBYTES: usize = 32;
pub const hydro_kx_SECRETKEYBYTES: usize = 32;
pub const hydro_kx_KK_PACKET1BYTES: usize = 48;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct hydro_hash_state {
	pub state: [u32; 12],
	pub buf_off: u8,
	pub align: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct hydro_sign_state {
	pub hash_st: hydro_hash_state,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct hydro_sign_keypair {
	pub pk: [u8; hydro_sign_PUBLICKEYBYTES],
	pub sk: [u8; hydro_sign_SECRETKEYBYTES],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct hydro_kx_keypair {
	pub pk: [u8; hydro_kx_PUBLICKEYBYTES],
	pub sk: [u8; hydro_kx_SECRETKEYBYTES],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct hydro_kx_session_keypair {
	pub rx: [u8; hydro_kx_SESSIONKEYBYTES],
	pub tx: [u8; hydro_kx_SESSIONKEYBYTES],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct hydro_kx_state {
	pub eph_kp: hydro_kx_keypair,
	pub h_st: hydro_hash_state,
}

const _: [(); 52] = [(); size_of::<hydro_hash_state>()];
const _: [(); 4] = [(); align_of::<hydro_hash_state>()];
const _: [(); 96] = [(); size_of::<hydro_sign_keypair>()];
const _: [(); 64] = [(); size_of::<hydro_kx_keypair>()];
const _: [(); 64] = [(); size_of::<hydro_kx_session_keypair>()];
const _: [(); 116] = [(); size_of::<hydro_kx_state>()];
const _: [(); 64] = [(); std::mem::offset_of!(hydro_kx_state, h_st)];

unsafe extern "C" {
	pub fn hydro_init() -> c_int;
	pub fn hydro_random_buf(out: *mut c_void, out_len: usize);
	pub fn hydro_memzero(pointer: *mut c_void, length: usize);

	pub fn hydro_hash_init(
		state: *mut hydro_hash_state,
		context: *const c_char,
		key: *const u8,
	) -> c_int;
	pub fn hydro_hash_update(
		state: *mut hydro_hash_state,
		input: *const c_void,
		input_length: usize,
	) -> c_int;
	pub fn hydro_hash_final(
		state: *mut hydro_hash_state,
		output: *mut u8,
		output_length: usize,
	) -> c_int;

	pub fn hydro_sign_keygen(keypair: *mut hydro_sign_keypair);
	pub fn hydro_sign_keygen_deterministic(keypair: *mut hydro_sign_keypair, seed: *const u8);
	pub fn hydro_sign_init(state: *mut hydro_sign_state, context: *const c_char) -> c_int;
	pub fn hydro_sign_update(
		state: *mut hydro_sign_state,
		message: *const c_void,
		message_length: usize,
	) -> c_int;
	pub fn hydro_sign_final_create(
		state: *mut hydro_sign_state,
		signature: *mut u8,
		secret_key: *const u8,
	) -> c_int;
	pub fn hydro_sign_final_verify(
		state: *mut hydro_sign_state,
		signature: *const u8,
		public_key: *const u8,
	) -> c_int;

	pub fn hydro_kx_keygen(keypair: *mut hydro_kx_keypair);
	pub fn hydro_kx_kk_1(
		state: *mut hydro_kx_state,
		packet_one: *mut u8,
		peer_public_key: *const u8,
		local_keypair: *const hydro_kx_keypair,
	) -> c_int;
	pub fn hydro_kx_kk_2(
		session_keys: *mut hydro_kx_session_keypair,
		packet_two: *mut u8,
		packet_one: *const u8,
		peer_public_key: *const u8,
		local_keypair: *const hydro_kx_keypair,
	) -> c_int;
	pub fn hydro_kx_kk_3(
		state: *mut hydro_kx_state,
		session_keys: *mut hydro_kx_session_keypair,
		packet_two: *const u8,
		local_keypair: *const hydro_kx_keypair,
	) -> c_int;

	pub fn hydro_secretbox_encrypt(
		ciphertext: *mut u8,
		message: *const c_void,
		message_length: usize,
		message_id: u64,
		context: *const c_char,
		key: *const u8,
	) -> c_int;
	pub fn hydro_secretbox_decrypt(
		message: *mut c_void,
		ciphertext: *const u8,
		ciphertext_length: usize,
		message_id: u64,
		context: *const c_char,
		key: *const u8,
	) -> c_int;
}
