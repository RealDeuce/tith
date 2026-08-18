//! TSP-0010 Windows named-pipe client.

#![allow(clippy::borrow_as_ptr)]

use std::ffi::c_void;
use std::io;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};
use std::thread;
use std::time::{Duration, Instant};

use tith_ipc::{DocumentFramer, EnvelopeKind};
use tith_wire::integer::{MAX_U64_BYTES, decode_u64, encode_u64};
use windows_sys::Win32::Foundation::{
	CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_PIPE_BUSY, FILETIME,
	GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{
	EqualSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
	CreateFileW, OPEN_EXISTING, ReadFile, SECURITY_IMPERSONATION, SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};
use windows_sys::Win32::System::Threading::{
	GetCurrentProcess, GetProcessTimes, OpenProcess, OpenProcessToken,
	PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::{Binding, ClientError, validate};

const REQUEST_MAGIC: &[u8; 8] = b"TITHNP01";
const RESULT_MAGIC: &[u8; 8] = b"TITHNR01";

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
	fn drop(&mut self) {
		if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
			// SAFETY: this wrapper owns one live Win32 handle.
			unsafe { CloseHandle(self.0) };
		}
	}
}

struct LocalSid(*mut c_void);

impl Drop for LocalSid {
	fn drop(&mut self) {
		if !self.0.is_null() {
			// SAFETY: ConvertStringSidToSidW allocated this SID with LocalAlloc.
			unsafe { LocalFree(self.0) };
		}
	}
}

pub struct NamedPipeBinding {
	name: Vec<u16>,
	service_sid: Vec<u16>,
}

impl NamedPipeBinding {
	pub fn new(name: &str, service_sid: &str) -> Result<Self, ClientError> {
		if !name.starts_with(r"\\.\pipe\") {
			return Err(ClientError::invalid(
				"named pipe must begin with \\\\.\\pipe\\",
			));
		}
		if service_sid.is_empty() {
			return Err(ClientError::invalid("trusted Service SID is empty"));
		}
		Ok(Self {
			name: name.encode_utf16().chain([0]).collect(),
			service_sid: service_sid.encode_utf16().chain([0]).collect(),
		})
	}
}

impl Binding for NamedPipeBinding {
	fn transact(&self, request: &[u8]) -> Result<Vec<u8>, ClientError> {
		validate(request, EnvelopeKind::Request)?;
		let pipe = connect(&self.name)?;
		authenticate_server(pipe.0, &self.service_sid)?;
		write_all(pipe.0, REQUEST_MAGIC)?;
		write_all(pipe.0, &encode_u64(current_process_creation()?))?;
		write_all(pipe.0, &encode_u64(0))?;
		write_all(pipe.0, request)?;
		let mut result_magic = [0; 8];
		read_exact(pipe.0, &mut result_magic)?;
		if result_magic != *RESULT_MAGIC {
			return Err(ClientError::invalid("invalid named-pipe result preamble"));
		}
		if read_integer(pipe.0)? != 0 {
			return Err(ClientError::invalid(
				"named-pipe result handles are not enabled",
			));
		}
		write_all(pipe.0, b"A")?;
		let result = read_document(pipe.0)?;
		validate(&result, EnvelopeKind::Result)?;
		Ok(result)
	}
}

fn connect(name: &[u16]) -> Result<OwnedHandle, ClientError> {
	let deadline = Instant::now() + Duration::from_secs(30);
	loop {
		let raw = unsafe {
			CreateFileW(
				name.as_ptr(),
				GENERIC_READ | GENERIC_WRITE,
				0,
				null(),
				OPEN_EXISTING,
				SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
				null_mut(),
			)
		};
		if raw != INVALID_HANDLE_VALUE {
			return Ok(OwnedHandle(raw));
		}
		let error = unsafe { GetLastError() };
		if error == ERROR_PIPE_BUSY {
			unsafe { WaitNamedPipeW(name.as_ptr(), 100) };
		} else if error == ERROR_FILE_NOT_FOUND {
			thread::sleep(Duration::from_millis(10));
		} else {
			return Err(io::Error::last_os_error().into());
		}
		if Instant::now() >= deadline {
			return Err(io::Error::new(io::ErrorKind::TimedOut, "named pipe unavailable").into());
		}
	}
}

pub fn current_user_sid() -> Result<String, ClientError> {
	let mut token = null_mut();
	if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
		return Err(io::Error::last_os_error().into());
	}
	let token = OwnedHandle(token);
	let user = token_buffer(token.0)?;
	let sid = unsafe { (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
	let mut text = null_mut();
	if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
		return Err(io::Error::last_os_error().into());
	}
	let text = LocalSid(text.cast());
	let pointer = text.0.cast::<u16>();
	let mut length = 0;
	while unsafe { *pointer.add(length) } != 0 {
		length += 1;
	}
	let value = String::from_utf16(unsafe { std::slice::from_raw_parts(pointer, length) })
		.map_err(ClientError::new)?;
	Ok(value)
}

fn authenticate_server(pipe: HANDLE, expected: &[u16]) -> Result<(), ClientError> {
	let mut process_id = 0;
	if unsafe { GetNamedPipeServerProcessId(pipe, &mut process_id) } == 0 {
		return Err(io::Error::last_os_error().into());
	}
	let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
	if process.is_null() {
		return Err(io::Error::last_os_error().into());
	}
	let process = OwnedHandle(process);
	let mut token = null_mut();
	if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } == 0 {
		return Err(io::Error::last_os_error().into());
	}
	let token = OwnedHandle(token);
	let user = token_buffer(token.0)?;
	let actual = unsafe { (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
	let mut expected_sid = null_mut();
	if unsafe { ConvertStringSidToSidW(expected.as_ptr(), &mut expected_sid) } == 0 {
		return Err(io::Error::last_os_error().into());
	}
	let expected_sid = LocalSid(expected_sid);
	if unsafe { EqualSid(actual, expected_sid.0) } == 0 {
		return Err(ClientError::invalid(
			"named-pipe server has the wrong Windows principal",
		));
	}
	Ok(())
}

fn token_buffer(token: HANDLE) -> Result<Vec<usize>, ClientError> {
	let mut bytes = 0;
	unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut bytes) };
	if bytes == 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
		return Err(io::Error::last_os_error().into());
	}
	let words = usize::try_from(bytes)
		.map_err(ClientError::new)?
		.div_ceil(size_of::<usize>());
	let mut buffer = vec![0_usize; words];
	if unsafe {
		GetTokenInformation(
			token,
			TokenUser,
			buffer.as_mut_ptr().cast(),
			bytes,
			&mut bytes,
		)
	} == 0
	{
		return Err(io::Error::last_os_error().into());
	}
	Ok(buffer)
}

fn current_process_creation() -> Result<u64, ClientError> {
	let mut creation: FILETIME = unsafe { zeroed() };
	let mut exit: FILETIME = unsafe { zeroed() };
	let mut kernel: FILETIME = unsafe { zeroed() };
	let mut user: FILETIME = unsafe { zeroed() };
	if unsafe {
		GetProcessTimes(
			GetCurrentProcess(),
			&mut creation,
			&mut exit,
			&mut kernel,
			&mut user,
		)
	} == 0
	{
		return Err(io::Error::last_os_error().into());
	}
	Ok(u64::from(creation.dwLowDateTime) | (u64::from(creation.dwHighDateTime) << 32))
}

fn read_document(pipe: HANDLE) -> Result<Vec<u8>, ClientError> {
	let mut document = Vec::new();
	let mut line = Vec::new();
	let mut framer = DocumentFramer::new(EnvelopeKind::Result);
	loop {
		let mut byte = [0];
		read_exact(pipe, &mut byte)?;
		document.push(byte[0]);
		line.push(byte[0]);
		if byte[0] == b'\n' && framer.push(&line).map_err(ClientError::new)? {
			return Ok(document);
		}
		if byte[0] == b'\n' {
			line.clear();
		}
	}
}

fn read_integer(pipe: HANDLE) -> Result<u64, ClientError> {
	let mut encoded = [0; MAX_U64_BYTES];
	for index in 0..MAX_U64_BYTES {
		read_exact(pipe, &mut encoded[index..=index])?;
		if encoded[index] & 0x80 == 0 {
			return decode_u64(&encoded[..=index]).map_err(ClientError::new);
		}
	}
	Err(ClientError::invalid("named-pipe integer overflow"))
}

fn read_exact(pipe: HANDLE, mut output: &mut [u8]) -> Result<(), ClientError> {
	while !output.is_empty() {
		let length = u32::try_from(output.len()).unwrap_or(u32::MAX);
		let mut read = 0;
		if unsafe { ReadFile(pipe, output.as_mut_ptr(), length, &mut read, null_mut()) } == 0 {
			return Err(io::Error::last_os_error().into());
		}
		if read == 0 {
			return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
		}
		output = &mut output[usize::try_from(read).expect("u32 fits usize")..];
	}
	Ok(())
}

fn write_all(pipe: HANDLE, mut input: &[u8]) -> Result<(), ClientError> {
	while !input.is_empty() {
		let length = u32::try_from(input.len()).unwrap_or(u32::MAX);
		let mut written = 0;
		if unsafe { WriteFile(pipe, input.as_ptr(), length, &mut written, null_mut()) } == 0 {
			return Err(io::Error::last_os_error().into());
		}
		if written == 0 {
			return Err(io::Error::from(io::ErrorKind::WriteZero).into());
		}
		input = &input[usize::try_from(written).expect("u32 fits usize")..];
	}
	Ok(())
}
