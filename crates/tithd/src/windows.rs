//! TSP-0010 Windows named-pipe service binding.

// The Win32 API is expressed entirely in raw pointers. Keeping ordinary
// borrows at the call sites makes this audited FFI boundary easier to read.
#![allow(clippy::borrow_as_ptr)]

use std::error::Error;
use std::ffi::c_void;
use std::io;
use std::mem::{size_of, zeroed};
use std::path::Path;
use std::ptr::null_mut;
use std::sync::Arc;

use tith_ipc::{Document, DocumentFramer, EnvelopeKind};
use tith_wire::integer::{MAX_U64_BYTES, decode_u64, encode_u64};
use windows_sys::Win32::Foundation::{
	CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_PIPE_CONNECTED, FILETIME, GetLastError, HANDLE,
	INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
	ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
	EqualSid, GetTokenInformation, RevertToSelf, SECURITY_ATTRIBUTES, SecurityImpersonation,
	TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER, TokenImpersonationLevel, TokenSessionId,
	TokenStatistics, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
	FlushFileBuffers, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows_sys::Win32::System::Pipes::{
	ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
	GetNamedPipeClientSessionId, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
	PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
	GetCurrentThread, GetProcessTimes, OpenProcess, OpenProcessToken, OpenThreadToken,
	PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::ipc::{IpcService, Principal};
use crate::submission::SubmissionEngine;

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

struct LocalSecurityDescriptor(*mut c_void);

impl Drop for LocalSecurityDescriptor {
	fn drop(&mut self) {
		if !self.0.is_null() {
			// SAFETY: ConvertStringSecurityDescriptor allocated this value with LocalAlloc.
			unsafe { LocalFree(self.0) };
		}
	}
}

pub fn serve(
	pipe_name: &str,
	database: &Path,
	exports: &Path,
	application: &str,
	submission: Option<Arc<SubmissionEngine>>,
) -> Result<(), Box<dyn Error>> {
	if !pipe_name.starts_with(r"\\.\pipe\") {
		return Err("named pipe must begin with \\\\.\\pipe\\".into());
	}
	let mut service = IpcService::create(database, exports)?;
	if let Some(submission) = submission {
		service = service.with_submission(submission);
	}
	let name: Vec<u16> = pipe_name.encode_utf16().chain([0]).collect();
	loop {
		if let Err(error) = listen_once(&name, &service, application) {
			eprintln!("tithd: named-pipe transaction failed: {error}");
		}
	}
}

fn listen_once(
	name: &[u16],
	service: &IpcService,
	application: &str,
) -> Result<(), Box<dyn Error>> {
	let pipe = create_pipe(name)?;
	let connected = unsafe { ConnectNamedPipe(pipe.0, null_mut()) };
	if connected == 0 && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
		return Err(io::Error::last_os_error().into());
	}
	let result = transaction(pipe.0, service, application);
	// SAFETY: pipe is a connected named-pipe server handle and remains owned here.
	unsafe { DisconnectNamedPipe(pipe.0) };
	result
}

fn create_pipe(name: &[u16]) -> Result<OwnedHandle, Box<dyn Error>> {
	// A protected DACL grants full access only to LocalSystem and the object owner.
	let sddl: Vec<u16> = "D:P(A;;GA;;;SY)(A;;GA;;;OW)"
		.encode_utf16()
		.chain([0])
		.collect();
	let mut descriptor = null_mut();
	if unsafe {
		ConvertStringSecurityDescriptorToSecurityDescriptorW(
			sddl.as_ptr(),
			SDDL_REVISION_1,
			&mut descriptor,
			null_mut(),
		)
	} == 0
	{
		return Err(io::Error::last_os_error().into());
	}
	let descriptor = LocalSecurityDescriptor(descriptor);
	let attributes = SECURITY_ATTRIBUTES {
		nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())?,
		lpSecurityDescriptor: descriptor.0,
		bInheritHandle: 0,
	};
	let handle = unsafe {
		CreateNamedPipeW(
			name.as_ptr(),
			PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
			PIPE_UNLIMITED_INSTANCES,
			65_536,
			65_536,
			0,
			&attributes,
		)
	};
	if handle == INVALID_HANDLE_VALUE {
		return Err(io::Error::last_os_error().into());
	}
	Ok(OwnedHandle(handle))
}

fn transaction(
	pipe: HANDLE,
	service: &IpcService,
	application: &str,
) -> Result<(), Box<dyn Error>> {
	let mut magic = [0; 8];
	read_exact(pipe, &mut magic)?;
	if magic != *REQUEST_MAGIC {
		return Err("invalid named-pipe request preamble".into());
	}
	let creation = read_integer(pipe)?;
	let handle_count = read_integer(pipe)?;
	if handle_count != 0 {
		return Err("native request handles are not enabled".into());
	}
	let identity = authenticate_client(pipe, creation)?;
	let request = read_document(pipe, EnvelopeKind::Request)?;
	let principal = Principal::single(identity, application);
	let response = service.process_request(&request, Some(&principal));
	write_all(pipe, RESULT_MAGIC)?;
	write_all(pipe, &encode_u64(0))?;
	let mut acknowledgement = [0];
	read_exact(pipe, &mut acknowledgement)?;
	if acknowledgement != *b"A" {
		return Err("invalid named-pipe result acknowledgement".into());
	}
	write_all(pipe, &response)?;
	if unsafe { FlushFileBuffers(pipe) } == 0 {
		return Err(io::Error::last_os_error().into());
	}
	Ok(())
}

fn authenticate_client(pipe: HANDLE, expected_creation: u64) -> Result<String, Box<dyn Error>> {
	if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
		return Err(io::Error::last_os_error().into());
	}
	let result = authenticated_client(pipe, expected_creation);
	if unsafe { RevertToSelf() } == 0 {
		// Continuing in an untrusted caller's context is never recoverable.
		std::process::abort();
	}
	result
}

fn authenticated_client(pipe: HANDLE, expected_creation: u64) -> Result<String, Box<dyn Error>> {
	let mut thread_token = null_mut();
	if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut thread_token) } == 0 {
		return Err(io::Error::last_os_error().into());
	}
	let thread_token = OwnedHandle(thread_token);
	let level: i32 = token_value(thread_token.0, TokenImpersonationLevel)?;
	if level < SecurityImpersonation {
		return Err("named-pipe client did not permit impersonation".into());
	}
	let mut process_id = 0;
	let mut pipe_session = 0;
	if unsafe { GetNamedPipeClientProcessId(pipe, &mut process_id) } == 0
		|| unsafe { GetNamedPipeClientSessionId(pipe, &mut pipe_session) } == 0
	{
		return Err(io::Error::last_os_error().into());
	}
	let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
	if process.is_null() {
		return Err(io::Error::last_os_error().into());
	}
	let process = OwnedHandle(process);
	let mut process_token = null_mut();
	if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut process_token) } == 0 {
		return Err(io::Error::last_os_error().into());
	}
	let process_token = OwnedHandle(process_token);
	let mut creation: FILETIME = unsafe { zeroed() };
	let mut exit: FILETIME = unsafe { zeroed() };
	let mut kernel: FILETIME = unsafe { zeroed() };
	let mut user: FILETIME = unsafe { zeroed() };
	if unsafe { GetProcessTimes(process.0, &mut creation, &mut exit, &mut kernel, &mut user) } == 0
	{
		return Err(io::Error::last_os_error().into());
	}
	let actual_creation =
		u64::from(creation.dwLowDateTime) | (u64::from(creation.dwHighDateTime) << 32);
	if actual_creation != expected_creation {
		return Err("named-pipe client process was replaced".into());
	}
	let thread_user = token_buffer(thread_token.0, TokenUser)?;
	let process_user = token_buffer(process_token.0, TokenUser)?;
	let thread_sid = unsafe { (*(thread_user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
	let client_process_sid = unsafe { (*(process_user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
	if unsafe { EqualSid(thread_sid, client_process_sid) } == 0 {
		return Err("pipe and process token users differ".into());
	}
	let thread_stats: TOKEN_STATISTICS = token_value(thread_token.0, TokenStatistics)?;
	let process_stats: TOKEN_STATISTICS = token_value(process_token.0, TokenStatistics)?;
	if thread_stats.AuthenticationId.LowPart != process_stats.AuthenticationId.LowPart
		|| thread_stats.AuthenticationId.HighPart != process_stats.AuthenticationId.HighPart
	{
		return Err("pipe and process logon identities differ".into());
	}
	let thread_session: u32 = token_value(thread_token.0, TokenSessionId)?;
	let process_session: u32 = token_value(process_token.0, TokenSessionId)?;
	let mut pid_session = 0;
	if unsafe { ProcessIdToSessionId(process_id, &mut pid_session) } == 0 {
		return Err(io::Error::last_os_error().into());
	}
	if thread_session != process_session
		|| process_session != pipe_session
		|| pipe_session != pid_session
	{
		return Err("named-pipe client sessions differ".into());
	}
	Ok(format!(
		"windows-logon:{}:{}",
		thread_stats.AuthenticationId.HighPart, thread_stats.AuthenticationId.LowPart
	))
}

fn token_buffer(token: HANDLE, class: i32) -> Result<Vec<usize>, Box<dyn Error>> {
	let mut bytes = 0;
	unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut bytes) };
	if bytes == 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
		return Err(io::Error::last_os_error().into());
	}
	let words = usize::try_from(bytes)?.div_ceil(size_of::<usize>());
	let mut buffer = vec![0_usize; words];
	if unsafe { GetTokenInformation(token, class, buffer.as_mut_ptr().cast(), bytes, &mut bytes) }
		== 0
	{
		return Err(io::Error::last_os_error().into());
	}
	Ok(buffer)
}

fn token_value<T: Copy>(token: HANDLE, class: i32) -> Result<T, Box<dyn Error>> {
	let buffer = token_buffer(token, class)?;
	if buffer.len() * size_of::<usize>() < size_of::<T>() {
		return Err("short token information".into());
	}
	Ok(unsafe { buffer.as_ptr().cast::<T>().read() })
}

fn read_document(pipe: HANDLE, kind: EnvelopeKind) -> Result<Vec<u8>, Box<dyn Error>> {
	let mut document = Vec::new();
	let mut line = Vec::new();
	let mut framer = DocumentFramer::new(kind);
	loop {
		let mut byte = [0];
		read_exact(pipe, &mut byte)?;
		document.push(byte[0]);
		line.push(byte[0]);
		if byte[0] == b'\n' && framer.push(&line)? {
			Document::parse(&document, kind)?;
			return Ok(document);
		}
		if byte[0] == b'\n' {
			line.clear();
		}
	}
}

fn read_integer(pipe: HANDLE) -> Result<u64, Box<dyn Error>> {
	let mut encoded = [0; MAX_U64_BYTES];
	for index in 0..MAX_U64_BYTES {
		read_exact(pipe, &mut encoded[index..=index])?;
		if encoded[index] & 0x80 == 0 {
			return Ok(decode_u64(&encoded[..=index])?);
		}
	}
	Err("named-pipe integer overflow".into())
}

fn read_exact(pipe: HANDLE, mut output: &mut [u8]) -> io::Result<()> {
	while !output.is_empty() {
		let length = u32::try_from(output.len()).unwrap_or(u32::MAX);
		let mut read = 0;
		if unsafe { ReadFile(pipe, output.as_mut_ptr(), length, &mut read, null_mut()) } == 0 {
			return Err(io::Error::last_os_error());
		}
		if read == 0 {
			return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
		}
		output = &mut output[usize::try_from(read).expect("u32 fits usize")..];
	}
	Ok(())
}

fn write_all(pipe: HANDLE, mut input: &[u8]) -> io::Result<()> {
	while !input.is_empty() {
		let length = u32::try_from(input.len()).unwrap_or(u32::MAX);
		let mut written = 0;
		if unsafe { WriteFile(pipe, input.as_ptr(), length, &mut written, null_mut()) } == 0 {
			return Err(io::Error::last_os_error());
		}
		if written == 0 {
			return Err(io::Error::from(io::ErrorKind::WriteZero));
		}
		input = &input[usize::try_from(written).expect("u32 fits usize")..];
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;
	use std::ptr::null;
	use std::time::{SystemTime, UNIX_EPOCH};
	use windows_sys::Win32::Foundation::GENERIC_ALL;
	use windows_sys::Win32::Storage::FileSystem::{
		CreateFileW, OPEN_EXISTING, SECURITY_IMPERSONATION, SECURITY_SQOS_PRESENT,
	};
	use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};
	use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId};

	#[test]
	fn carries_a_complete_authenticated_transaction() {
		let unique = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_nanos();
		let pipe_name = format!(r"\\.\pipe\tith-test-{unique}");
		let wide: Vec<u16> = pipe_name.encode_utf16().chain([0]).collect();
		let root = std::env::temp_dir().join(format!("tith-pipe-{unique}"));
		fs::create_dir_all(&root).unwrap();
		let service = IpcService::create(&root.join("state.redb"), &root.join("exports")).unwrap();
		let server_name = wide.clone();
		let server =
			std::thread::spawn(move || listen_once(&server_name, &service, "tosser").unwrap());
		assert_ne!(unsafe { WaitNamedPipeW(wide.as_ptr(), 30_000) }, 0);
		let raw = unsafe {
			CreateFileW(
				wide.as_ptr(),
				GENERIC_ALL,
				0,
				null(),
				OPEN_EXISTING,
				SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
				null_mut(),
			)
		};
		assert_ne!(raw, INVALID_HANDLE_VALUE);
		let pipe = OwnedHandle(raw);
		let mut server_pid = 0;
		assert_ne!(
			unsafe { GetNamedPipeServerProcessId(pipe.0, &mut server_pid) },
			0
		);
		assert_eq!(server_pid, unsafe { GetCurrentProcessId() });
		let mut creation: FILETIME = unsafe { zeroed() };
		let mut exit: FILETIME = unsafe { zeroed() };
		let mut kernel: FILETIME = unsafe { zeroed() };
		let mut user: FILETIME = unsafe { zeroed() };
		assert_ne!(
			unsafe {
				GetProcessTimes(
					GetCurrentProcess(),
					&mut creation,
					&mut exit,
					&mut kernel,
					&mut user,
				)
			},
			0
		);
		let creation =
			u64::from(creation.dwLowDateTime) | (u64::from(creation.dwHighDateTime) << 32);
		write_all(pipe.0, REQUEST_MAGIC).unwrap();
		write_all(pipe.0, &encode_u64(creation)).unwrap();
		write_all(pipe.0, &encode_u64(0)).unwrap();
		write_all(pipe.0, b"TITH-IPC 1\nCapabilities\nEnd\n").unwrap();
		let mut result_magic = [0; 8];
		read_exact(pipe.0, &mut result_magic).unwrap();
		assert_eq!(result_magic, *RESULT_MAGIC);
		assert_eq!(read_integer(pipe.0).unwrap(), 0);
		write_all(pipe.0, b"A").unwrap();
		let result = read_document(pipe.0, EnvelopeKind::Result).unwrap();
		assert!(
			String::from_utf8(result)
				.unwrap()
				.contains("Capabilities Completed")
		);
		drop(pipe);
		server.join().unwrap();
		fs::remove_dir_all(root).unwrap();
	}
}
