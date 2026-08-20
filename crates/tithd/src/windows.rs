//! TSP-0010 Windows named-pipe service binding.

// The Win32 API is expressed entirely in raw pointers. Keeping ordinary
// borrows at the call sites makes this audited FFI boundary easier to read.
#![allow(clippy::borrow_as_ptr)]

use std::error::Error;
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::ptr::null_mut;
use std::sync::Arc;

use tith_ipc::{Document, DocumentFramer, EnvelopeKind};
use tith_wire::integer::{MAX_U64_BYTES, decode_u64, encode_u64};
use windows_sys::Win32::Foundation::{
	CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_PIPE_CONNECTED, ERROR_SUCCESS, FILETIME,
	GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
	ConvertSecurityDescriptorToStringSecurityDescriptorW,
	ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
	SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
	DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorDacl, GetTokenInformation,
	PROTECTED_DACL_SECURITY_INFORMATION, RevertToSelf, SECURITY_ATTRIBUTES, SecurityImpersonation,
	TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER, TokenImpersonationLevel, TokenSessionId,
	TokenStatistics, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
	CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, FlushFileBuffers,
	PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
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
			// SAFETY: every constructor holds a value the security descriptor and
			// SDDL conversion calls allocated with LocalAlloc.
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

/// A protected DACL granting full access only to `LocalSystem` and the object
/// owner, and nothing else. This is the Windows spelling of POSIX mode 0600;
/// `create_pipe` builds the same descriptor for the service pipe.
///
/// "P" makes the DACL protected, so nothing is inherited from the containing
/// directory. Without it a key file in a user profile picks up whatever that
/// profile grants.
const OWNER_ONLY: &str = "D:P(A;;FA;;;SY)(A;;FA;;;OW)";

/// Creates a file carrying [`OWNER_ONLY`], failing when it already exists.
pub fn create_owner_only(path: &Path) -> io::Result<File> {
	let name = wide(path.as_os_str());
	let sddl: Vec<u16> = OWNER_ONLY.encode_utf16().chain([0]).collect();
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
		return Err(io::Error::last_os_error());
	}
	let descriptor = LocalSecurityDescriptor(descriptor);
	let attributes = SECURITY_ATTRIBUTES {
		nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).expect("a struct size fits u32"),
		lpSecurityDescriptor: descriptor.0,
		bInheritHandle: 0,
	};
	let handle = unsafe {
		CreateFileW(
			name.as_ptr(),
			GENERIC_WRITE,
			FILE_SHARE_NONE,
			&attributes,
			CREATE_NEW,
			FILE_ATTRIBUTE_NORMAL,
			null_mut(),
		)
	};
	if handle == INVALID_HANDLE_VALUE {
		return Err(io::Error::last_os_error());
	}
	// SAFETY: CreateFileW returned one live handle and this is its only owner.
	Ok(unsafe { File::from_raw_handle(handle) })
}

/// The same protection for an object whose owner should read it but never
/// rewrite it in place.
///
/// "FRSD" is `FILE_GENERIC_READ` and DELETE. The read-only file attribute would
/// be the tempting spelling and is the wrong one: Windows refuses to delete a
/// file carrying it, and the service has to remove an export once its consumer
/// acknowledges.
const OWNER_READ_ONLY: &str = "D:P(A;;FA;;;SY)(A;;FRSD;;;OW)";

/// Applies [`OWNER_ONLY`] to an existing directory.
///
/// A directory is restricted after the fact rather than created with the
/// descriptor, because `create_dir_all` may find it already there — an endpoint
/// root an operator laid down is exactly the case that needs restricting.
pub fn restrict_directory(path: &Path) -> io::Result<()> {
	apply(path, OWNER_ONLY)
}

/// Applies [`OWNER_READ_ONLY`] to an existing file.
pub fn seal_file(path: &Path) -> io::Result<()> {
	apply(path, OWNER_READ_ONLY)
}

/// Replaces the DACL of an existing object, protected so it inherits nothing.
fn apply(path: &Path, sddl: &str) -> io::Result<()> {
	let name = wide(path.as_os_str());
	let text: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
	let mut descriptor = null_mut();
	if unsafe {
		ConvertStringSecurityDescriptorToSecurityDescriptorW(
			text.as_ptr(),
			SDDL_REVISION_1,
			&mut descriptor,
			null_mut(),
		)
	} == 0
	{
		return Err(io::Error::last_os_error());
	}
	let descriptor = LocalSecurityDescriptor(descriptor);
	let mut dacl = null_mut();
	let mut present = 0;
	let mut defaulted = 0;
	if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) }
		== 0
	{
		return Err(io::Error::last_os_error());
	}
	if present == 0 {
		return Err(io::Error::other("the owner-only descriptor has no DACL"));
	}
	let status = unsafe {
		SetNamedSecurityInfoW(
			name.as_ptr(),
			SE_FILE_OBJECT,
			DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
			null_mut(),
			null_mut(),
			dacl,
			null_mut(),
		)
	};
	if status == ERROR_SUCCESS {
		return Ok(());
	}
	Err(io::Error::from_raw_os_error(
		i32::try_from(status).unwrap_or(-1),
	))
}

/// Confirms that `path` still carries exactly [`OWNER_ONLY`].
///
/// This is the counterpart of the POSIX `mode & 0o077` check: it reports a key
/// another account can reach rather than repairing one, because a key which has
/// been readable is already a key which may have been read.
pub fn owner_only_dacl(path: &Path) -> io::Result<()> {
	let stored = dacl(path)?;
	if crate::owner_only::permits_only_owner(&stored) {
		return Ok(());
	}
	Err(io::Error::new(
		io::ErrorKind::PermissionDenied,
		format!(
			"{} is reachable by accounts other than its owner; its DACL is \"{stored}\" and must be \"{OWNER_ONLY}\"",
			path.display()
		),
	))
}

/// The DACL of `path` in SDDL form.
fn dacl(path: &Path) -> io::Result<String> {
	let name = wide(path.as_os_str());
	let mut descriptor = null_mut();
	let status = unsafe {
		GetNamedSecurityInfoW(
			name.as_ptr(),
			SE_FILE_OBJECT,
			DACL_SECURITY_INFORMATION,
			null_mut(),
			null_mut(),
			null_mut(),
			null_mut(),
			&mut descriptor,
		)
	};
	if status != ERROR_SUCCESS {
		return Err(io::Error::from_raw_os_error(
			i32::try_from(status).unwrap_or(-1),
		));
	}
	let descriptor = LocalSecurityDescriptor(descriptor);
	let mut text = null_mut();
	if unsafe {
		ConvertSecurityDescriptorToStringSecurityDescriptorW(
			descriptor.0,
			SDDL_REVISION_1,
			DACL_SECURITY_INFORMATION,
			&mut text,
			null_mut(),
		)
	} == 0
	{
		return Err(io::Error::last_os_error());
	}
	let text = LocalSecurityDescriptor(text.cast());
	// SAFETY: the call above returned one NUL terminated LocalAlloc'd string.
	Ok(unsafe { from_wide(text.0.cast::<u16>()) })
}

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
	value.encode_wide().chain([0]).collect()
}

/// # Safety
///
/// `text` must point at a NUL terminated UTF-16 string.
unsafe fn from_wide(text: *const u16) -> String {
	let mut length = 0;
	// SAFETY: the caller guarantees a NUL terminator bounds this walk.
	while unsafe { *text.add(length) } != 0 {
		length += 1;
	}
	// SAFETY: `length` units precede the NUL the walk above found.
	String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) })
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;
	use std::time::{SystemTime, UNIX_EPOCH};
	use tith_submit::{NamedPipeBinding, check_capabilities, current_user_sid};

	#[test]
	fn carries_a_complete_authenticated_transaction() {
		let unique = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_nanos();
		let pipe_name = format!(r"\\.\pipe\tith-test-{unique}");
		let root = std::env::temp_dir().join(format!("tith-pipe-{unique}"));
		fs::create_dir_all(&root).unwrap();
		let service = IpcService::create(&root.join("state.redb"), &root.join("exports")).unwrap();
		let server_name: Vec<u16> = pipe_name.encode_utf16().chain([0]).collect();
		let server =
			std::thread::spawn(move || listen_once(&server_name, &service, "tosser").unwrap());
		let binding = NamedPipeBinding::new(&pipe_name, &current_user_sid().unwrap()).unwrap();
		check_capabilities(&binding).unwrap();
		server.join().unwrap();
		fs::remove_dir_all(root).unwrap();
	}
}
