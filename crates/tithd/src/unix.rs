use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;

use nix::unistd::{Uid, geteuid};

use crate::ipc::{IpcService, Principal};
use crate::submission::SubmissionEngine;

pub fn serve(
	socket: &Path,
	database: &Path,
	exports: &Path,
	application: String,
	submission: Option<Arc<SubmissionEngine>>,
) -> Result<(), Box<dyn Error>> {
	if socket.exists() {
		return Err("refusing to replace an existing socket path".into());
	}
	let listener = UnixListener::bind(socket)?;
	fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
	let mut service = IpcService::create(database, exports)?;
	if let Some(submission) = submission {
		service = service.with_submission(submission);
	}
	let service = Arc::new(service);
	let principal = Arc::new(Principal::single(
		format!("uid:{}", geteuid().as_raw()),
		application,
	));
	for connection in listener.incoming() {
		match connection {
			Ok(stream) => {
				let service = Arc::clone(&service);
				let principal = Arc::clone(&principal);
				std::thread::spawn(move || {
					if let Err(error) = transaction(&stream, &service, &principal) {
						eprintln!("tithd: IPC transaction failed: {error}");
					}
				});
			}
			Err(error) => eprintln!("tithd: accept failed: {error}"),
		}
	}
	Ok(())
}

fn transaction(
	mut stream: &UnixStream,
	service: &IpcService,
	principal: &Principal,
) -> Result<(), Box<dyn Error>> {
	let authorized = peer_uid(stream)? == geteuid();
	let request = read_request(&mut stream)?;
	let response = service.process_request(&request, authorized.then_some(principal));
	stream.write_all(&response)?;
	stream.flush()?;
	Ok(())
}

#[cfg(any(
	target_os = "freebsd",
	target_os = "dragonfly",
	target_os = "macos",
	target_os = "ios",
	target_os = "netbsd",
	target_os = "openbsd"
))]
fn peer_uid(stream: &UnixStream) -> Result<Uid, Box<dyn Error>> {
	Ok(nix::unistd::getpeereid(stream)?.0)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_uid(stream: &UnixStream) -> Result<Uid, Box<dyn Error>> {
	use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
	Ok(Uid::from_raw(getsockopt(stream, PeerCredentials)?.uid()))
}

#[cfg(not(any(
	target_os = "freebsd",
	target_os = "dragonfly",
	target_os = "macos",
	target_os = "ios",
	target_os = "netbsd",
	target_os = "openbsd",
	target_os = "linux",
	target_os = "android"
)))]
fn peer_uid(_: &UnixStream) -> Result<Uid, Box<dyn Error>> {
	Err("this Unix platform has no implemented peer-credential binding".into())
}

pub(crate) fn read_request(stream: &mut &UnixStream) -> Result<Vec<u8>, Box<dyn Error>> {
	let mut request = Vec::new();
	let mut byte = [0_u8; 1];
	loop {
		let count = stream.read(&mut byte)?;
		if count == 0 {
			return Err("connection ended before final End".into());
		}
		request.push(byte[0]);
		if request.ends_with(b"\nEnd\n") {
			return Ok(request);
		}
	}
}
