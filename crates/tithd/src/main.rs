#![forbid(unsafe_code)]

#[cfg(unix)]
mod unix;

use std::error::Error;
use std::fs;
use std::path::Path;

use tith_config::ConfigurationSet;

fn main() {
	if let Err(error) = run() {
		eprintln!("tithd: {error}");
		std::process::exit(1);
	}
}

fn run() -> Result<(), Box<dyn Error>> {
	let mut arguments = std::env::args().skip(1);
	match arguments.next().as_deref() {
		Some("check-config") => {
			let directory = arguments.next().ok_or("usage: tithd check-config DIRECTORY")?;
			if arguments.next().is_some() { return Err("usage: tithd check-config DIRECTORY".into()); }
			load_config(Path::new(&directory))?;
			println!("configuration is valid");
			Ok(())
		}
		#[cfg(unix)]
		Some("serve-unix") => {
			let socket = arguments.next().ok_or("usage: tithd serve-unix SOCKET DATABASE EXPORT-DIRECTORY APPLICATION")?;
			let database = arguments.next().ok_or("usage: tithd serve-unix SOCKET DATABASE EXPORT-DIRECTORY APPLICATION")?;
			let exports = arguments.next().ok_or("usage: tithd serve-unix SOCKET DATABASE EXPORT-DIRECTORY APPLICATION")?;
			let application = arguments.next().ok_or("usage: tithd serve-unix SOCKET DATABASE EXPORT-DIRECTORY APPLICATION")?;
			if arguments.next().is_some() { return Err("usage: tithd serve-unix SOCKET DATABASE EXPORT-DIRECTORY APPLICATION".into()); }
			unix::serve(Path::new(&socket), Path::new(&database), Path::new(&exports), application)
		}
		_ => Err("usage: tithd check-config DIRECTORY | serve-unix SOCKET DATABASE EXPORT-DIRECTORY APPLICATION".into()),
	}
}

fn load_config(directory: &Path) -> Result<ConfigurationSet, Box<dyn Error>> {
	let read = |name: &str| fs::read_to_string(directory.join(name));
	Ok(ConfigurationSet::parse(
		&read("peers")?,
		&read("routes")?,
		&read("areas")?,
		&read("schedules")?,
	)?)
}
