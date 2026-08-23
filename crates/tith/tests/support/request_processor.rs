//! Portable FSC-0086.001 request-processor fixture for qualification tests.

use std::fs;
use std::path::PathBuf;

fn main() {
	let srif = std::env::args_os()
		.nth(1)
		.map(PathBuf::from)
		.expect("SRIF argument");
	assert!(std::env::args_os().nth(2).is_none(), "unexpected argument");
	let text = fs::read_to_string(&srif).expect("read SRIF");
	let value = |name: &str| {
		text.lines()
			.find_map(|line| line.strip_prefix(&format!("{name} ")))
			.map(PathBuf::from)
			.unwrap_or_else(|| panic!("missing {name} in SRIF"))
	};
	assert_eq!(
		fs::read_to_string(value("RequestList")).expect("read request list"),
		"fidonet-nodelist.zst\n"
	);
	let publication = srif
		.parent()
		.expect("SRIF directory")
		.join("fidonet-nodelist.zst");
	fs::write(
		value("ResponseList"),
		format!("+{}\n", publication.to_string_lossy()),
	)
	.expect("write response list");
}
