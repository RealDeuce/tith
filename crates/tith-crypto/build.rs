use std::path::Path;

const LIBHYDROGEN: &str = "vendor/libhydrogen";

fn main() {
	let source = Path::new(LIBHYDROGEN);
	let implementation = source.join("hydrogen.c");

	println!("cargo:rerun-if-changed={LIBHYDROGEN}");
	println!("cargo:rerun-if-changed=vendor/libhydrogen.UPSTREAM");

	cc::Build::new()
		.file(&implementation)
		.flag_if_supported("-fomit-frame-pointer")
		.opt_level(3)
		.compile("hydrogen");
}
