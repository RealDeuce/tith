use std::env;
use std::path::{Path, PathBuf};

const LIBHYDROGEN: &str = "vendor/libhydrogen";

fn main() {
	let source = Path::new(LIBHYDROGEN);
	let header = source.join("hydrogen.h");
	let implementation = source.join("hydrogen.c");

	println!("cargo:rerun-if-changed={LIBHYDROGEN}");
	println!("cargo:rerun-if-changed=vendor/libhydrogen.UPSTREAM");

	cc::Build::new()
		.file(&implementation)
		.flag_if_supported("-fomit-frame-pointer")
		.opt_level(3)
		.compile("hydrogen");

	let bindings = bindgen::Builder::default()
		.header(header.to_string_lossy())
		.allowlist_function("hydro_.*")
		.allowlist_function("randombytes_.*")
		.allowlist_type("hydro_.*")
		.allowlist_type("randombytes_.*")
		.allowlist_var("HYDRO_.*")
		.allowlist_var("hydro_.*")
		.allowlist_var("randombytes_.*")
		.size_t_is_usize(true)
		.derive_copy(true)
		.derive_debug(true)
		.derive_default(true)
		.derive_eq(true)
		.layout_tests(true)
		.prepend_enum_name(true)
		.generate()
		.expect("unable to generate the pinned Libhydrogen bindings");

	let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
	bindings
		.write_to_file(output.join("libhydrogen_bindings.rs"))
		.expect("unable to write the pinned Libhydrogen bindings");
}
