//! `tith netmail` subcommands.

pub(crate) mod submission;

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tith_crypto::random_bytes;
use tith_ipc::EnvelopeKind;
use tith_message_legacy::{AttachStyle, StoredMessage, set_attributes, with_sent};
use tith_submit::{Binding, check_capabilities, validate};
use tith_wire::address::Address;

use submission::{Context, build};

const USAGE: &str = "usage: tith netmail scan (--files ROOT | --tcp ADDRESS CLIENT-PUBLIC CLIENT-SECRET-FILE SERVER-PUBLIC | --unix SOCKET | --named-pipe PIPE SERVICE-SID) --origin LOCAL-IDENTITY [--domain NAME] [--source-offset SECONDS] [--application NAME] [--binkley] [--kill-sent] [--dry-run] [--recover-after SECONDS] DIRECTORY";

/// Marks a message claimed for processing. The suffix deliberately fails the
/// `###.msg` filter so a concurrent scanner's main pass cannot see it.
const CLAIM_PREFIX: &str = ".tith-";

pub fn run(arguments: &mut impl Iterator<Item = String>) -> Result<i32, Box<dyn Error>> {
	match arguments.next().as_deref() {
		Some("scan") => scan(arguments),
		_ => Err(USAGE.into()),
	}
}

struct Options {
	origin: String,
	legacy_origin: Option<String>,
	domain: Option<String>,
	configured_offset: Option<i64>,
	application: String,
	style: AttachStyle,
	kill_sent: bool,
	dry_run: bool,
	recover_after: Duration,
	directory: PathBuf,
}

/// How long a claim must sit untouched before another scanner may take it.
const DEFAULT_RECOVER_AFTER: Duration = Duration::from_mins(10);

fn options(arguments: &mut impl Iterator<Item = String>) -> Result<Options, Box<dyn Error>> {
	let mut origin = None;
	let mut application = "netmail".to_owned();
	let mut domain = None;
	let mut configured_offset = None;
	let mut style = AttachStyle::Flags;
	let mut kill_sent = false;
	let mut dry_run = false;
	let mut recover_after = DEFAULT_RECOVER_AFTER;
	let mut directory = None;
	while let Some(argument) = arguments.next() {
		match argument.as_str() {
			"--origin" => origin = Some(arguments.next().ok_or(USAGE)?),
			"--domain" => domain = Some(arguments.next().ok_or(USAGE)?),
			"--source-offset" => configured_offset = Some(arguments.next().ok_or(USAGE)?.parse()?),
			"--application" => application = arguments.next().ok_or(USAGE)?,
			"--binkley" => style = AttachStyle::Binkley,
			"--kill-sent" => kill_sent = true,
			"--dry-run" => dry_run = true,
			"--recover-after" => {
				recover_after = Duration::from_secs(arguments.next().ok_or(USAGE)?.parse()?);
			}
			value if value.starts_with('-') => return Err(USAGE.into()),
			value if directory.is_none() => directory = Some(PathBuf::from(value)),
			_ => return Err(USAGE.into()),
		}
	}
	let origin = origin.ok_or(USAGE)?;
	Ok(Options {
		legacy_origin: legacy_form(&origin),
		origin,
		domain,
		configured_offset,
		application,
		style,
		kill_sent,
		dry_run,
		recover_after,
		directory: directory.ok_or(USAGE)?,
	})
}

fn scan(arguments: &mut impl Iterator<Item = String>) -> Result<i32, Box<dyn Error>> {
	let binding = tith_submit::cli::binding(arguments, USAGE)?;
	let options = options(arguments)?;
	let features = advertised_features(&binding)?;
	let outcome = sweep(&binding, &options, &features)?;
	println!(
		"tith netmail scan: {} committed, {} failed",
		outcome.committed, outcome.failures
	);
	Ok(i32::from(outcome.failures != 0))
}

#[derive(Default)]
struct Outcome {
	committed: usize,
	failures: usize,
}

/// One complete pass: every `###.msg`, then any leftover claim.
///
/// Generic over the binding so tests can drive it without a service.
fn sweep(
	binding: &impl Binding,
	options: &Options,
	features: &BTreeSet<String>,
) -> Result<Outcome, Box<dyn Error>> {
	let mut outcome = Outcome::default();
	for path in stored_messages(&options.directory)? {
		record(
			&mut outcome,
			&path,
			process(&path, binding, options, features),
		);
	}
	// Recover anything a previous run claimed and did not finish. Submission is
	// idempotent by MSGID, so reprocessing repeats no committed work.
	for path in abandoned_claims(&options.directory, options.recover_after)? {
		record(
			&mut outcome,
			&path,
			recover(&path, binding, options, features),
		);
	}
	Ok(outcome)
}

fn record(outcome: &mut Outcome, path: &Path, result: Result<bool, Box<dyn Error>>) {
	match result {
		Ok(true) => outcome.committed += 1,
		Ok(false) => {}
		Err(error) => {
			outcome.failures += 1;
			eprintln!("tith netmail scan: {}: {error}", path.display());
		}
	}
}

/// Reads the TSP-0004 features the service advertises.
fn advertised_features(binding: &impl Binding) -> Result<BTreeSet<String>, Box<dyn Error>> {
	let result = check_capabilities(binding)?;
	let document = validate(&result, EnvelopeKind::Result)?;
	Ok(document
		.lines
		.iter()
		.filter_map(|line| match line.fields.as_slice() {
			[name, value] if !name.quoted && name.text == "Feature" && value.quoted => {
				Some(value.text.clone())
			}
			_ => None,
		})
		.collect())
}

/// Selects `###.msg`: a non-empty all-digit stem and a case-insensitive `msg`
/// extension. Ordered by stem value so a run is reproducible.
fn stored_messages(directory: &Path) -> io::Result<Vec<PathBuf>> {
	let mut found = Vec::new();
	for entry in fs::read_dir(directory)? {
		let path = entry?.path();
		let (Some(stem), Some(extension)) = (path.file_stem(), path.extension()) else {
			continue;
		};
		let Some(stem) = stem.to_str() else { continue };
		if !extension.eq_ignore_ascii_case("msg") {
			continue;
		}
		if stem.is_empty() || !stem.bytes().all(|byte| byte.is_ascii_digit()) {
			continue;
		}
		if let Ok(number) = stem.parse::<u64>() {
			found.push((number, path));
		}
	}
	found.sort();
	Ok(found.into_iter().map(|(_, path)| path).collect())
}

/// Claims old enough to presume abandoned.
///
/// A claim held by a live scanner is indistinguishable from one left by a
/// crashed one, so age decides, as FTS-5005.003 section 5.1 already does for
/// bsy files: "It is reasonable to ignore and delete bsy files with an age
/// more than the maximum estimated time of session multiplied on 2." Stealing
/// a claim that was actually live costs at most a duplicate submission, and
/// the MSGID key absorbs that by returning Existing.
fn abandoned_claims(directory: &Path, older_than: Duration) -> io::Result<Vec<PathBuf>> {
	let mut found = Vec::new();
	for entry in fs::read_dir(directory)? {
		let entry = entry?;
		let path = entry.path();
		if !path
			.file_name()
			.and_then(|name| name.to_str())
			.is_some_and(|name| name.contains(CLAIM_PREFIX))
		{
			continue;
		}
		let stale = entry
			.metadata()
			.and_then(|metadata| metadata.modified())
			.is_ok_and(|modified| modified.elapsed().is_ok_and(|age| age >= older_than));
		if stale {
			found.push(path);
		}
	}
	found.sort();
	Ok(found)
}

/// Atomically takes exclusive ownership of a message.
///
/// The claim name is derived from the message name rather than random, because
/// the gate is the claim already existing: exactly one racer can create it, and
/// the losers see `AlreadyExists`.
///
/// A rename cannot be that gate. POSIX `rename(2)` is name based, so exactly one
/// racer moves a given name away and the rest get `ENOENT`, but Rust's Windows
/// `fs::rename` opens a handle to the path and then renames the file *object*
/// through `SetFileInformationByHandle`. Eight racers there open eight handles
/// to one file and every rename succeeds, so every racer believes it holds an
/// exclusive claim. An exclusive create has the semantics we actually want and
/// has them on both platforms.
fn claim(path: &Path) -> io::Result<Option<PathBuf>> {
	let name = path
		.file_name()
		.and_then(|name| name.to_str())
		.ok_or_else(|| io::Error::other("message has no usable file name"))?;
	let target = path.with_file_name(format!("{name}{CLAIM_PREFIX}"));
	match fs::hard_link(path, &target) {
		Ok(()) => {
			// The link is the claim. Dropping the original leaves exactly one
			// name, and a crash between the two leaves both pointing at the same
			// contents, which the next pass recovers rather than duplicates.
			fs::remove_file(path)?;
			return Ok(Some(target));
		}
		// Another scanner holds the claim, or took the message away entirely.
		Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(None),
		Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
		// A filesystem without hard links still gets an exclusive create below.
		Err(_) => {}
	}
	let mut file = match fs::OpenOptions::new()
		.create_new(true)
		.write(true)
		.open(&target)
	{
		Ok(file) => file,
		Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(None),
		Err(error) => return Err(error),
	};
	// The name is reserved, so only this racer copies. If the message vanished
	// first the reservation is released again rather than left behind empty.
	let bytes = match fs::read(path) {
		Ok(bytes) => bytes,
		Err(error) if error.kind() == io::ErrorKind::NotFound => {
			drop(file);
			fs::remove_file(&target)?;
			return Ok(None);
		}
		Err(error) => return Err(error),
	};
	io::Write::write_all(&mut file, &bytes)?;
	file.sync_all()?;
	drop(file);
	fs::remove_file(path)?;
	Ok(Some(target))
}

/// Publishes claimed bytes back under a `###.msg` name.
///
/// `hard_link` fails when the destination exists, which makes reserving a name
/// atomic. If the original number was reused while the claim was held, the
/// message takes the lowest free number instead of clobbering a stranger.
fn publish(claimed: &Path, directory: &Path, preferred: Option<&str>) -> io::Result<PathBuf> {
	if let Some(name) = preferred
		&& let Some(path) = place(claimed, &directory.join(name))?
	{
		return Ok(path);
	}
	for number in 1..=u32::MAX {
		if let Some(path) = place(claimed, &directory.join(format!("{number}.msg")))? {
			return Ok(path);
		}
	}
	Err(io::Error::other("no free message number is available"))
}

/// Places the claimed bytes at `candidate`, or reports the name already taken.
///
/// No existence check precedes this: the create is the atomic gate, so a racer
/// that takes the name between a check and a create cannot be clobbered.
fn place(claimed: &Path, candidate: &Path) -> io::Result<Option<PathBuf>> {
	match fs::hard_link(claimed, candidate) {
		Ok(()) => {
			fs::remove_file(claimed)?;
			return Ok(Some(candidate.to_path_buf()));
		}
		Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(None),
		// A filesystem without hard links still gets an atomic reserve below.
		Err(_) => {}
	}
	match fs::OpenOptions::new()
		.create_new(true)
		.write(true)
		.open(candidate)
	{
		Ok(mut file) => {
			use io::Write as _;
			file.write_all(&fs::read(claimed)?)?;
			file.sync_all()?;
			drop(file);
			fs::remove_file(claimed)?;
			Ok(Some(candidate.to_path_buf()))
		}
		Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(None),
		Err(error) => Err(error),
	}
}

/// The original `###.msg` name a claim was taken from.
fn original_name(claimed: &Path) -> Option<String> {
	let name = claimed.file_name()?.to_str()?;
	let (original, _) = name.rsplit_once(CLAIM_PREFIX)?;
	Some(original.to_owned())
}

fn process(
	path: &Path,
	binding: &impl Binding,
	options: &Options,
	features: &BTreeSet<String>,
) -> Result<bool, Box<dyn Error>> {
	if options.dry_run {
		let bytes = fs::read(path)?;
		let message = StoredMessage::parse(&bytes)?;
		// A real run generates this at submission time; a dry run only needs
		// something nonempty, since TSP-0006 forbids an empty key.
		let fallback = generated_key()?;
		let built = build(&message, &context(options, features, path, &fallback))?;
		print!("{}", String::from_utf8_lossy(&built.request));
		return Ok(false);
	}
	let Some(claimed) = claim(path)? else {
		// Another scanner took it first.
		return Ok(false);
	};
	deliver(&claimed, binding, options, features, path.file_name())
}

fn recover(
	claimed: &Path,
	binding: &impl Binding,
	options: &Options,
	features: &BTreeSet<String>,
) -> Result<bool, Box<dyn Error>> {
	if options.dry_run {
		return Ok(false);
	}
	// Re-claim so two scanners cannot recover the same leftover.
	let Some(mine) = claim(claimed)? else {
		return Ok(false);
	};
	let restore = original_name(claimed);
	deliver(
		&mine,
		binding,
		options,
		features,
		restore.as_ref().map(AsRef::as_ref),
	)
}

fn context<'a>(
	options: &'a Options,
	features: &'a BTreeSet<String>,
	claimed: &'a Path,
	fallback_key: &'a str,
) -> Context<'a> {
	Context {
		application: &options.application,
		origin: &options.origin,
		legacy_origin: options.legacy_origin.clone(),
		domain: options.domain.as_deref(),
		configured_offset: options.configured_offset,
		style: options.style,
		features,
		directory: claimed.parent().unwrap_or(Path::new(".")),
		fallback_key,
	}
}

/// Submits a claimed message and applies the outcome to the legacy object.
fn deliver(
	claimed: &Path,
	binding: &impl Binding,
	options: &Options,
	features: &BTreeSet<String>,
	restore: Option<&std::ffi::OsStr>,
) -> Result<bool, Box<dyn Error>> {
	let directory = claimed.parent().unwrap_or(Path::new(".")).to_path_buf();
	let preferred = restore.and_then(|name| name.to_str()).map(str::to_owned);
	let mut bytes = fs::read(claimed)?;
	let message = &match StoredMessage::parse(&bytes) {
		Ok(message) => message,
		Err(error) => {
			publish(claimed, &directory, preferred.as_deref())?;
			return Err(error.into());
		}
	};
	// The Sent bit is what a previous run left behind to say this message has
	// already been submitted. Without this check a republished message is
	// picked up by the next sweep forever.
	if message.has_sent() {
		publish(claimed, &directory, preferred.as_deref())?;
		return Ok(false);
	}
	match submit(message, binding, options, features, &directory) {
		Ok(()) => {
			if options.kill_sent || message.requests_kill() {
				fs::remove_file(claimed)?;
			} else {
				set_attributes(&mut bytes, with_sent(message.attributes))?;
				fs::write(claimed, &bytes)?;
				publish(claimed, &directory, preferred.as_deref())?;
			}
			Ok(true)
		}
		Err(error) => {
			// TSP-0013 forbids retiring a legacy object before a Committed
			// result proves the Job exists, so the message goes back unchanged.
			publish(claimed, &directory, preferred.as_deref())?;
			Err(error)
		}
	}
}

fn submit(
	message: &StoredMessage,
	binding: &impl Binding,
	options: &Options,
	features: &BTreeSet<String>,
	directory: &Path,
) -> Result<(), Box<dyn Error>> {
	let fallback = generated_key()?;
	let built = build(
		message,
		&Context {
			application: &options.application,
			origin: &options.origin,
			legacy_origin: options.legacy_origin.clone(),
			domain: options.domain.as_deref(),
			configured_offset: options.configured_offset,
			style: options.style,
			features,
			directory,
			fallback_key: &fallback,
		},
	)?;
	if built.key_is_generated {
		eprintln!(
			"tith netmail scan: no MSGID, so this submission cannot be deduplicated and an interrupted run may repeat it"
		);
	}
	let result = binding.transact(&built.request)?;
	let document = validate(&result, EnvelopeKind::Result)?;
	let committed = document.lines.first().is_some_and(|line| {
		matches!(line.fields.as_slice(), [operation, status]
			if !operation.quoted
				&& operation.text == "Submit"
				&& !status.quoted
				&& status.text == "Committed")
	});
	if !committed {
		// Naming the key lets an operator recover the outcome with
		// Lookup-Submission rather than guessing whether work was created.
		return Err(format!(
			"submission was not committed (Idempotency-Key {}): {}",
			built.idempotency_key,
			String::from_utf8_lossy(&result).replace('\n', " ")
		)
		.into());
	}
	Ok(())
}

/// Renders a non-anonymous TTS-0004 address in the legacy 3D or 4D form MSGID uses.
///
/// MSGID carries a legacy address, so recognising our own messages means
/// comparing in that space rather than against the native text.
pub(crate) fn legacy_form(origin: &str) -> Option<String> {
	let address: Address = origin.parse().ok()?;
	if address.is_anonymous() {
		return None;
	}
	let base = format!("{}:{}/{}", address.zone(), address.net(), address.node());
	Some(if address.point() == 0 {
		base
	} else {
		format!("{base}.{}", address.point())
	})
}

pub(crate) fn generated_key() -> Result<String, Box<dyn Error>> {
	let mut bytes = [0_u8; 16];
	random_bytes(&mut bytes)?;
	let mut encoded = String::from("generated:");
	for byte in bytes {
		use std::fmt::Write as _;
		write!(encoded, "{byte:02x}").expect("String writes cannot fail");
	}
	Ok(encoded)
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::Mutex;
	use tith_ipc::SubmissionRequest;
	use tith_submit::ClientError;

	/// Accepts every submission and records the key it carried.
	#[derive(Default)]
	struct Recorder {
		keys: Mutex<Vec<String>>,
	}

	impl Binding for Recorder {
		fn transact(&self, request: &[u8]) -> Result<Vec<u8>, ClientError> {
			let text = String::from_utf8_lossy(request);
			if text.contains("\nCapabilities\n") {
				return Ok(
					b"TITH-IPC-Result 1\nCapabilities Completed\nOperation \"Capabilities\"\nFeature \"Submit.Delete\"\nEnd\n"
						.to_vec(),
				);
			}
			let parsed = SubmissionRequest::parse(request).expect("built request parses");
			for job in &parsed.jobs {
				self.keys
					.lock()
					.expect("recorder lock")
					.push(job.idempotency_key.clone());
			}
			Ok(
				b"TITH-IPC-Result 1\nSubmit Committed\nJob 1 New J0123456789abcdef0123456789abcdef Queued\nEnd\n"
					.to_vec(),
			)
		}
	}

	fn stored(msgid: &str, attributes: u16) -> Vec<u8> {
		let mut bytes = vec![0_u8; tith_message_legacy::HEADER_BYTES];
		bytes[..6].copy_from_slice(b"Sender");
		bytes[36..45].copy_from_slice(b"Recipient");
		bytes[72..79].copy_from_slice(b"Subject");
		bytes[144..163].copy_from_slice(b"01 Jan 26  00:00:00");
		bytes[166..168].copy_from_slice(&4_u16.to_le_bytes());
		bytes[174..176].copy_from_slice(&2_u16.to_le_bytes());
		bytes[176..178].copy_from_slice(&1_u16.to_le_bytes());
		bytes[186..188].copy_from_slice(&attributes.to_le_bytes());
		bytes.extend_from_slice(format!("\u{1}MSGID: 1:2/3 {msgid}\rBody\r\n").as_bytes());
		bytes.push(0);
		bytes
	}

	fn temp_dir(name: &str) -> PathBuf {
		let path = std::env::temp_dir().join(format!(
			"tith-netmail-{name}-{}-{:?}",
			std::process::id(),
			std::thread::current().id()
		));
		let _ = fs::remove_dir_all(&path);
		fs::create_dir_all(&path).expect("temp directory");
		path
	}

	fn options(directory: &Path) -> Options {
		Options {
			origin: "fidonet#1:2/3".to_owned(),
			legacy_origin: Some("1:2/3".to_owned()),
			domain: Some("fidonet".to_owned()),
			configured_offset: Some(0),
			application: "netmail".to_owned(),
			style: AttachStyle::Flags,
			kill_sent: false,
			dry_run: false,
			// Long enough that a concurrent sweep never steals a live claim,
			// which keeps the concurrency test deterministic.
			recover_after: Duration::from_mins(10),
			directory: directory.to_path_buf(),
		}
	}

	#[test]
	fn renders_a_native_origin_into_the_legacy_form_msgid_uses() {
		assert_eq!(legacy_form("fidonet#1:2/3").as_deref(), Some("1:2/3"));
		assert_eq!(legacy_form("fidonet#1:2/3.4").as_deref(), Some("1:2/3.4"));
		// A Zone entry's net and node default, so it still renders in full.
		assert_eq!(legacy_form("fidonet#1").as_deref(), Some("1:1/0"));
		// An anonymous address has no legacy rendering to compare against.
		assert_eq!(legacy_form("p2p#-1"), None);
		assert_eq!(legacy_form("not an address"), None);
	}

	#[test]
	fn selects_only_digit_stemmed_msg_files() {
		let directory = temp_dir("select");
		for name in [
			"1.msg", "23.MSG", "007.Msg", "abc.msg", "1.msgx", "9.bak", "msg",
		] {
			fs::write(directory.join(name), b"x").expect("fixture");
		}
		let found: Vec<_> = stored_messages(&directory)
			.expect("scan")
			.iter()
			.map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
			.collect();
		// Numeric order, not lexical: 1 < 7 < 23, so "007.Msg" sits in the middle.
		assert_eq!(found, ["1.msg", "007.Msg", "23.MSG"]);
		fs::remove_dir_all(directory).expect("cleanup");
	}

	/// The gate must be the claim name already existing, not the message name
	/// having moved. A rename is the second of those and is name based only on
	/// POSIX, so this pins the property the Windows failure exposed.
	#[test]
	fn the_claim_name_is_the_gate() {
		let directory = temp_dir("gate");
		let path = directory.join("1.msg");
		fs::write(&path, stored("1a2b3c4d", 0)).expect("fixture");

		let claimed = claim(&path).expect("claim").expect("claimed");
		assert_eq!(
			claimed.file_name().unwrap().to_string_lossy(),
			format!("1.msg{CLAIM_PREFIX}")
		);
		assert!(claimed.is_file());
		assert!(!path.exists(), "the message keeps exactly one name");

		// The claim exists, so a second racer loses even after the message is
		// restored under its original name.
		fs::write(&path, stored("1a2b3c4d", 0)).expect("restore");
		assert!(claim(&path).expect("claim").is_none());
		assert!(path.is_file(), "a losing racer leaves the message alone");

		// A message another racer already took away is not an error either.
		fs::remove_file(&path).expect("remove");
		fs::remove_file(&claimed).expect("remove");
		assert!(claim(&path).expect("claim").is_none());
		assert!(!claimed.exists(), "a lost race reserves nothing");
		fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn exactly_one_racer_claims_a_message() {
		let directory = temp_dir("claim");
		let path = directory.join("1.msg");
		fs::write(&path, stored("1a2b3c4d", 0)).expect("fixture");
		let winners: usize = std::thread::scope(|scope| {
			let handles: Vec<_> = (0..8)
				.map(|_| scope.spawn(|| usize::from(claim(&path).expect("claim").is_some())))
				.collect();
			handles
				.into_iter()
				.map(|handle| handle.join().unwrap())
				.sum()
		});
		assert_eq!(winners, 1, "more than one scanner claimed the same message");
		fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn concurrent_sweeps_submit_every_message_exactly_once() {
		let directory = temp_dir("sweep");
		let count = 24;
		for number in 1..=count {
			fs::write(
				directory.join(format!("{number}.msg")),
				stored(&format!("{number:08x}"), 0),
			)
			.expect("fixture");
		}
		let recorder = Recorder::default();
		let options = options(&directory);
		let features = BTreeSet::from(["Submit.Delete".to_owned()]);

		std::thread::scope(|scope| {
			for _ in 0..4 {
				scope.spawn(|| {
					sweep(&recorder, &options, &features).expect("sweep");
				});
			}
		});

		let mut keys = recorder.keys.lock().expect("recorder lock").clone();
		keys.sort();
		let unique: BTreeSet<_> = keys.iter().cloned().collect();
		assert_eq!(unique.len(), count, "not every message was submitted");
		assert_eq!(keys.len(), unique.len(), "a message was submitted twice");

		// Every message is back under a ###.msg name, marked Sent, and no claim
		// was left behind.
		let remaining = stored_messages(&directory).expect("rescan");
		assert_eq!(remaining.len(), count);
		for path in remaining {
			let message =
				StoredMessage::parse(&fs::read(&path).expect("read")).expect("stored message");
			assert!(message.has_sent(), "{} was not marked Sent", path.display());
		}
		assert!(
			abandoned_claims(&directory, Duration::ZERO)
				.expect("claims")
				.is_empty(),
			"a claim was left behind"
		);
		fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn a_second_sweep_does_not_resubmit_an_already_sent_message() {
		let directory = temp_dir("resubmit");
		fs::write(directory.join("1.msg"), stored("1a2b3c4d", 0)).expect("fixture");
		let recorder = Recorder::default();
		let options = options(&directory);
		let features = BTreeSet::from(["Submit.Delete".to_owned()]);

		let first = sweep(&recorder, &options, &features).expect("first sweep");
		assert_eq!(first.committed, 1);

		// The Sent bit left by the first sweep is what stops the second one.
		let second = sweep(&recorder, &options, &features).expect("second sweep");
		assert_eq!(second.committed, 0);
		assert_eq!(second.failures, 0);
		assert_eq!(
			recorder.keys.lock().expect("lock").len(),
			1,
			"the message was submitted again"
		);
		fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn a_kill_sent_message_is_removed_rather_than_marked() {
		let directory = temp_dir("kill");
		fs::write(directory.join("1.msg"), stored("1a2b3c4d", 1 << 7)).expect("fixture");
		fs::write(directory.join("2.msg"), stored("2a2b3c4d", 0)).expect("fixture");
		let recorder = Recorder::default();
		let outcome = sweep(
			&recorder,
			&options(&directory),
			&BTreeSet::from(["Submit.Delete".to_owned()]),
		)
		.expect("sweep");
		assert_eq!(outcome.committed, 2);
		let remaining = stored_messages(&directory).expect("rescan");
		assert_eq!(remaining.len(), 1, "the K/S message should be gone");
		fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn an_abandoned_claim_is_recovered_and_restored() {
		let directory = temp_dir("recover");
		let path = directory.join("1.msg");
		fs::write(&path, stored("1a2b3c4d", 0)).expect("fixture");
		// Simulate a crash between claiming and finishing.
		let claimed = claim(&path).expect("claim").expect("claimed");
		assert!(stored_messages(&directory).expect("scan").is_empty());
		assert_eq!(
			abandoned_claims(&directory, Duration::ZERO)
				.expect("claims")
				.len(),
			1
		);
		assert_eq!(original_name(&claimed).as_deref(), Some("1.msg"));

		let recorder = Recorder::default();
		let mut options = options(&directory);
		// Treat the claim as abandoned immediately for this test.
		options.recover_after = Duration::ZERO;
		let outcome = sweep(
			&recorder,
			&options,
			&BTreeSet::from(["Submit.Delete".to_owned()]),
		)
		.expect("sweep");
		assert_eq!(outcome.committed, 1);
		assert_eq!(recorder.keys.lock().expect("lock").len(), 1);

		// It came back under its original name, and no claim remains.
		let remaining = stored_messages(&directory).expect("rescan");
		assert_eq!(remaining.len(), 1);
		assert_eq!(remaining[0].file_name().unwrap(), "1.msg");
		assert!(
			abandoned_claims(&directory, Duration::ZERO)
				.expect("claims")
				.is_empty()
		);
		fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn a_reused_number_does_not_clobber_a_stranger() {
		let directory = temp_dir("reuse");
		let path = directory.join("1.msg");
		fs::write(&path, stored("1a2b3c4d", 0)).expect("fixture");
		let claimed = claim(&path).expect("claim").expect("claimed");
		// Another program allocates 1.msg while the claim is held.
		fs::write(directory.join("1.msg"), b"a stranger's message").expect("stranger");

		let placed = publish(&claimed, &directory, Some("1.msg")).expect("publish");
		assert_ne!(placed.file_name().unwrap(), "1.msg");
		assert_eq!(
			fs::read(directory.join("1.msg")).expect("stranger survives"),
			b"a stranger's message"
		);
		fs::remove_dir_all(directory).expect("cleanup");
	}
}
