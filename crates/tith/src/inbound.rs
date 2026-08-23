//! `tith inbound`: the TSP-0013 adapter daemon.
//!
//! Claims TSP-0012 inbound items, converts them under TSP-0003, and publishes
//! the legacy objects a tosser polls for. Every ordering rule lives in
//! `tith-adapter`; this is the loop, the clock, and the command line.

use std::error::Error;
use std::io::Write as _;
use std::path::PathBuf;
use std::path::{Component, Path};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tith_adapter::config::{Configuration, Link};
use tith_adapter::inbound::{Claimed, Outcome, commit, plan};
use tith_adapter::policy::Disposition;
use tith_adapter::publish::clear_staging;
use tith_adapter::srif::{Offered, Processor, Session};
use tith_ledger::{Ledger, State};
use tith_nodelist::Nodelist;
use tith_submit::ConfiguredBinding;
use tith_submit::consume::{self, Authentication, Claimed as ClaimResult, Forwarded, PeerFile};
use tith_wire::Address;
use tith_wire::bundle::KeyResolver;
use tith_wire::item::ItemAuthentication;

const USAGE: &str = "usage: tith inbound (run (--files ROOT | --tcp ADDRESS CLIENT-PUBLIC CLIENT-SECRET-FILE SERVER-PUBLIC | --unix SOCKET | --named-pipe PIPE SERVICE-SID) --config PATH [--nodelist PATH] [--application NAME] [--batch-window SECONDS] [--batch-max N] [--once] [--poll SECONDS] | orphan list --config PATH | orphan export --config PATH INBOUND-ID DIRECTORY)";

/// How long a batch may collect before it must publish.
///
/// Kept well inside tithd's 300 second claim expiry, because every item in the
/// batch is held under a claim until the whole batch is published.
const DEFAULT_BATCH_WINDOW: u64 = 20;
const DEFAULT_BATCH_MAX: usize = 32;
const DEFAULT_POLL: u64 = 15;

pub fn run(arguments: &mut impl Iterator<Item = String>) -> Result<i32, Box<dyn Error>> {
	match arguments.next().as_deref() {
		Some("run") => execute(arguments),
		Some("orphan") => orphan(arguments),
		_ => Err(USAGE.into()),
	}
}

fn orphan(arguments: &mut impl Iterator<Item = String>) -> Result<i32, Box<dyn Error>> {
	let operation = arguments.next().ok_or(USAGE)?;
	if arguments.next().as_deref() != Some("--config") {
		return Err(USAGE.into());
	}
	let path = PathBuf::from(arguments.next().ok_or(USAGE)?);
	let configuration = Configuration::parse(&std::fs::read_to_string(path)?)?;
	let ledger = Ledger::open(&configuration.ledger)?;
	match operation.as_str() {
		"list" if arguments.next().is_none() => {
			print!("{}", orphan_listing(&ledger)?);
			Ok(0)
		}
		"export" => {
			let inbound_id = arguments.next().ok_or(USAGE)?;
			let directory = PathBuf::from(arguments.next().ok_or(USAGE)?);
			if arguments.next().is_some() {
				return Err(USAGE.into());
			}
			export_orphan(&ledger, &inbound_id, &directory)?;
			Ok(0)
		}
		_ => Err(USAGE.into()),
	}
}

fn orphan_listing(ledger: &Ledger) -> Result<String, Box<dyn Error>> {
	let mut output = String::new();
	for orphan in ledger.orphans()? {
		output.push_str(&single_line(&orphan.inbound_id));
		output.push('\t');
		output.push_str(&single_line(&orphan.authentication));
		output.push('\t');
		output.push_str(&single_line(&orphan.reason));
		output.push('\n');
	}
	Ok(output)
}

fn single_line(value: &str) -> String {
	value
		.chars()
		.map(|character| match character {
			'\r' | '\n' | '\t' => ' ',
			other => other,
		})
		.collect()
}

fn export_orphan(
	ledger: &Ledger,
	inbound_id: &str,
	directory: &Path,
) -> Result<(), Box<dyn Error>> {
	let orphan = ledger
		.orphan(inbound_id)?
		.ok_or_else(|| format!("no quarantined orphan has InboundID {inbound_id}"))?;
	std::fs::create_dir(directory)?;
	write_new(&directory.join("payload.tlv"), &orphan.payload)?;
	write_new(
		&directory.join("reason.txt"),
		format!(
			"Authentication: {}\nReason: {}\n",
			orphan.authentication, orphan.reason
		)
		.as_bytes(),
	)?;
	let legacy = directory.join("legacy");
	std::fs::create_dir(&legacy)?;
	for object in orphan.objects {
		let path = Path::new(&object.name);
		if !matches!(
			path.components().collect::<Vec<_>>().as_slice(),
			[Component::Normal(_)]
		) {
			return Err(format!("unsafe quarantined legacy name {:?}", object.name).into());
		}
		write_new(&legacy.join(path), &object.contents)?;
	}
	Ok(())
}

fn write_new(path: &Path, contents: &[u8]) -> Result<(), Box<dyn Error>> {
	let mut file = std::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(path)?;
	file.write_all(contents)?;
	file.sync_all()?;
	Ok(())
}

struct Options {
	configuration: PathBuf,
	nodelist: Option<PathBuf>,
	application: String,
	batch_window: Duration,
	batch_max: usize,
	once: bool,
	poll: Duration,
}

fn parse(arguments: &mut impl Iterator<Item = String>) -> Result<Options, Box<dyn Error>> {
	let mut configuration = None;
	let mut nodelist = None;
	let mut application = "tosser".to_owned();
	let mut batch_window = DEFAULT_BATCH_WINDOW;
	let mut batch_max = DEFAULT_BATCH_MAX;
	let mut once = false;
	let mut poll = DEFAULT_POLL;
	while let Some(argument) = arguments.next() {
		match argument.as_str() {
			"--config" => configuration = Some(PathBuf::from(arguments.next().ok_or(USAGE)?)),
			"--nodelist" => nodelist = Some(PathBuf::from(arguments.next().ok_or(USAGE)?)),
			"--application" => application = arguments.next().ok_or(USAGE)?,
			"--batch-window" => batch_window = arguments.next().ok_or(USAGE)?.parse()?,
			"--batch-max" => batch_max = arguments.next().ok_or(USAGE)?.parse()?,
			"--poll" => poll = arguments.next().ok_or(USAGE)?.parse()?,
			"--once" => once = true,
			_ => return Err(USAGE.into()),
		}
	}
	if batch_max == 0 {
		return Err("--batch-max must be at least one".into());
	}
	Ok(Options {
		configuration: configuration.ok_or(USAGE)?,
		nodelist,
		application,
		batch_window: Duration::from_secs(batch_window),
		batch_max,
		once,
		poll: Duration::from_secs(poll),
	})
}

fn execute(arguments: &mut impl Iterator<Item = String>) -> Result<i32, Box<dyn Error>> {
	let binding = tith_submit::cli::binding(arguments, USAGE)?;
	let options = parse(arguments)?;
	let configuration = Configuration::parse(&std::fs::read_to_string(&options.configuration)?)?;
	let ledger = Ledger::open(&configuration.ledger)?;
	let nodelist = match &options.nodelist {
		Some(path) => Some(Nodelist::parse(
			&configuration.domain,
			&std::fs::read_to_string(path)?,
		)?),
		None => None,
	};
	let resolver = move |address: &Address| {
		nodelist
			.as_ref()
			.and_then(|nodelist| nodelist.public_key(address))
	};

	recover(&ledger, &configuration)?;

	let mut failures = 0;
	loop {
		let claimed = batch(&binding, &options)?;
		if claimed.is_empty() {
			if options.once {
				break;
			}
			std::thread::sleep(options.poll);
			continue;
		}
		for pending in claimed {
			match handle(
				&binding,
				&pending,
				&configuration,
				&ledger,
				&resolver,
				&options.application,
			) {
				Ok(true) => {}
				Ok(false) => failures += 1,
				Err(error) => {
					eprintln!("tith inbound: {}: {error}", pending.claim.inbound_id);
					failures += 1;
					// Release transfers no durable responsibility away from the
					// mailer, so the item stays owned there and returns later.
					let _ = consume::release(&binding, &pending.claim.inbound_id, &pending.token);
				}
			}
		}
		if options.once {
			break;
		}
	}
	Ok(i32::from(failures != 0))
}

/// TSP-0013 section 6: the ledger is recovered before any new work is claimed.
fn recover(ledger: &Ledger, configuration: &Configuration) -> Result<(), Box<dyn Error>> {
	// A staged object carries no final name, so nothing can have consumed it and
	// it is safe to discard.
	let cleared = clear_staging(&configuration.inbound)?;
	if cleared != 0 {
		eprintln!("tith inbound: discarded {cleared} interrupted staging files");
	}
	for record in ledger.unfinished()? {
		match record.state {
			// Staged work never reached a final name, so it is rolled back and the
			// item will be redelivered under its own idempotency.
			State::Staged => eprintln!(
				"tith inbound: {} was staged but not published; it will be converted again",
				record.inbound_id
			),
			// Published work is never published again. The claim may still need
			// acknowledging, which the next delivery of that InboundID resolves.
			State::Published => eprintln!(
				"tith inbound: {} is published and awaiting acknowledgement",
				record.inbound_id
			),
			State::Acknowledged | State::Retired => {}
		}
	}
	// A legacy removal the adapter owes outlives the conversion which created it,
	// so it is recovered on its own rather than with the unfinished records.
	for record in ledger.pending_cleanup()? {
		eprintln!(
			"tith inbound: {}: finishing {} interrupted legacy removals",
			record.inbound_id,
			record.cleanup.len()
		);
		discharge_cleanup(ledger, &record.inbound_id, &record.cleanup)?;
	}
	Ok(())
}

/// One claimed item and the export path its payload is presented at.
///
/// The path belongs to the claim, not to the adapter: TSP-0012 section 7
/// forbids retaining a payload reference as the durable source of work, so it
/// lives only for as long as the batch does.
struct Pending {
	claim: Claimed,
	token: String,
	payload_path: PathBuf,
}

/// Claims up to the batch bounds, or until the queue is empty.
fn batch(binding: &ConfiguredBinding, options: &Options) -> Result<Vec<Pending>, Box<dyn Error>> {
	let started = Instant::now();
	let mut claimed = Vec::new();
	while claimed.len() < options.batch_max && started.elapsed() < options.batch_window {
		// Each selection needs a fresh key: section 4 forbids a resolved key from
		// selecting another item.
		let key = format!("{}-{}", now(), claimed.len());
		match consume::claim(binding, &options.application, &key, false)? {
			ClaimResult::Completed(claim) => {
				if !claim.is_current(now()) {
					// Section 4: an already expired result is not usable.
					continue;
				}
				claimed.push(Pending {
					claim: Claimed {
						inbound_id: claim.inbound_id.clone(),
						payload_hash: *claim.payload_hash.as_bytes(),
						claim_token: claim.claim_token.clone(),
						peer: claim.peer.parse()?,
						peer_key: claim.peer_key,
						authentication: authentication(claim.authentication),
					},
					token: claim.claim_token.clone(),
					payload_path: claim.payload_path.clone(),
				});
			}
			ClaimResult::Empty => break,
			// A resolved key cannot select another item, so this key is spent.
			ClaimResult::Resolved { .. } => {}
			ClaimResult::Failed(reason) => {
				return Err(format!("Claim-Inbound returned {reason}").into());
			}
		}
	}
	Ok(claimed)
}

fn handle(
	binding: &ConfiguredBinding,
	pending: &Pending,
	configuration: &Configuration,
	ledger: &Ledger,
	resolver: &impl KeyResolver,
	application: &str,
) -> Result<bool, Box<dyn Error>> {
	let Pending { claim, token, .. } = pending;
	let token = token.as_str();
	let payload = std::fs::read(&pending.payload_path)?;
	let resuming_published = ledger.get(&claim.inbound_id)?.is_some_and(|record| {
		record.payload_hash == claim.payload_hash && record.state == State::Published
	});

	let Some(outcome) = plan(claim, &payload, configuration, ledger, resolver)? else {
		// Already published under this exact InboundID and PayloadHash.
		consume::acknowledge(binding, &claim.inbound_id, token)?;
		return Ok(true);
	};

	match &outcome {
		Outcome::Refuse {
			refusal,
			disposition,
		} => {
			let description = refusal.to_string();
			eprintln!("tith inbound: {}: {description}", claim.inbound_id);
			match disposition {
				Disposition::Reject => {
					consume::reject(binding, &claim.inbound_id, token, &description)?;
				}
				Disposition::Defer => {
					consume::defer(
						binding,
						&claim.inbound_id,
						token,
						now() + 3600,
						&description,
					)?;
				}
			}
			return Ok(false);
		}
		Outcome::Publish { .. } | Outcome::Orphan { .. } | Outcome::ServeRequest { .. } => {}
	}

	let committed = if resuming_published {
		// The legacy objects already have their final durable names. Re-publishing
		// would either duplicate them or collide with them; only the interrupted
		// external obligation below remains.
		Ok(())
	} else {
		commit(claim, &outcome, configuration, ledger)?
	};
	match committed {
		Ok(()) => {
			// A distribution obligation is discharged before the claim is
			// resolved, because TSP-0013 section 4 requires the native copies be
			// committed "while the claim remains current".
			if !distribute(binding, claim, &outcome, ledger, application)? {
				return Ok(false);
			}
			if !serve(binding, claim, &outcome, configuration, ledger, application)? {
				return Ok(false);
			}
			// Section 4: acknowledge only after every converted object and the
			// ledger state which transfers responsibility are durable.
			consume::acknowledge(binding, &claim.inbound_id, token)?;
			ledger.advance(&claim.inbound_id, State::Acknowledged)?;
			Ok(true)
		}
		Err(reason) => {
			eprintln!("tith inbound: {}: {reason}", claim.inbound_id);
			consume::defer(binding, &claim.inbound_id, token, now() + 300, &reason)?;
			Ok(false)
		}
	}
}

/// Commits the native distribution copies for an item which owes them.
///
/// TSP-0013 section 4 requires a TSP-0006 `Job Forward`, which "MUST NOT decode
/// and re-encode, alter, or re-sign any covered byte", so the item's
/// authentication state survives the fan-out exactly and the legacy object
/// published beside it is terminal local delivery.
///
/// An item TSP-0006 section 6 will not forward -- Unsigned or either Invalid
/// state -- has no native onward copy by definition and is final-delivery work,
/// so it owes nothing here.
fn distribute(
	binding: &ConfiguredBinding,
	claim: &Claimed,
	outcome: &Outcome,
	ledger: &Ledger,
	application: &str,
) -> Result<bool, Box<dyn Error>> {
	let Outcome::Publish {
		distribution,
		forwardable,
		..
	} = outcome
	else {
		return Ok(true);
	};
	let Some(area) = distribution else {
		return Ok(true);
	};
	if !forwardable {
		return Ok(true);
	}
	// The key is derived from InboundID so a redelivery resolves to the same Job
	// rather than committing a second fan-out.
	let key = format!("forward:{}", claim.inbound_id);
	match consume::forward(
		binding,
		application,
		&key,
		&claim.inbound_id,
		&claim.claim_token,
	)? {
		Forwarded::Committed { job_id, .. } => {
			ledger.record_forward(&claim.inbound_id, &job_id)?;
			Ok(true)
		}
		Forwarded::NotCommitted {
			reason,
			description,
		} => {
			eprintln!(
				"tith inbound: {}: native distribution of {area} was not committed: {reason} {description}",
				claim.inbound_id
			);
			consume::defer(
				binding,
				&claim.inbound_id,
				&claim.claim_token,
				now() + 300,
				&format!("native distribution not committed: {reason} {description}"),
			)?;
			Ok(false)
		}
	}
}

/// Answers one claimed `FileRequest`.
///
/// The FSC-0086.001 processor decides which files the peer may have; this only
/// carries its answer across the IPC boundary. Every offered file becomes one
/// TSP-0006 `Job Peer-File` addressed back to the requesting peer, which is the
/// shape TTS-0005 gives a File that belongs to no distribution area.
///
/// The whole set is one Batch keyed on `InboundID`, so a redelivered request
/// resolves to the original Jobs rather than sending everything a second time.
/// Like `distribute`, this runs before the claim is resolved.
fn serve(
	binding: &ConfiguredBinding,
	claim: &Claimed,
	outcome: &Outcome,
	configuration: &Configuration,
	ledger: &Ledger,
	application: &str,
) -> Result<bool, Box<dyn Error>> {
	let Outcome::ServeRequest {
		filename,
		newer_than,
	} = outcome
	else {
		return Ok(true);
	};
	let program = configuration
		.request_processor
		.clone()
		.ok_or("a FileRequest was planned with no Request-Processor configured")?;
	let link = configuration
		.link_for(&claim.peer, &claim.peer_key)
		.ok_or("no Link is configured for the requesting peer")?;

	// The processor never sees the condition; TTS-0005 makes it the requester's,
	// so it is applied to what the processor offered.
	let response = Processor {
		program,
		working_directory: working_directory(configuration),
	}
	.run(
		&processor_session(link),
		std::slice::from_ref(filename),
		fnv(&claim.inbound_id),
	)?;

	let reply = plan_reply(&response.offered, *newer_than);
	for path in &reply.unusable {
		eprintln!(
			"tith inbound: {}: offered path {} has no usable filename",
			claim.inbound_id,
			path.display()
		);
	}
	// TSP-0013 section 2: durable before the external action which makes it owed,
	// so a crash before the removals leaves them recoverable. Section 3 requires
	// a disposition with no exact TSP-0006 mapping be recorded, not remembered.
	ledger.record_cleanup(&claim.inbound_id, &reply.cleanup)?;

	match consume::submit_peer_files(
		binding,
		application,
		&format!("request:{}", claim.inbound_id),
		&link.local.to_string(),
		&link.peer.to_string(),
		&reply.offered,
	)? {
		Forwarded::Committed { .. } => {
			discharge_cleanup(ledger, &claim.inbound_id, &reply.cleanup)?;
			Ok(true)
		}
		Forwarded::NotCommitted {
			reason,
			description,
		} => {
			// No reply exists, so nothing was sent and nothing is owed yet. The item
			// is deferred and will be served again, which re-records the obligation
			// against whatever the processor offers then; removing the files here
			// would only sabotage that retry.
			ledger.record_cleanup(&claim.inbound_id, &[])?;
			eprintln!(
				"tith inbound: {}: the file request reply was not committed: {reason} {description}",
				claim.inbound_id
			);
			consume::defer(
				binding,
				&claim.inbound_id,
				&claim.claim_token,
				now() + 300,
				&format!("file request reply not committed: {reason} {description}"),
			)?;
			Ok(false)
		}
	}
}

fn processor_session(link: &Link) -> Session {
	Session {
		sysop: String::new(),
		akas: vec![link.peer.to_string()],
		our_aka: link.local.to_string(),
		// The Bundle signature authenticated the peer, which is strictly more
		// than an FTN session password ever proved.
		protected: true,
		listed: link.listed,
	}
}

/// What one processor run turned into.
#[derive(Debug, Default)]
struct Reply {
	/// The files to submit as `Job Peer-File`.
	offered: Vec<PeerFile>,
	/// Paths the adapter owes a removal for whatever happens next.
	cleanup: Vec<String>,
	/// Offered paths with no usable final component, for the caller to report.
	unusable: Vec<PathBuf>,
}

/// Sorts what the processor offered into the reply and the removals it owes.
///
/// The cleanup obligation is collected before anything can exclude a file from
/// the reply. FSC-0086.001 `-` means "erase the file in any case after the
/// session", and a file the request's condition rejects, or whose path has no
/// usable final component, is still one the processor asked to be rid of.
fn plan_reply(offered: &[Offered], newer_than: Option<u64>) -> Reply {
	let mut reply = Reply::default();
	for file in offered {
		if file.afterward.needs_local_cleanup() {
			reply.cleanup.push(file.path.to_string_lossy().into_owned());
		}
		if newer_than.is_some_and(|newer_than| !newer_than_condition(&file.path, newer_than)) {
			continue;
		}
		let Some(wire_filename) = file.path.file_name().and_then(|name| name.to_str()) else {
			reply.unusable.push(file.path.clone());
			continue;
		};
		reply.offered.push(PeerFile {
			path: file.path.clone(),
			wire_filename: wire_filename.to_owned(),
			disposition: file.afterward.disposition(),
		});
	}
	reply
}

/// Removes every owed path, then clears the obligation.
///
/// The order is what makes it recoverable: the record is cleared only once every
/// path is gone, so an interrupted run repeats the removals rather than
/// forgetting them. A path which is already absent has nothing left to owe.
fn discharge_cleanup(
	ledger: &Ledger,
	inbound_id: &str,
	paths: &[String],
) -> Result<(), Box<dyn Error>> {
	if paths.is_empty() {
		return Ok(());
	}
	let mut remaining = Vec::new();
	for path in paths {
		match std::fs::remove_file(path) {
			Ok(()) => {}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => {
				eprintln!("tith inbound: {inbound_id}: could not remove {path}: {error}");
				remaining.push(path.clone());
			}
		}
	}
	ledger.record_cleanup(inbound_id, &remaining)?;
	Ok(())
}

/// A private directory beside the ledger for the SRIF and its two lists.
fn working_directory(configuration: &Configuration) -> PathBuf {
	configuration
		.ledger
		.parent()
		.unwrap_or_else(|| std::path::Path::new("."))
		.join("tith-request")
}

/// Whether a file satisfies the TTS-0005 `FileRequest` condition.
///
/// A file whose modification time cannot be read is offered: the processor
/// already decided the peer may have it, and dropping it silently would answer
/// a request with nothing and no reason.
fn newer_than_condition(path: &std::path::Path, newer_than: u64) -> bool {
	std::fs::metadata(path)
		.and_then(|metadata| metadata.modified())
		.ok()
		.and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
		.is_none_or(|since| since.as_secs() > newer_than)
}

/// A stable numeric identity for the SRIF filenames of one `InboundID`.
fn fnv(value: &str) -> u64 {
	let mut hash = 0xcbf2_9ce4_8422_2325_u64;
	for byte in value.as_bytes() {
		hash ^= u64::from(*byte);
		hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
	}
	hash
}

const fn authentication(value: Authentication) -> ItemAuthentication {
	match value {
		Authentication::Unsigned => ItemAuthentication::Unsigned,
		Authentication::SignedOriginInvalid => ItemAuthentication::SignedOriginInvalid,
		Authentication::SignedOriginValid => ItemAuthentication::SignedOriginValid,
		Authentication::OriginInvalid => ItemAuthentication::OriginInvalid,
		Authentication::OriginValid => ItemAuthentication::OriginValid,
		Authentication::Transport => ItemAuthentication::Transport,
	}
}

fn now() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_or(0, |since| since.as_secs())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;
	use tith_adapter::srif::Afterward;
	use tith_crypto::PublicKey;
	use tith_ledger::{QuarantineObject, Record, State};

	fn temp_dir(name: &str) -> PathBuf {
		let path = std::env::temp_dir().join(format!(
			"tith-inbound-{name}-{}-{:?}",
			std::process::id(),
			std::thread::current().id()
		));
		let _ = fs::remove_dir_all(&path);
		fs::create_dir_all(&path).expect("temp directory");
		path
	}

	fn build_request_processor(directory: &std::path::Path) -> PathBuf {
		let executable =
			directory.join(format!("request-processor{}", std::env::consts::EXE_SUFFIX));
		let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
			.join("tests/support/request_processor.rs");
		let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
		let status = std::process::Command::new(rustc)
			.arg("--edition=2024")
			.arg(source)
			.arg("-o")
			.arg(&executable)
			.status()
			.expect("run rustc for request-processor fixture");
		assert!(status.success(), "request-processor fixture did not build");
		executable
	}

	fn ledger_with(path: &std::path::Path, inbound_id: &str) -> Ledger {
		let ledger = Ledger::open(path.join("ledger.redb")).expect("ledger");
		ledger
			.stage(&Record {
				inbound_id: inbound_id.to_owned(),
				payload_hash: [0; 32],
				state: State::Published,
				objects: Vec::new(),
				note: "file request".to_owned(),
				claim_token: "C1".to_owned(),
				distribution: String::new(),
				forward_job: String::new(),
				cleanup: Vec::new(),
			})
			.expect("stage");
		ledger
	}

	#[test]
	fn srif_listing_uses_trusted_link_state_not_address_shape() {
		let unlisted = Link {
			peer: "fidonet#1:104/1".parse().unwrap(),
			local: "fidonet#1:104/36".parse().unwrap(),
			peer_key: None,
			listed: false,
			password: String::new(),
		};
		assert!(!processor_session(&unlisted).listed);

		let listed = Link {
			peer: "p2p#-1".parse().unwrap(),
			peer_key: Some(PublicKey::from_bytes([7; 32])),
			listed: true,
			..unlisted
		};
		assert!(processor_session(&listed).listed);
	}

	#[test]
	fn configured_processor_returns_current_nodelist_byte_exactly() {
		let directory = temp_dir("configured_processor_returns_current_nodelist_byte_exactly");
		let processor = build_request_processor(&directory);
		let nodelist = b"Zone\t1\tNode\tLocation\tSysop\t\t\t\t\t\t\n";
		let archive = tith_nodelist::compress_zstd_frame(&nodelist[..], Vec::new())
			.expect("compress publication");
		let publication = directory.join("fidonet-nodelist.zst");
		fs::write(&publication, &archive).expect("publish current nodelist");

		let response = Processor {
			program: processor,
			working_directory: directory.clone(),
		}
		.run(
			&Session {
				sysop: "Requester".to_owned(),
				akas: vec!["1:104/1@fidonet".to_owned()],
				our_aka: "1:104/36@fidonet".to_owned(),
				protected: true,
				listed: true,
			},
			&["fidonet-nodelist.zst".to_owned()],
			1,
		)
		.expect("configured request processor");
		assert_eq!(response.offered.len(), 1);
		assert_eq!(response.offered[0].path, publication);

		let selected = plan_reply(&response.offered, Some(0));
		assert_eq!(selected.offered.len(), 1);
		assert_eq!(selected.offered[0].wire_filename, "fidonet-nodelist.zst");
		assert_eq!(
			fs::read(&selected.offered[0].path).expect("read selected publication"),
			archive
		);
		assert!(
			plan_reply(&response.offered, Some(now() + 86_400))
				.offered
				.is_empty(),
			"a publication older than the requested timestamp must be omitted"
		);
		fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn orphan_recovery_lists_and_exports_without_releasing_quarantine() {
		let directory = temp_dir("orphan-export");
		let ledger = Ledger::open(directory.join("ledger.redb")).expect("ledger");
		let record = Record {
			inbound_id: "I1".to_owned(),
			payload_hash: [7; 32],
			state: State::Retired,
			objects: Vec::new(),
			note: "orphan: invalid signature".to_owned(),
			claim_token: "C1".to_owned(),
			distribution: String::new(),
			forward_job: String::new(),
			cleanup: Vec::new(),
		};
		ledger
			.stage_orphan(
				&record,
				"Origin-Invalid",
				b"exact TLV",
				&[QuarantineObject {
					name: "00000001.pkt".to_owned(),
					contents: b"recovery packet".to_vec(),
				}],
				None,
			)
			.expect("stage orphan");

		assert_eq!(
			orphan_listing(&ledger).expect("list"),
			"I1\tOrigin-Invalid\torphan: invalid signature\n"
		);
		let export = directory.join("export");
		export_orphan(&ledger, "I1", &export).expect("export");
		assert_eq!(fs::read(export.join("payload.tlv")).unwrap(), b"exact TLV");
		assert_eq!(
			fs::read_to_string(export.join("reason.txt")).unwrap(),
			"Authentication: Origin-Invalid\nReason: orphan: invalid signature\n"
		);
		assert_eq!(
			fs::read(export.join("legacy/00000001.pkt")).unwrap(),
			b"recovery packet"
		);
		assert!(
			export_orphan(&ledger, "I1", &export).is_err(),
			"an existing export directory must not be replaced"
		);
		assert!(ledger.orphan("I1").unwrap().is_some());
		fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn an_erase_always_file_is_owed_even_when_the_condition_excludes_it() {
		// FSC-0086.001 "-" erases "in any case", which is not conditional on the
		// file having been sent. Before this the condition filter ran first and
		// such a file was left on disk forever.
		let directory = temp_dir("condition");
		let stale = directory.join("stale.zip");
		let fresh = directory.join("fresh.zip");
		fs::write(&stale, b"stale").expect("stale");
		fs::write(&fresh, b"fresh").expect("fresh");
		// Both are older than a condition far in the future, so neither is offered.
		let future = now() + 86_400;

		let reply = plan_reply(
			&[
				Offered {
					path: stale.clone(),
					afterward: Afterward::EraseAlways,
				},
				Offered {
					path: fresh.clone(),
					afterward: Afterward::Keep,
				},
			],
			Some(future),
		);
		assert!(reply.offered.is_empty(), "the condition excludes both");
		assert_eq!(
			reply.cleanup,
			[stale.to_string_lossy().into_owned()],
			"only the \"-\" file is owed a removal"
		);

		// With no condition both are offered, and the obligation is unchanged.
		let reply = plan_reply(
			&[
				Offered {
					path: stale.clone(),
					afterward: Afterward::EraseAlways,
				},
				Offered {
					path: fresh,
					afterward: Afterward::EraseIfSent,
				},
			],
			None,
		);
		assert_eq!(reply.offered.len(), 2);
		assert_eq!(reply.offered[0].disposition, "Keep");
		assert_eq!(reply.offered[1].disposition, "Delete");
		assert_eq!(reply.cleanup, [stale.to_string_lossy().into_owned()]);
		fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn a_discharged_obligation_removes_its_files_and_clears_the_record() {
		let directory = temp_dir("discharge");
		let ledger = ledger_with(&directory, "I1");
		let present = directory.join("present.zip");
		let absent = directory.join("absent.zip");
		fs::write(&present, b"payload").expect("write");

		let owed = vec![
			present.to_string_lossy().into_owned(),
			absent.to_string_lossy().into_owned(),
		];
		ledger.record_cleanup("I1", &owed).expect("record");
		discharge_cleanup(&ledger, "I1", &owed).expect("discharge");

		assert!(!present.exists(), "the file was not removed");
		// A path which is already gone owes nothing, so the record clears.
		assert!(
			ledger.pending_cleanup().expect("pending").is_empty(),
			"the obligation was not cleared"
		);
		fs::remove_dir_all(directory).expect("cleanup");
	}

	#[test]
	fn a_removal_which_fails_stays_owed_for_the_next_recovery() {
		let directory = temp_dir("retained");
		let ledger = ledger_with(&directory, "I1");
		// A directory is not removable with remove_file, which stands in for any
		// permission or busy failure.
		let stubborn = directory.join("stubborn");
		fs::create_dir(&stubborn).expect("directory");
		let gone = directory.join("gone.zip");
		fs::write(&gone, b"payload").expect("write");

		let owed = vec![
			gone.to_string_lossy().into_owned(),
			stubborn.to_string_lossy().into_owned(),
		];
		ledger.record_cleanup("I1", &owed).expect("record");
		discharge_cleanup(&ledger, "I1", &owed).expect("discharge");

		assert!(!gone.exists(), "the removable file should still be removed");
		let pending = ledger.pending_cleanup().expect("pending");
		assert_eq!(pending.len(), 1);
		assert_eq!(
			pending[0].cleanup,
			[stubborn.to_string_lossy().into_owned()],
			"only the failure stays owed"
		);
		fs::remove_dir_all(directory).expect("cleanup");
	}
}
