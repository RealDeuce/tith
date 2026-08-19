//! `tith inbound`: the TSP-0013 adapter daemon.
//!
//! Claims TSP-0012 inbound items, converts them under TSP-0003, and publishes
//! the legacy objects a tosser polls for. Every ordering rule lives in
//! `tith-adapter`; this is the loop, the clock, and the command line.

use std::error::Error;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tith_adapter::config::Configuration;
use tith_adapter::inbound::{Claimed, Outcome, commit, plan};
use tith_adapter::policy::{Disposition, Distribution};
use tith_adapter::publish::clear_staging;
use tith_adapter::srif::{Processor, Session};
use tith_ledger::{Ledger, State};
use tith_nodelist::Nodelist;
use tith_submit::ConfiguredBinding;
use tith_submit::consume::{self, Authentication, Claimed as ClaimResult, Forwarded, PeerFile};
use tith_wire::Address;
use tith_wire::bundle::KeyResolver;
use tith_wire::item::ItemAuthentication;

const USAGE: &str = "usage: tith inbound (--files ROOT | --tcp ADDRESS CLIENT-PUBLIC CLIENT-SECRET-FILE SERVER-PUBLIC | --unix SOCKET | --named-pipe PIPE SERVICE-SID) --config PATH [--nodelist PATH] [--application NAME] [--batch-window SECONDS] [--batch-max N] [--once] [--poll SECONDS]";

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
		_ => Err(USAGE.into()),
	}
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
						peer: claim.peer.clone(),
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

	match commit(claim, &outcome, configuration, ledger)? {
		Ok(()) => {
			// A distribution obligation is discharged before the claim is
			// resolved, because TSP-0013 section 4 requires the native copies be
			// committed "while the claim remains current".
			if !distribute(binding, claim, &outcome, configuration, ledger, application)? {
				return Ok(false);
			}
			if !serve(binding, claim, &outcome, configuration, application)? {
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
/// TSP-0013 section 4 offers two branches. The native one commits a TSP-0006
/// `Job Forward`, which "MUST NOT decode and re-encode, alter, or re-sign any
/// covered byte", so the item's authentication state survives the fan-out
/// exactly and the legacy object published beside it is for local reading only.
/// The legacy branch instead leaves the fan-out to the tosser, whose copies
/// carry no TITHSIG and re-import as `SignedOrigin-Valid` whatever they were.
///
/// An item TSP-0006 section 6 will not forward -- Unsigned or either Invalid
/// state -- has no native onward copy by definition and is final-delivery work,
/// so it owes nothing here.
fn distribute(
	binding: &ConfiguredBinding,
	claim: &Claimed,
	outcome: &Outcome,
	configuration: &Configuration,
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
	if configuration.policy.distribution == Distribution::Legacy || !forwardable {
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
		.link_for(&claim.peer)
		.ok_or("no Link is configured for the requesting peer")?;

	// The processor never sees the condition; TTS-0005 makes it the requester's,
	// so it is applied to what the processor offered.
	let response = Processor {
		program,
		working_directory: working_directory(configuration),
	}
	.run(
		&Session {
			sysop: String::new(),
			akas: vec![link.peer.to_string()],
			our_aka: link.local.to_string(),
			// The Bundle signature authenticated the peer, which is strictly more
			// than an FTN session password ever proved.
			protected: true,
			listed: !link.peer.is_unlisted(),
		},
		std::slice::from_ref(filename),
		fnv(&claim.inbound_id),
	)?;

	let mut offered = Vec::new();
	let mut cleanup = Vec::new();
	for file in &response.offered {
		if let Some(newer_than) = newer_than
			&& !newer_than_condition(&file.path, *newer_than)
		{
			continue;
		}
		let Some(wire_filename) = file.path.file_name().and_then(|name| name.to_str()) else {
			eprintln!(
				"tith inbound: {}: offered path {} has no usable filename",
				claim.inbound_id,
				file.path.display()
			);
			continue;
		};
		if file.afterward.needs_local_cleanup() {
			cleanup.push(file.path.clone());
		}
		offered.push(PeerFile {
			path: file.path.clone(),
			wire_filename: wire_filename.to_owned(),
			disposition: file.afterward.disposition(),
		});
	}

	match consume::submit_peer_files(
		binding,
		application,
		&format!("request:{}", claim.inbound_id),
		&link.local.to_string(),
		&link.peer.to_string(),
		&offered,
	)? {
		Forwarded::Committed { .. } => {
			// FSC-0086 "-" erases whatever happens, which TSP-0006 has no
			// disposition for, so the adapter owes the removal itself.
			for path in cleanup {
				let _ = std::fs::remove_file(path);
			}
			Ok(true)
		}
		Forwarded::NotCommitted {
			reason,
			description,
		} => {
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
