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
use tith_adapter::policy::Disposition;
use tith_adapter::publish::clear_staging;
use tith_ledger::{Ledger, State};
use tith_nodelist::Nodelist;
use tith_submit::ConfiguredBinding;
use tith_submit::consume::{self, Authentication, Claimed as ClaimResult};
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
			match handle(&binding, &pending, &configuration, &ledger, &resolver) {
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
		Outcome::Publish { .. } | Outcome::Orphan { .. } => {}
	}

	match commit(claim, &outcome, configuration, ledger)? {
		Ok(()) => {
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
