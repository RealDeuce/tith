//! `tith bso` subcommands.

mod correlate;

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tith_bso::{
	BusyLock, Flavour, FlowFile, FlowKind, NodeAddress, Outbound, classify_extension, held,
	parse_reference, rewrite_reference,
};
use tith_ipc::EnvelopeKind;
use tith_message_legacy::{AttachStyle, PackedMessage, Packet};
use tith_submit::{Binding, check_capabilities, validate};

use crate::netmail::submission::{self, Context};
use correlate::{Correlation, correlate};

const USAGE: &str = "usage: tith bso scan (--files ROOT | --tcp ADDRESS CLIENT-PUBLIC CLIENT-SECRET-FILE SERVER-PUBLIC | --unix SOCKET | --named-pipe PIPE SERVICE-SID) --origin LOCAL-IDENTITY --outbound ROOT [--zone N] [--domain NAME] [--domain-root NAME=PATH]... [--application NAME] [--binkley] [--dry-run] [--bsy-timeout SECONDS] [--include-hold]";

/// FTS-5005 section 5.1 recommends ignoring a bsy older than twice the maximum
/// session time. Ten minutes is the same default the netmail scanner uses for
/// its own claims.
const DEFAULT_BSY_TIMEOUT: Duration = Duration::from_mins(10);

pub fn run(arguments: &mut impl Iterator<Item = String>) -> Result<i32, Box<dyn Error>> {
	match arguments.next().as_deref() {
		Some("scan") => scan(arguments),
		_ => Err(USAGE.into()),
	}
}

struct Options {
	origin: String,
	legacy_origin: Option<String>,
	application: String,
	style: AttachStyle,
	dry_run: bool,
	include_hold: bool,
	bsy_timeout: Duration,
	outbound: Outbound,
	root: PathBuf,
	domain: Option<String>,
}

fn options(arguments: &mut impl Iterator<Item = String>) -> Result<Options, Box<dyn Error>> {
	let mut origin = None;
	let mut application = "bso".to_owned();
	let mut style = AttachStyle::Flags;
	let mut dry_run = false;
	let mut include_hold = false;
	let mut bsy_timeout = DEFAULT_BSY_TIMEOUT;
	let mut root = None;
	let mut zone = 1_u16;
	let mut domain = None;
	let mut domain_roots = Vec::new();
	while let Some(argument) = arguments.next() {
		match argument.as_str() {
			"--origin" => origin = Some(arguments.next().ok_or(USAGE)?),
			"--outbound" => root = Some(PathBuf::from(arguments.next().ok_or(USAGE)?)),
			"--zone" => zone = arguments.next().ok_or(USAGE)?.parse()?,
			"--domain" => domain = Some(arguments.next().ok_or(USAGE)?),
			"--domain-root" => {
				let value = arguments.next().ok_or(USAGE)?;
				let (name, path) = value.split_once('=').ok_or(USAGE)?;
				domain_roots.push((name.to_owned(), PathBuf::from(path)));
			}
			"--application" => application = arguments.next().ok_or(USAGE)?,
			"--binkley" => style = AttachStyle::Binkley,
			"--dry-run" => dry_run = true,
			"--include-hold" => include_hold = true,
			"--bsy-timeout" => {
				bsy_timeout = Duration::from_secs(arguments.next().ok_or(USAGE)?.parse()?);
			}
			_ => return Err(USAGE.into()),
		}
	}
	let root = root.ok_or(USAGE)?;
	let mut outbound = Outbound::new(root.clone(), zone);
	if let Some(domain) = &domain {
		outbound = outbound.with_default_domain(domain.clone());
	}
	for (name, path) in domain_roots {
		outbound = outbound.with_domain_root(name, path);
	}
	let origin = origin.ok_or(USAGE)?;
	Ok(Options {
		legacy_origin: crate::netmail::legacy_form(&origin),
		origin,
		application,
		style,
		dry_run,
		include_hold,
		bsy_timeout,
		outbound,
		root,
		domain,
	})
}

#[derive(Default)]
struct Outcome {
	committed: usize,
	failures: usize,
	unclaimed: usize,
}

fn scan(arguments: &mut impl Iterator<Item = String>) -> Result<i32, Box<dyn Error>> {
	let binding = tith_submit::cli::binding(arguments, USAGE)?;
	let options = options(arguments)?;
	let features = advertised_features(&binding)?;
	let outcome = sweep(&binding, &options, &features);
	println!(
		"tith bso scan: {} committed, {} failed, {} entries with no submission path",
		outcome.committed, outcome.failures, outcome.unclaimed
	);
	Ok(i32::from(outcome.failures != 0))
}

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

/// Every directory that may hold flow files under this root.
///
/// The bare root, every `<root>.<zzz>`, and each `*.pnt` beneath them.
fn outbound_directories(root: &Path) -> Vec<PathBuf> {
	let mut found = Vec::new();
	if root.is_dir() {
		found.push(root.to_path_buf());
	}
	let (Some(parent), Some(name)) = (root.parent(), root.file_name().and_then(|n| n.to_str()))
	else {
		return found;
	};
	let prefix = format!("{}.", name.to_ascii_lowercase());
	if let Ok(entries) = fs::read_dir(parent) {
		for entry in entries.flatten() {
			let path = entry.path();
			if !path.is_dir() {
				continue;
			}
			let Some(entry_name) = path.file_name().and_then(|n| n.to_str()) else {
				continue;
			};
			let lower = entry_name.to_ascii_lowercase();
			if lower.starts_with(&prefix) && u16::from_str_radix(&lower[prefix.len()..], 16).is_ok()
			{
				found.push(path);
			}
		}
	}
	let mut points = Vec::new();
	for base in &found {
		if let Ok(entries) = fs::read_dir(base) {
			for entry in entries.flatten() {
				let path = entry.path();
				if path.is_dir()
					&& path
						.file_name()
						.and_then(|n| n.to_str())
						.is_some_and(|n| n.to_ascii_lowercase().ends_with(".pnt"))
				{
					points.push(path);
				}
			}
		}
	}
	found.extend(points);
	found.sort();
	found.dedup();
	found
}

/// Groups every recognised flow file by the node it belongs to.
fn flow_files(options: &Options) -> BTreeMap<NodeAddress, Vec<FlowFile>> {
	let mut grouped: BTreeMap<NodeAddress, Vec<FlowFile>> = BTreeMap::new();
	for directory in outbound_directories(&options.root) {
		let Ok(entries) = fs::read_dir(&directory) else {
			continue;
		};
		for entry in entries.flatten() {
			let path = entry.path();
			let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
				continue;
			};
			let Some((flavour, kind)) = classify_extension(extension) else {
				continue;
			};
			let Some(address) = options
				.outbound
				.address_of(&path, options.domain.as_deref())
			else {
				continue;
			};
			grouped.entry(address).or_default().push(FlowFile {
				path,
				flavour,
				kind,
			});
		}
	}
	for files in grouped.values_mut() {
		// FTS-5005 section 3.2 processing order, packets before references.
		files.sort_by(|a, b| {
			a.flavour
				.cmp(&b.flavour)
				.then_with(|| {
					matches!(a.kind, FlowKind::Reference)
						.cmp(&matches!(b.kind, FlowKind::Reference))
				})
				.then_with(|| a.path.cmp(&b.path))
		});
	}
	grouped
}

fn sweep(binding: &impl Binding, options: &Options, features: &BTreeSet<String>) -> Outcome {
	let mut outcome = Outcome::default();
	for (address, files) in flow_files(options) {
		if let Err(error) = node(binding, options, features, &address, &files, &mut outcome) {
			outcome.failures += 1;
			eprintln!("tith bso scan: {address}: {error}");
		}
	}
	outcome
}

/// Processes one node under its `.bsy`.
fn node(
	binding: &impl Binding,
	options: &Options,
	features: &BTreeSet<String>,
	address: &NodeAddress,
	files: &[FlowFile],
	outcome: &mut Outcome,
) -> Result<(), Box<dyn Error>> {
	let Some(directory) = files.first().and_then(|file| file.path.parent()) else {
		return Ok(());
	};
	let stem = Outbound::stem(address);

	if held(&directory.join(format!("{stem}.hld")))? {
		println!("tith bso scan: {address}: held, skipping");
		return Ok(());
	}
	if options.dry_run {
		for file in files {
			println!("tith bso scan: would process {}", file.path.display());
		}
		return Ok(());
	}

	// Section 5.1: take the bsy before changing any flow file.
	let Some(_lock) = BusyLock::take(directory.join(format!("{stem}.bsy")), options.bsy_timeout)?
	else {
		println!("tith bso scan: {address}: busy, skipping");
		return Ok(());
	};

	for file in files {
		if file.flavour == Flavour::Hold && !options.include_hold {
			// Hold means wait for their poll; overriding that is not this
			// tool's decision.
			continue;
		}
		let reference_path = matching_reference(files, file);
		match file.kind {
			FlowKind::Packet => {
				packet(
					binding,
					options,
					features,
					address,
					file,
					reference_path,
					outcome,
				)?;
			}
			FlowKind::Reference => {
				// Handled with its packet; a reference with no packet still has
				// its entries submitted on their own.
				if !files
					.iter()
					.any(|other| other.kind == FlowKind::Packet && other.flavour == file.flavour)
				{
					lone_reference(binding, options, features, address, file, outcome)?;
				}
			}
			FlowKind::Request => request_list(binding, options, address, file, outcome)?,
		}
	}
	Ok(())
}

/// The TTS-0004 address a flow file's placement selects.
///
/// A canonical address needs a domain, which the outbound layout cannot supply
/// on its own; FTS-5005 has no place to record one. Without `--domain` there is
/// nothing correct to address a submission to, so nothing is submitted.
fn destination(address: &NodeAddress) -> Option<String> {
	address.domain.as_ref()?;
	Some(address.to_string())
}

fn matching_reference<'a>(files: &'a [FlowFile], packet: &FlowFile) -> Option<&'a FlowFile> {
	files
		.iter()
		.find(|other| other.kind == FlowKind::Reference && other.flavour == packet.flavour)
}

/// Submits one packet's messages and any unclaimed entries, then retires what
/// committed.
fn packet(
	binding: &impl Binding,
	options: &Options,
	features: &BTreeSet<String>,
	address: &NodeAddress,
	file: &FlowFile,
	reference: Option<&FlowFile>,
	outcome: &mut Outcome,
) -> Result<(), Box<dyn Error>> {
	let directory = file.path.parent().unwrap_or(Path::new("."));
	let packet = Packet::parse(&fs::read(&file.path)?)?;
	let references = match reference {
		Some(reference) => parse_reference(&fs::read_to_string(&reference.path)?),
		None => Vec::new(),
	};
	let correlation = correlate(packet.messages, &references, directory, options.style);

	let mut all_committed = true;
	let mut consumed: Vec<String> = Vec::new();
	for owned in &correlation.messages {
		match submit_message(
			binding,
			options,
			features,
			&owned.message,
			&owned.attachments,
			directory,
		) {
			Ok(()) => {
				outcome.committed += 1;
				consumed.extend(owned.consumed.iter().cloned());
			}
			Err(error) => {
				all_committed = false;
				outcome.failures += 1;
				eprintln!("tith bso scan: {}: {error}", file.path.display());
			}
		}
	}
	consumed.extend(unclaimed_entries(
		binding,
		options,
		features,
		address,
		file,
		&correlation,
		outcome,
	));

	// Section 3.1: the packet is deleted after its information is transferred.
	// Committed is that point; anything short of it leaves everything alone.
	if all_committed {
		fs::remove_file(&file.path)?;
	}
	if let Some(reference) = reference
		&& !consumed.is_empty()
	{
		let keep: Vec<String> = references
			.iter()
			.map(|entry| entry.line.clone())
			.filter(|line| !consumed.contains(line))
			.collect();
		rewrite_reference(&reference.path, &keep)?;
	}
	Ok(())
}

/// A reference file with no packet beside it.
///
/// Its entries own no message, so each one is a peer-addressed File in its own
/// right and is submitted as such.
fn lone_reference(
	binding: &impl Binding,
	options: &Options,
	features: &BTreeSet<String>,
	address: &NodeAddress,
	file: &FlowFile,
	outcome: &mut Outcome,
) -> Result<(), Box<dyn Error>> {
	let directory = file.path.parent().unwrap_or(Path::new("."));
	let references = parse_reference(&fs::read_to_string(&file.path)?);
	let correlation = correlate(Vec::new(), &references, directory, options.style);
	let consumed = unclaimed_entries(
		binding,
		options,
		features,
		address,
		file,
		&correlation,
		outcome,
	);
	if !consumed.is_empty() {
		let keep: Vec<String> = references
			.iter()
			.map(|entry| entry.line.clone())
			.filter(|line| !consumed.contains(line))
			.collect();
		rewrite_reference(&file.path, &keep)?;
	}
	Ok(())
}

/// Submits every entry no message claimed, returning the lines that committed.
///
/// TSP-0003 section 9: an entry with no owning message and no TIC maps to one
/// peer-addressed standalone File. A TIC-accompanied entry is an area
/// distribution and still needs the TIC conversion this tool does not do.
fn unclaimed_entries(
	binding: &impl Binding,
	options: &Options,
	features: &BTreeSet<String>,
	address: &NodeAddress,
	file: &FlowFile,
	correlation: &Correlation,
	outcome: &mut Outcome,
) -> Vec<String> {
	for (entry, area) in &correlation.distributions {
		eprintln!(
			"tith bso scan: {}: \"{}\" is a TIC distribution for area {area}, which this tool does not submit yet",
			file.path.display(),
			entry.name
		);
		outcome.unclaimed += 1;
	}
	if correlation.unclaimed.is_empty() {
		return Vec::new();
	}
	let Some(destination) = destination(address) else {
		for entry in &correlation.unclaimed {
			eprintln!(
				"tith bso scan: {}: \"{}\" has no owning message and no --domain was given, so it cannot be addressed and is left in place",
				file.path.display(),
				entry.name
			);
			outcome.unclaimed += 1;
		}
		return Vec::new();
	};

	let entries: Vec<_> = correlation
		.unclaimed
		.iter()
		.map(tith_bso::as_attachment)
		.collect();
	let directory = file.path.parent().unwrap_or(Path::new("."));
	let fallback = match crate::netmail::generated_key() {
		Ok(key) => key,
		Err(error) => {
			outcome.failures += 1;
			eprintln!("tith bso scan: {}: {error}", file.path.display());
			return Vec::new();
		}
	};
	let built = submission::build_peer_files(
		&entries,
		&destination,
		file.flavour == Flavour::Hold,
		&Context {
			application: &options.application,
			origin: &options.origin,
			legacy_origin: options.legacy_origin.clone(),
			domain: options.domain.as_deref(),
			style: options.style,
			features,
			directory,
			fallback_key: &fallback,
		},
	);
	let sent = built
		.map_err(|error| Box::new(error) as Box<dyn Error>)
		.and_then(|built| commit(binding, &built));
	match sent {
		Ok(()) => {
			outcome.committed += correlation.unclaimed.len();
			correlation
				.unclaimed
				.iter()
				.map(|entry| entry.line.clone())
				.collect()
		}
		Err(error) => {
			outcome.failures += 1;
			eprintln!("tith bso scan: {}: {error}", file.path.display());
			Vec::new()
		}
	}
}

/// Submits every action in one request list, then retires what committed.
///
/// TSP-0003 section 8: every successfully parsed action becomes one
/// `FileRequest`. An action with no exact TITH representation — a minus time is
/// the documented case — is retained as unsupported work, which means the file
/// is rewritten rather than deleted.
fn request_list(
	binding: &impl Binding,
	options: &Options,
	address: &NodeAddress,
	file: &FlowFile,
	outcome: &mut Outcome,
) -> Result<(), Box<dyn Error>> {
	let actions = tith_bso::parse_request(&fs::read_to_string(&file.path)?);
	if actions.is_empty() {
		return Ok(());
	}
	let Some(destination) = destination(address) else {
		eprintln!(
			"tith bso scan: {}: no --domain was given, so these requests cannot be addressed and are left in place",
			file.path.display()
		);
		outcome.unclaimed += actions.len();
		return Ok(());
	};
	let (submit, retain): (Vec<_>, Vec<_>) = actions.iter().partition(|action| !action.unsupported);
	for action in &retain {
		eprintln!(
			"tith bso scan: {}: \"{}\" has no exact TITH representation and is left in place",
			file.path.display(),
			action.line
		);
		outcome.unclaimed += 1;
	}
	if submit.is_empty() {
		return Ok(());
	}

	let owned: Vec<_> = submit.iter().map(|action| (*action).clone()).collect();
	let features = BTreeSet::new();
	let fallback = crate::netmail::generated_key()?;
	let built = submission::build_file_requests(
		&owned,
		&destination,
		file.flavour == Flavour::Hold,
		&Context {
			application: &options.application,
			origin: &options.origin,
			legacy_origin: options.legacy_origin.clone(),
			domain: options.domain.as_deref(),
			style: options.style,
			features: &features,
			directory: file.path.parent().unwrap_or(Path::new(".")),
			fallback_key: &fallback,
		},
	);
	match commit(binding, &built) {
		Ok(()) => {
			outcome.committed += submit.len();
			// Only the actions which committed are removed.
			let keep: Vec<String> = retain.iter().map(|action| action.line.clone()).collect();
			tith_bso::rewrite_request(&file.path, &keep)?;
			Ok(())
		}
		Err(error) => {
			outcome.failures += 1;
			eprintln!("tith bso scan: {}: {error}", file.path.display());
			Ok(())
		}
	}
}

fn submit_message(
	binding: &impl Binding,
	options: &Options,
	features: &BTreeSet<String>,
	message: &PackedMessage,
	attachments: &[tith_message_legacy::Attachment],
	directory: &Path,
) -> Result<(), Box<dyn Error>> {
	let fallback = crate::netmail::generated_key()?;
	let built = submission::build_packed(
		message,
		attachments,
		&Context {
			application: &options.application,
			origin: &options.origin,
			legacy_origin: options.legacy_origin.clone(),
			domain: options.domain.as_deref(),
			style: options.style,
			features,
			directory,
			fallback_key: &fallback,
		},
	)?;
	commit(binding, &built)
}

/// Sends one submission and requires a Committed result for its own operation.
///
/// TSP-0006 section 8: "A result MUST name the operation in its request", so
/// the check is against the operation the document actually used rather than
/// always `Submit`.
fn commit(binding: &impl Binding, built: &submission::Submission) -> Result<(), Box<dyn Error>> {
	let result = binding.transact(&built.request)?;
	let document = validate(&result, EnvelopeKind::Result)?;
	let committed = document.lines.first().is_some_and(|line| {
		matches!(line.fields.as_slice(), [operation, status]
			if !operation.quoted
				&& operation.text == built.operation
				&& !status.quoted
				&& status.text == "Committed")
	});
	if !committed {
		return Err(format!(
			"submission was not committed (Idempotency-Key {}): {}",
			built.idempotency_key,
			String::from_utf8_lossy(&result).replace('\n', " ")
		)
		.into());
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::Mutex;
	use tith_ipc::SubmissionRequest;
	use tith_submit::ClientError;

	/// Accepts every submission and records what it carried.
	#[derive(Default)]
	struct Recorder {
		keys: Mutex<Vec<String>>,
		requests: Mutex<Vec<String>>,
		reject: bool,
	}

	impl Binding for Recorder {
		fn transact(&self, request: &[u8]) -> Result<Vec<u8>, ClientError> {
			let text = String::from_utf8_lossy(request).into_owned();
			if text.contains("\nCapabilities\n") {
				return Ok(
					b"TITH-IPC-Result 1\nCapabilities Completed\nOperation \"Capabilities\"\nFeature \"Submit.Delete\"\nEnd\n"
						.to_vec(),
				);
			}
			let parsed = SubmissionRequest::parse(request).expect("built request parses");
			// TSP-0006 section 8: a result names the operation in its request.
			let operation = match parsed.operation {
				tith_ipc::SubmitOperation::Submit => "Submit",
				tith_ipc::SubmitOperation::SubmitItems => "Submit-Items",
			};
			if self.reject {
				return Ok(format!(
					"TITH-IPC-Result 1\n{operation} Not-Committed\nFailure 1 Invalid \"refused\"\nEnd\n"
				)
				.into_bytes());
			}
			self.requests.lock().expect("lock").push(text);
			let jobs: Vec<String> = parsed
				.jobs
				.iter()
				.enumerate()
				.map(|(index, job)| {
					self.keys
						.lock()
						.expect("lock")
						.push(job.idempotency_key.clone());
					format!(
						"Job {} New J0123456789abcdef0123456789abcde{index:x} Queued\n",
						index + 1
					)
				})
				.collect();
			Ok(format!(
				"TITH-IPC-Result 1\n{operation} Committed\n{}End\n",
				jobs.concat()
			)
			.into_bytes())
		}
	}

	fn temp_dir(name: &str) -> PathBuf {
		let path = std::env::temp_dir().join(format!(
			"tith-bso-scan-{name}-{}-{:?}",
			std::process::id(),
			std::thread::current().id()
		));
		let _ = fs::remove_dir_all(&path);
		fs::create_dir_all(&path).expect("temp directory");
		path
	}

	/// Builds a one-message packet, optionally with the attach attribute and a
	/// Subject `FileList`.
	fn packet_bytes(msgid: &str, attributes: u16, subject: &str) -> Vec<u8> {
		let mut bytes = vec![0_u8; tith_message_legacy::PACKET_HEADER_BYTES];
		let put = |bytes: &mut Vec<u8>, offset: usize, value: u16| {
			bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
		};
		put(&mut bytes, 18, 2);
		put(&mut bytes, 40, 0x0100);
		put(&mut bytes, 44, 0x0001);
		put(&mut bytes, 46, 1);
		put(&mut bytes, 48, 1);
		put(&mut bytes, 20, 104);
		put(&mut bytes, 22, 104);
		let mut record = 2_u16.to_le_bytes().to_vec();
		let mut header = vec![0_u8; tith_message_legacy::PACKED_HEADER_BYTES - 2];
		// Full offsets 2, 4, 6, 8: origin node, destination node, origin net,
		// destination net.
		header[0..2].copy_from_slice(&36_u16.to_le_bytes());
		header[2..4].copy_from_slice(&36_u16.to_le_bytes());
		header[4..6].copy_from_slice(&104_u16.to_le_bytes());
		header[6..8].copy_from_slice(&104_u16.to_le_bytes());
		header[8..10].copy_from_slice(&attributes.to_le_bytes());
		header[12..12 + 19].copy_from_slice(b"18 Aug 26  12:00:00");
		record.extend_from_slice(&header);
		record.extend_from_slice(b"Recipient\0Sender\0");
		record.extend_from_slice(subject.as_bytes());
		record.push(0);
		record.extend_from_slice(
			format!("\u{1}MSGID: 1:104/36 {msgid}\r\u{1}MSGTO: fidonet#1:104/36\rBody\r\n")
				.as_bytes(),
		);
		record.push(0);
		bytes.extend_from_slice(&record);
		bytes.extend_from_slice(&0_u16.to_le_bytes());
		bytes
	}

	fn options(root: &Path, reject_style: AttachStyle) -> Options {
		Options {
			origin: "fidonet#1:104/36".to_owned(),
			legacy_origin: Some("1:104/36".to_owned()),
			application: "bso".to_owned(),
			style: reject_style,
			dry_run: false,
			include_hold: false,
			bsy_timeout: Duration::from_mins(10),
			outbound: Outbound::new(root, 1),
			root: root.to_path_buf(),
			domain: None,
		}
	}

	fn features() -> BTreeSet<String> {
		BTreeSet::from(["Submit.Delete".to_owned(), "Submit.Truncate".to_owned()])
	}

	#[test]
	fn finds_flow_files_in_every_outbound_directory() {
		let base = temp_dir("dirs");
		let root = base.join("outbound");
		fs::create_dir_all(root.join("00680024.pnt")).expect("point dir");
		fs::create_dir_all(base.join("outbound.002")).expect("zone dir");
		fs::write(root.join("00680024.flo"), "").expect("flo");
		fs::write(base.join("outbound.002/00680024.out"), "").expect("out");
		fs::write(root.join("00680024.pnt/0000002d.flo"), "").expect("point flo");
		fs::write(root.join("ignored.txt"), "").expect("other");

		let grouped = flow_files(&options(&root, AttachStyle::Flags));
		let addresses: Vec<String> = grouped.keys().map(ToString::to_string).collect();
		assert_eq!(addresses, ["1:104/36", "1:104/36.45", "2:104/36"]);
		fs::remove_dir_all(base).expect("cleanup");
	}

	#[test]
	fn a_committed_packet_is_deleted_and_its_flo_line_removed() {
		let base = temp_dir("commit");
		let root = base.join("outbound");
		fs::create_dir_all(&root).expect("root");
		fs::write(
			root.join("00680024.out"),
			packet_bytes("aa000001", 1 << 4, "work.zip"),
		)
		.expect("packet");
		fs::write(root.join("00680024.flo"), "^work.zip\n#bundle.su0\n").expect("flo");
		fs::write(root.join("work.zip"), b"payload").expect("payload");

		let recorder = Recorder::default();
		let outcome = sweep(&recorder, &options(&root, AttachStyle::Flags), &features());
		assert_eq!(outcome.committed, 1);
		assert_eq!(outcome.failures, 0);
		// Without --domain the ARCmail entry cannot be addressed, so it is
		// reported and left alone rather than guessed at.
		assert_eq!(outcome.unclaimed, 1);

		assert!(
			!root.join("00680024.out").exists(),
			"packet was not deleted"
		);
		assert_eq!(
			fs::read_to_string(root.join("00680024.flo")).expect("flo"),
			"#bundle.su0\n",
			"only the consumed line should be removed"
		);
		// The scanner never touches the payload; Source-Disposition does.
		assert_eq!(
			fs::read(root.join("work.zip")).expect("payload"),
			b"payload"
		);
		assert!(!root.join("00680024.bsy").exists(), "lock was left behind");
		fs::remove_dir_all(base).expect("cleanup");
	}

	#[test]
	fn an_unclaimed_entry_is_submitted_as_a_peer_file_and_its_line_removed() {
		// TSP-0003 section 9: an entry no message claims and no TIC accompanies
		// is a peer-addressed standalone File.
		let base = temp_dir("peerfile");
		let root = base.join("outbound");
		fs::create_dir_all(&root).expect("root");
		fs::write(root.join("00680024.flo"), "#0068002400.su0\n").expect("flo");
		fs::write(root.join("0068002400.su0"), b"arcmail").expect("payload");

		let mut options = options(&root, AttachStyle::Flags);
		options.domain = Some("fidonet".to_owned());
		options.outbound = Outbound::new(&root, 1).with_default_domain("fidonet");
		let recorder = Recorder::default();
		let outcome = sweep(&recorder, &options, &features());
		assert_eq!(outcome.committed, 1);
		assert_eq!(outcome.failures, 0);
		assert_eq!(outcome.unclaimed, 0);

		let sent = recorder.requests.lock().expect("lock").concat();
		assert!(sent.contains("Submit-Items"), "{sent}");
		assert!(sent.contains("Job Peer-File"), "{sent}");
		assert!(sent.contains("Destination \"fidonet#1:104/36\""), "{sent}");
		assert!(sent.contains("Wire-Filename \"0068002400.su0\""), "{sent}");
		// "#" is Truncate, and it travels as a Source-Disposition rather than
		// being performed here.
		assert!(sent.contains("Source-Disposition Truncate"), "{sent}");
		assert!(
			!root.join("00680024.flo").exists(),
			"an emptied reference file is deleted"
		);
		assert_eq!(
			fs::read(root.join("0068002400.su0")).expect("payload"),
			b"arcmail",
			"the scanner never truncates a referenced payload"
		);
		fs::remove_dir_all(base).expect("cleanup");
	}

	#[test]
	fn a_request_list_is_submitted_and_unsupported_actions_are_retained() {
		let base = temp_dir("request");
		let root = base.join("outbound");
		fs::create_dir_all(&root).expect("root");
		fs::write(
			root.join("00680024.req"),
			"nodediff.zip\nfiles.zip +1755400000\nold.zip -1755400000\n",
		)
		.expect("req");

		let mut options = options(&root, AttachStyle::Flags);
		options.domain = Some("fidonet".to_owned());
		options.outbound = Outbound::new(&root, 1).with_default_domain("fidonet");
		let recorder = Recorder::default();
		let outcome = sweep(&recorder, &options, &features());
		assert_eq!(outcome.committed, 2);
		assert_eq!(outcome.failures, 0);
		// TSP-0003 section 8: a minus time has no exact TITH representation.
		assert_eq!(outcome.unclaimed, 1);

		let sent = recorder.requests.lock().expect("lock").concat();
		assert!(sent.contains("Job FileRequest"), "{sent}");
		assert!(sent.contains("Filename \"nodediff.zip\""), "{sent}");
		assert!(sent.contains("Newer-Than 1755400000"), "{sent}");
		assert!(!sent.contains("old.zip"), "{sent}");
		assert_eq!(
			fs::read_to_string(root.join("00680024.req")).expect("req"),
			"old.zip -1755400000\n",
			"only the actions which committed are removed"
		);
		fs::remove_dir_all(base).expect("cleanup");
	}

	#[test]
	fn a_hold_flavoured_entry_is_committed_passive() {
		// The Hold flavour means "wait for their poll", which is exactly what an
		// explicit Passive Next-Hop preserves.
		let base = temp_dir("holdpeer");
		let root = base.join("outbound");
		fs::create_dir_all(&root).expect("root");
		fs::write(root.join("00680024.hlo"), "@held.zip\n").expect("hlo");
		fs::write(root.join("held.zip"), b"payload").expect("payload");

		let mut options = options(&root, AttachStyle::Flags);
		options.domain = Some("fidonet".to_owned());
		options.outbound = Outbound::new(&root, 1).with_default_domain("fidonet");
		options.include_hold = true;
		let recorder = Recorder::default();
		let outcome = sweep(&recorder, &options, &features());
		assert_eq!(outcome.committed, 1);
		let sent = recorder.requests.lock().expect("lock").concat();
		assert!(sent.contains("Next-Hop Passive"), "{sent}");
		fs::remove_dir_all(base).expect("cleanup");
	}

	#[test]
	fn a_packet_from_another_origin_is_refused_and_left_alone() {
		// Regression: the origin check must compare against the configured
		// local identity, not against the message's own claim, or in-transit
		// mail would always look local.
		let base = temp_dir("intransit");
		let root = base.join("outbound");
		fs::create_dir_all(&root).expect("root");
		let packet = packet_bytes("ff000001", 0, "Subject");
		fs::write(root.join("00680024.out"), &packet).expect("packet");

		let mut options = options(&root, AttachStyle::Flags);
		options.origin = "fidonet#1:999/1".to_owned();
		options.legacy_origin = Some("1:999/1".to_owned());

		let recorder = Recorder::default();
		let outcome = sweep(&recorder, &options, &features());
		assert_eq!(outcome.committed, 0);
		assert_eq!(outcome.failures, 1);
		assert!(recorder.keys.lock().expect("lock").is_empty());
		assert_eq!(fs::read(root.join("00680024.out")).expect("packet"), packet);
		fs::remove_dir_all(base).expect("cleanup");
	}

	#[test]
	fn a_refused_submission_changes_nothing() {
		let base = temp_dir("refuse");
		let root = base.join("outbound");
		fs::create_dir_all(&root).expect("root");
		let packet = packet_bytes("bb000001", 1 << 4, "work.zip");
		fs::write(root.join("00680024.out"), &packet).expect("packet");
		fs::write(root.join("00680024.flo"), "^work.zip\n").expect("flo");
		fs::write(root.join("work.zip"), b"payload").expect("payload");

		let recorder = Recorder {
			reject: true,
			..Recorder::default()
		};
		let outcome = sweep(&recorder, &options(&root, AttachStyle::Flags), &features());
		assert_eq!(outcome.committed, 0);
		assert_eq!(outcome.failures, 1);

		assert_eq!(fs::read(root.join("00680024.out")).expect("packet"), packet);
		assert_eq!(
			fs::read_to_string(root.join("00680024.flo")).expect("flo"),
			"^work.zip\n"
		);
		assert_eq!(
			fs::read(root.join("work.zip")).expect("payload"),
			b"payload"
		);
		assert!(!root.join("00680024.bsy").exists());
		fs::remove_dir_all(base).expect("cleanup");
	}

	#[test]
	fn a_held_node_is_skipped_and_an_expired_hold_is_removed() {
		let base = temp_dir("hold");
		let root = base.join("outbound");
		fs::create_dir_all(&root).expect("root");
		fs::write(
			root.join("00680024.out"),
			packet_bytes("cc000001", 0, "Subject"),
		)
		.expect("packet");

		let future = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap()
			.as_secs()
			+ 3600;
		fs::write(root.join("00680024.hld"), format!("{future}\n")).expect("hld");
		let recorder = Recorder::default();
		let outcome = sweep(&recorder, &options(&root, AttachStyle::Flags), &features());
		assert_eq!(outcome.committed, 0);
		assert!(
			root.join("00680024.out").exists(),
			"a held packet must remain"
		);

		fs::write(root.join("00680024.hld"), "1\n").expect("hld");
		let outcome = sweep(&recorder, &options(&root, AttachStyle::Flags), &features());
		assert_eq!(outcome.committed, 1);
		assert!(
			!root.join("00680024.hld").exists(),
			"expired hold must be deleted"
		);
		fs::remove_dir_all(base).expect("cleanup");
	}

	#[test]
	fn hold_flavoured_flow_files_are_left_alone() {
		let base = temp_dir("holdflavour");
		let root = base.join("outbound");
		fs::create_dir_all(&root).expect("root");
		fs::write(
			root.join("00680024.hut"),
			packet_bytes("dd000001", 0, "Subject"),
		)
		.expect("packet");
		let recorder = Recorder::default();
		let outcome = sweep(&recorder, &options(&root, AttachStyle::Flags), &features());
		assert_eq!(outcome.committed, 0);
		assert!(root.join("00680024.hut").exists());
		fs::remove_dir_all(base).expect("cleanup");
	}

	#[test]
	fn concurrent_sweeps_submit_each_packet_exactly_once() {
		let base = temp_dir("concurrent");
		let root = base.join("outbound");
		fs::create_dir_all(&root).expect("root");
		for node in 1..=8_u16 {
			fs::write(
				root.join(format!("0068{node:04x}.out")),
				packet_bytes(&format!("{node:08x}"), 0, "Subject"),
			)
			.expect("packet");
		}
		let recorder = Recorder::default();
		let options = options(&root, AttachStyle::Flags);
		let features = features();

		std::thread::scope(|scope| {
			for _ in 0..4 {
				scope.spawn(|| {
					sweep(&recorder, &options, &features);
				});
			}
		});

		let keys = recorder.keys.lock().expect("lock").clone();
		let unique: BTreeSet<_> = keys.iter().cloned().collect();
		assert_eq!(unique.len(), 8, "not every packet was submitted");
		assert_eq!(keys.len(), unique.len(), "a packet was submitted twice");
		assert!(
			fs::read_dir(&root)
				.expect("read")
				.flatten()
				.all(|entry| entry.path().extension().is_none_or(|e| e != "bsy")),
			"a lock was left behind"
		);
		fs::remove_dir_all(base).expect("cleanup");
	}

	#[test]
	fn a_busy_node_is_skipped_rather_than_processed() {
		let base = temp_dir("busy");
		let root = base.join("outbound");
		fs::create_dir_all(&root).expect("root");
		fs::write(
			root.join("00680024.out"),
			packet_bytes("ee000001", 0, "Subject"),
		)
		.expect("packet");
		let _lock = tith_bso::BusyLock::take(root.join("00680024.bsy"), Duration::from_mins(10))
			.expect("take")
			.expect("holder");

		let recorder = Recorder::default();
		let outcome = sweep(&recorder, &options(&root, AttachStyle::Flags), &features());
		assert_eq!(outcome.committed, 0);
		assert!(
			root.join("00680024.out").exists(),
			"a busy node must be untouched"
		);
		fs::remove_dir_all(base).expect("cleanup");
	}
}
