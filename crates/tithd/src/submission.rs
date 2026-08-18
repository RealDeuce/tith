use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use tith_config::{ConfigurationSet, IdentityRef};
use tith_crypto::{SecretKey, hash_submission_file, hash_submission_job, random_bytes};
use tith_ipc::{
	FailureDisposition as IpcDisposition, FailureNotification as IpcNotification, FailureOverride,
	FileSubmission, Ingestion, MessageKind, MessageSubmission, NextHop, Source,
	SourceDisposition as IpcSourceDisposition, SourceSubmission, SubmissionBody, SubmissionRequest,
	WireFilename,
};
use tith_nodelist::Nodelist;
use tith_router::{failure_policies, route_netmail, routes_for};
use tith_store::{
	BatchCommit, CleanupState, DeliveryMode, FailureDisposition, FailureNotification,
	FailurePolicy, JobBuildFailure, JobKind, JobTarget, NewDelivery, NewOutboundJob, OutboundStore,
	SourceDisposition, SourceKind, SourceRecord, StoreError, SubmissionClass, SubmissionIdentity,
};
use tith_wire::address::Address;
use tith_wire::bundle::{Identity, KeyResolver};
use tith_wire::item::{
	AttachmentData, ItemProvenance, MessageData, StandaloneFileData, build_originated_file,
	build_originated_message, forward_item, validate_item,
};

const SOFTWARE: &str = "tithd 0.1.0";

pub struct LocalSigner {
	pub reference: IdentityRef,
	pub identity: Identity,
	pub secret: Arc<SecretKey>,
}

pub struct SubmissionEngine {
	configuration: Arc<ConfigurationSet>,
	nodelist: Arc<Nodelist>,
	signers: BTreeMap<String, LocalSigner>,
}

impl SubmissionEngine {
	#[must_use]
	pub fn new(
		configuration: Arc<ConfigurationSet>,
		nodelist: Arc<Nodelist>,
		signers: impl IntoIterator<Item = (String, LocalSigner)>,
	) -> Self {
		Self {
			configuration,
			nodelist,
			signers: signers.into_iter().collect(),
		}
	}

	pub fn submit(
		&self,
		request: &SubmissionRequest,
		store: &OutboundStore,
	) -> Result<BatchCommit, StoreError> {
		let identities: Vec<_> = request
			.jobs
			.iter()
			.map(|job| {
				Ok(SubmissionIdentity {
					application: job.application.clone(),
					idempotency_key: job.idempotency_key.clone(),
					digest: hash_submission_job(&job.canonical)?,
				})
			})
			.collect::<Result<_, tith_crypto::CryptoError>>()?;
		store.commit_batch(&identities, |classes, context| {
			let mut jobs = Vec::new();
			for (position, ((request_job, identity), class)) in request
				.jobs
				.iter()
				.zip(&identities)
				.zip(classes)
				.enumerate()
			{
				let SubmissionClass::New { job_id } = class else {
					continue;
				};
				let job = self
					.build_job(job_id, request_job, identity, context)
					.map_err(|failure| StoreError::JobBuild {
						position: position + 1,
						kind: failure.kind,
						description: failure.description,
					})?;
				jobs.push(job);
			}
			Ok(jobs)
		})
	}

	pub fn reroute_delivery(
		&self,
		job: &tith_store::OutboundJob,
		item: &[u8],
		next_hop: &NextHop,
		failure_policy: Option<FailureOverride>,
	) -> Result<NewDelivery, StoreError> {
		let failure = |failure: BuildFailure| StoreError::JobBuild {
			position: 1,
			kind: failure.kind,
			description: failure.description,
		};
		if job.kind != JobKind::NetMail {
			return Err(failure(BuildFailure::invalid(
				"Reroute applies only to NetMail",
			)));
		}
		let signer = self
			.signers
			.values()
			.find(|signer| signer.identity.address.to_string() == job.local_identity)
			.ok_or_else(|| {
				failure(BuildFailure::invalid(
					"Job local identity is no longer configured",
				))
			})?;
		let parsed = tith_wire::tlv::parse_sequence(item)
			.map_err(|error| failure(BuildFailure::invalid(error.to_string())))?;
		let validated = parsed
			.first()
			.ok_or_else(|| failure(BuildFailure::invalid("Job item is missing")))
			.and_then(|value| {
				validate_item(value, self.nodelist.as_ref())
					.map_err(|error| failure(BuildFailure::invalid(error.to_string())))
			})?
			.ok_or_else(|| failure(BuildFailure::invalid("Job item is not a deliverable item")))?;
		let destination = validated
			.destination
			.ok_or_else(|| failure(BuildFailure::invalid("NetMail item has no Destination")))?;
		let routes = routes_for(&self.configuration, &signer.reference).ok_or_else(|| {
			failure(BuildFailure::permanent(
				"local identity has no Routes block",
			))
		})?;
		let (target, mode, route_rule) = match next_hop {
			NextHop::Route => {
				let commitment = route_netmail(
					&self.configuration,
					routes,
					&destination,
					&[],
					&self.nodelist,
				)
				.map_err(|error| failure(BuildFailure::permanent(format!("{error:?}"))))?;
				(
					commitment.next_hop,
					if commitment.passive {
						DeliveryMode::Passive
					} else {
						DeliveryMode::Active
					},
					commitment.route_rule,
				)
			}
			NextHop::Active(value) => {
				if !self.has_usable_endpoint(value) {
					return Err(failure(BuildFailure::permanent(
						"explicit Active next hop has no usable endpoint",
					)));
				}
				(
					self.resolve_identity(value).map_err(failure)?,
					DeliveryMode::Active,
					None,
				)
			}
			NextHop::Passive(value) => (
				self.resolve_identity(value).map_err(failure)?,
				DeliveryMode::Passive,
				None,
			),
		};
		let configured = failure_policies(
			&self.configuration,
			routes,
			&signer.identity,
			&target,
			route_rule,
			&self.nodelist,
		);
		Ok(NewDelivery {
			local_identity: signer.identity.address.to_string(),
			next_hop: target.address.to_string(),
			mode,
			class: job.deliveries[0].class.clone(),
			retry_at: None,
			policies: convert_policies(configured, failure_policy),
		})
	}

	fn build_job(
		&self,
		job_id: &str,
		job: &tith_ipc::SubmissionJob,
		identity: &SubmissionIdentity,
		context: &tith_store::BatchContext<'_>,
	) -> Result<NewOutboundJob, BuildFailure> {
		if job.application.is_empty() || job.idempotency_key.is_empty() {
			return Err(BuildFailure::invalid(
				"Application and Idempotency-Key must be nonempty",
			));
		}
		match &job.body {
			SubmissionBody::Message(message) => {
				self.build_message_job(job_id, identity.clone(), message)
			}
			SubmissionBody::File(file) => self.build_file_job(identity.clone(), file),
			SubmissionBody::Forward {
				inbound_id,
				claim_token,
			} => self.build_forward_job(identity.clone(), inbound_id, claim_token, context),
		}
	}

	fn build_message_job(
		&self,
		job_id: &str,
		identity: SubmissionIdentity,
		message: &MessageSubmission,
	) -> Result<NewOutboundJob, BuildFailure> {
		let (signer, provenance) =
			self.item_provenance(&message.origin, message.signed_origin.as_deref())?;
		if message.kind == MessageKind::EchoMail {
			validate_area_name(&message.destination_or_area)?;
		}
		let timestamp = message.timestamp.unwrap_or_else(now);
		let mut attachments = Vec::new();
		let mut sources = Vec::new();
		let mut filenames = BTreeSet::new();
		for (index, source) in message.attachments.iter().enumerate() {
			let ingested = ingest_source(source, job_id, index + 1, true)?;
			if !filenames.insert(ingested.filename.clone()) {
				return Err(BuildFailure::invalid("duplicate Wire-Filename in one Job"));
			}
			let record = ingested.record(SourceKind::Attachment, index + 1);
			attachments.push(AttachmentData {
				filename: ingested.filename.clone(),
				timestamp: ingested.timestamp,
				contents: ingested.contents,
			});
			sources.push(record);
		}
		let (kind, target, destination, seen_by, deliveries) = match message.kind {
			MessageKind::NetMail => {
				let destination = self.resolve_identity(&message.destination_or_area)?;
				let routes =
					routes_for(&self.configuration, &signer.reference).ok_or_else(|| {
						BuildFailure::permanent("local signing identity has no Routes block")
					})?;
				let (next_hop, mode, route_rule) =
					match message.next_hop.as_ref().unwrap_or(&NextHop::Route) {
						NextHop::Route => {
							let commitment = route_netmail(
								&self.configuration,
								routes,
								&destination,
								&[],
								&self.nodelist,
							)
							.map_err(|failure| BuildFailure::permanent(format!("{failure:?}")))?;
							(
								commitment.next_hop,
								if commitment.passive {
									DeliveryMode::Passive
								} else {
									DeliveryMode::Active
								},
								commitment.route_rule,
							)
						}
						NextHop::Active(value) => {
							if !self.has_usable_endpoint(value) {
								return Err(BuildFailure::permanent(
									"explicit Active next hop has no usable endpoint",
								));
							}
							(self.resolve_identity(value)?, DeliveryMode::Active, None)
						}
						NextHop::Passive(value) => {
							(self.resolve_identity(value)?, DeliveryMode::Passive, None)
						}
					};
				let configured = failure_policies(
					&self.configuration,
					routes,
					&signer.identity,
					&next_hop,
					route_rule,
					&self.nodelist,
				);
				let delivery = NewDelivery {
					local_identity: signer.identity.address.to_string(),
					next_hop: next_hop.address.to_string(),
					mode,
					class: message.class.clone().unwrap_or_else(|| "Normal".to_owned()),
					retry_at: None,
					policies: convert_policies(configured, message.failure_policy),
				};
				(
					JobKind::NetMail,
					JobTarget::Destination(destination.address.to_string()),
					Some(destination),
					Vec::new(),
					vec![delivery],
				)
			}
			MessageKind::EchoMail => {
				let deliveries = self.area_deliveries(
					&signer.reference,
					&signer.identity,
					&message.destination_or_area,
					false,
				)?;
				(
					JobKind::EchoMail,
					JobTarget::Area(message.destination_or_area.clone()),
					None,
					vec![signer.identity.address.to_string()],
					deliveries,
				)
			}
		};
		let reply_to = message
			.reply_to
			.as_ref()
			.map(|(address, identifier)| {
				Ok((
					address
						.parse::<Address>()
						.map_err(|_| BuildFailure::invalid("invalid Reply-To address"))?,
					identifier.clone(),
				))
			})
			.transpose()?;
		let item = build_originated_message(
			MessageData {
				destination,
				timestamp,
				to_user: message.to_user.clone(),
				from_user: message.from_user.clone(),
				subject: message.subject.clone(),
				text: message.message_text.clone(),
				area: (message.kind == MessageKind::EchoMail)
					.then(|| message.destination_or_area.clone()),
				attachments,
				legacy_attributes: message.legacy_attributes,
				timestamp_offset: message.timestamp_offset,
				tear_line: message.tear_line.clone(),
				origin_line: message.origin_line.clone(),
				message_id: message.message_id.clone(),
				reply_to,
				additional_kludge_lines: message.additional_kludge_lines.clone(),
			},
			&provenance,
			&signer.secret,
			random_u64()?,
			timestamp,
			SOFTWARE,
			&seen_by,
		)
		.map_err(|error| BuildFailure::invalid(error.to_string()))?;
		validate_item(&item, self.nodelist.as_ref())
			.map_err(|error| BuildFailure::invalid(error.to_string()))?
			.ok_or_else(|| BuildFailure::invalid("submission did not construct an item"))?;
		Ok(NewOutboundJob {
			identity,
			kind,
			target,
			local_identity: signer.identity.address.to_string(),
			item: item.encode(),
			deliveries,
			sources,
			created: timestamp,
			forward_inbound: None,
			forward_claim_token: None,
		})
	}

	fn build_file_job(
		&self,
		identity: SubmissionIdentity,
		file: &FileSubmission,
	) -> Result<NewOutboundJob, BuildFailure> {
		let (signer, provenance) =
			self.item_provenance(&file.origin, file.signed_origin.as_deref())?;
		validate_area_name(&file.area)?;
		let ingested = ingest_source(&file.source, "", 1, false)?;
		let deliveries =
			self.area_deliveries(&signer.reference, &signer.identity, &file.area, true)?;
		let created = now();
		let source_record = ingested.record(SourceKind::File, 1);
		let item = build_originated_file(
			StandaloneFileData {
				filename: ingested.filename.clone(),
				timestamp: ingested.timestamp,
				contents: ingested.contents,
				area: file.area.clone(),
				short_description: file.short_description.clone(),
				long_description_lines: file.long_description_lines.clone(),
				tear_line: file.tear_line.clone(),
				magic_word: file.magic_word.clone(),
				replaces: file.replaces.clone(),
			},
			&provenance,
			&signer.secret,
			random_u64()?,
			created,
			SOFTWARE,
			&[signer.identity.address.to_string()],
		)
		.map_err(|error| BuildFailure::invalid(error.to_string()))?;
		validate_item(&item, self.nodelist.as_ref())
			.map_err(|error| BuildFailure::invalid(error.to_string()))?
			.ok_or_else(|| BuildFailure::invalid("submission did not construct an item"))?;
		Ok(NewOutboundJob {
			identity,
			kind: JobKind::File,
			target: JobTarget::Area(file.area.clone()),
			local_identity: signer.identity.address.to_string(),
			item: item.encode(),
			deliveries,
			sources: vec![source_record],
			created,
			forward_inbound: None,
			forward_claim_token: None,
		})
	}

	fn build_forward_job(
		&self,
		identity: SubmissionIdentity,
		inbound_id: &str,
		claim_token: &str,
		context: &tith_store::BatchContext<'_>,
	) -> Result<NewOutboundJob, BuildFailure> {
		let created = now();
		let inbound = context
			.claimed_inbound(&identity.application, inbound_id, claim_token, created)
			.map_err(|error| {
				BuildFailure::invalid(format!("inbound claim is not current: {error}"))
			})?;
		if !matches!(
			inbound.record.authentication,
			tith_store::ItemAuthentication::OriginValid
				| tith_store::ItemAuthentication::SignedOriginValid
		) {
			return Err(BuildFailure::invalid(
				"Forward requires a valid end-to-end item signature",
			));
		}
		let signer = self
			.signers
			.values()
			.find(|signer| signer.identity.address.to_string() == inbound.record.local_identity)
			.ok_or_else(|| {
				BuildFailure::invalid("inbound receiving identity is no longer configured")
			})?;
		let roots = tith_wire::tlv::parse_sequence(&inbound.payload)
			.map_err(|error| BuildFailure::invalid(error.to_string()))?;
		let root = roots
			.first()
			.filter(|_| roots.len() == 1)
			.ok_or_else(|| BuildFailure::invalid("inbound payload is not one item"))?;
		let validated = validate_item(root, self.nodelist.as_ref())
			.map_err(|error| BuildFailure::invalid(error.to_string()))?
			.ok_or_else(|| BuildFailure::invalid("inbound payload is not a forwardable item"))?;
		let (kind, file_area) = match validated.kind {
			tith_wire::item::ItemKind::EchoMail => (JobKind::EchoMail, false),
			tith_wire::item::ItemKind::File => (JobKind::File, true),
			_ => {
				return Err(BuildFailure::invalid(
					"Forward requires EchoMail or standalone File",
				));
			}
		};
		let area = validated
			.area
			.clone()
			.ok_or_else(|| BuildFailure::invalid("distribution item has no Area"))?;
		let children = tith_wire::tlv::parse_sequence(&root.value)
			.map_err(|error| BuildFailure::invalid(error.to_string()))?;
		let mut seen_by: BTreeSet<String> = children
			.iter()
			.filter(|child| child.type_code == tith_wire::types::SEEN_BY)
			.map(|child| {
				String::from_utf8(child.value.clone())
					.map_err(|_| BuildFailure::invalid("SeenBy is not UTF-8"))
			})
			.collect::<Result<_, _>>()?;
		let mut deliveries =
			self.area_deliveries(&signer.reference, &signer.identity, &area, file_area)?;
		deliveries.retain(|copy| {
			copy.next_hop != inbound.record.peer && !seen_by.contains(&copy.next_hop)
		});
		seen_by.insert(signer.identity.address.to_string());
		seen_by.extend(deliveries.iter().map(|copy| copy.next_hop.clone()));
		let item = forward_item(
			root,
			&signer.identity,
			random_u64()?,
			created,
			SOFTWARE,
			&seen_by.into_iter().collect::<Vec<_>>(),
		)
		.map_err(|error| BuildFailure::invalid(error.to_string()))?;
		validate_item(&item, self.nodelist.as_ref())
			.map_err(|error| BuildFailure::invalid(error.to_string()))?
			.ok_or_else(|| BuildFailure::invalid("forwarding did not construct an item"))?;
		Ok(NewOutboundJob {
			identity,
			kind,
			target: JobTarget::Area(area),
			local_identity: signer.identity.address.to_string(),
			item: item.encode(),
			deliveries,
			sources: Vec::new(),
			created,
			forward_inbound: Some(inbound_id.to_owned()),
			forward_claim_token: Some(claim_token.to_owned()),
		})
	}

	fn signer(&self, value: &str) -> Result<&LocalSigner, BuildFailure> {
		self.signers
			.get(value)
			.ok_or_else(|| BuildFailure::invalid("unknown or unauthorized Origin"))
	}

	fn item_provenance<'a>(
		&'a self,
		origin: &str,
		signed_origin: Option<&str>,
	) -> Result<(&'a LocalSigner, ItemProvenance), BuildFailure> {
		let Some(signed_origin) = signed_origin else {
			let signer = self.signer(origin)?;
			return Ok((
				signer,
				ItemProvenance {
					origin: signer.identity.address.clone(),
					signer: Some(signer.identity.clone()),
				},
			));
		};
		let origin = origin
			.parse::<Address>()
			.map_err(|_| BuildFailure::invalid("invalid Origin address"))?;
		if origin.is_unlisted() {
			return Err(BuildFailure::invalid(
				"Signed-Origin requires a listed Origin address",
			));
		}
		if self.nodelist.public_key(&origin).is_some() {
			return Err(BuildFailure::invalid(
				"Signed-Origin cannot override the Origin nodelist key",
			));
		}
		let signer = self
			.signers
			.get(signed_origin)
			.ok_or_else(|| BuildFailure::invalid("unknown or unauthorized Signed-Origin"))?;
		Ok((
			signer,
			ItemProvenance {
				origin,
				signer: Some(signer.identity.clone()),
			},
		))
	}

	fn resolve_identity(&self, value: &str) -> Result<Identity, BuildFailure> {
		if let Some(name) = value.strip_prefix('@') {
			let peer = self
				.configuration
				.peers
				.get(name)
				.ok_or_else(|| BuildFailure::invalid("unknown Peer reference"))?;
			let public_key = if peer.address.is_unlisted() {
				peer.public_key
					.ok_or_else(|| BuildFailure::invalid("unlisted Peer has no public key"))?
			} else {
				self.nodelist
					.public_key(&peer.address)
					.ok_or_else(|| BuildFailure::permanent("listed Peer has no nodelist key"))?
			};
			return Ok(Identity {
				address: peer.address.clone(),
				public_key,
			});
		}
		let address: Address = value
			.parse()
			.map_err(|_| BuildFailure::invalid("invalid identity"))?;
		if address.is_unlisted() {
			return Err(BuildFailure::invalid(
				"unlisted identities require a Peer reference",
			));
		}
		let public_key = self
			.nodelist
			.public_key(&address)
			.ok_or_else(|| BuildFailure::permanent("identity has no nodelist public key"))?;
		Ok(Identity {
			address,
			public_key,
		})
	}

	fn has_usable_endpoint(&self, value: &str) -> bool {
		if let Some(name) = value.strip_prefix('@') {
			return self
				.configuration
				.peers
				.get(name)
				.is_some_and(|peer| !peer.endpoints.is_empty());
		}
		value.parse::<Address>().ok().is_some_and(|address| {
			self.nodelist
				.get(&address)
				.and_then(|entry| entry.tith.as_ref())
				.is_some_and(|service| {
					service
						.endpoints
						.iter()
						.any(tith_nodelist::Endpoint::is_usable)
				})
		})
	}

	fn area_deliveries(
		&self,
		local: &IdentityRef,
		local_identity: &Identity,
		area_name: &str,
		file_area: bool,
	) -> Result<Vec<NewDelivery>, BuildFailure> {
		let areas = self
			.configuration
			.areas
			.iter()
			.find(|areas| &areas.local == local)
			.ok_or_else(|| BuildFailure::permanent("local signing identity has no Areas block"))?;
		let area = areas
			.areas
			.iter()
			.find(|area| area.file_area == file_area && area.name == area_name)
			.ok_or_else(|| BuildFailure::permanent("undefined area"))?;
		if area.send_to.is_empty() {
			return Err(BuildFailure::permanent("area has no Send-To link"));
		}
		let routes = routes_for(&self.configuration, local)
			.ok_or_else(|| BuildFailure::permanent("local signing identity has no Routes block"))?;
		area.send_to
			.iter()
			.map(|link| {
				let peer = self
					.configuration
					.peers
					.get(&link.peer)
					.ok_or_else(|| BuildFailure::invalid("unknown Send-To Peer"))?;
				let identity = self.resolve_identity(&format!("@{}", link.peer))?;
				Ok(NewDelivery {
					local_identity: local_identity.address.to_string(),
					next_hop: identity.address.to_string(),
					mode: if peer.endpoints.is_empty() {
						DeliveryMode::Passive
					} else {
						DeliveryMode::Active
					},
					class: link.class.clone(),
					retry_at: None,
					policies: convert_policies(
						failure_policies(
							&self.configuration,
							routes,
							local_identity,
							&identity,
							None,
							&self.nodelist,
						),
						None,
					),
				})
			})
			.collect()
	}
}

struct IngestedSource {
	filename: String,
	timestamp: Option<u64>,
	contents: Vec<u8>,
	path: String,
	file_identity: Vec<u8>,
}

impl IngestedSource {
	fn record(&self, kind: SourceKind, index: usize) -> SourceRecord {
		SourceRecord {
			index: index as u64,
			kind,
			wire_filename: self.filename.clone(),
			path: Some(self.path.clone()),
			disposition: SourceDisposition::Keep,
			cleanup: CleanupState::NotRequested,
			file_identity: self.file_identity.clone(),
		}
	}
}

fn ingest_source(
	source: &SourceSubmission,
	job_id: &str,
	index: usize,
	attachment: bool,
) -> Result<IngestedSource, BuildFailure> {
	if source.ingestion != Ingestion::Copy || source.disposition != IpcSourceDisposition::Keep {
		return Err(BuildFailure::invalid(
			"Move, Delete, and Truncate are not available over this service",
		));
	}
	let Source::Path(path) = &source.source else {
		return Err(BuildFailure::invalid(
			"Source-Handle is unavailable over this binding",
		));
	};
	if path.contains('\0') {
		return Err(BuildFailure::invalid("Source-Path contains Null"));
	}
	let mut input = File::open(path)
		.map_err(|error| BuildFailure::temporary(format!("cannot open Source-Path: {error}")))?;
	let before = input
		.metadata()
		.map_err(|error| BuildFailure::temporary(format!("cannot inspect Source: {error}")))?;
	if !before.is_file() {
		return Err(BuildFailure::invalid("Source is not a regular file"));
	}
	let mut contents = Vec::new();
	input
		.read_to_end(&mut contents)
		.map_err(|error| BuildFailure::temporary(format!("cannot read Source: {error}")))?;
	let after = input
		.metadata()
		.map_err(|error| BuildFailure::temporary(format!("cannot recheck Source: {error}")))?;
	if before.len() != after.len()
		|| after.len() != contents.len() as u64
		|| before.modified().ok() != after.modified().ok()
	{
		return Err(BuildFailure::temporary("Source changed during ingestion"));
	}
	if source
		.expected_size
		.is_some_and(|size| size != contents.len() as u64)
	{
		return Err(BuildFailure::invalid("Expected-Size does not match Source"));
	}
	if let Some(expected) = &source.expected_hash {
		if expected.len() != 43 || expected.contains('=') {
			return Err(BuildFailure::invalid("invalid Expected-Hash"));
		}
		let expected = STANDARD_NO_PAD
			.decode(expected)
			.map_err(|_| BuildFailure::invalid("invalid Expected-Hash"))?;
		let actual = hash_submission_file(&contents)
			.map_err(|error| BuildFailure::temporary(error.to_string()))?;
		if expected.as_slice() != actual.as_bytes() {
			return Err(BuildFailure::invalid("Expected-Hash does not match Source"));
		}
	}
	let filename = match &source.wire_filename {
		WireFilename::Generate if attachment => format!("{}-{index}.pkt", &job_id[1..]),
		WireFilename::Generate => {
			return Err(BuildFailure::invalid(
				"standalone File requires Wire-Filename",
			));
		}
		WireFilename::Name(value) if !value.is_empty() && !value.contains(['/', '\\']) => {
			value.clone()
		}
		WireFilename::Name(_) => return Err(BuildFailure::invalid("invalid Wire-Filename")),
	};
	let timestamp = source.timestamp.or_else(|| {
		before
			.modified()
			.ok()
			.and_then(|value| value.duration_since(UNIX_EPOCH).ok())
			.map(|value| value.as_secs())
	});
	Ok(IngestedSource {
		filename,
		timestamp,
		contents,
		path: path.clone(),
		file_identity: file_identity(&before),
	})
}

#[cfg(unix)]
fn file_identity(metadata: &std::fs::Metadata) -> Vec<u8> {
	use std::os::unix::fs::MetadataExt;
	let mut output = Vec::with_capacity(16);
	output.extend_from_slice(&metadata.dev().to_be_bytes());
	output.extend_from_slice(&metadata.ino().to_be_bytes());
	output
}

#[cfg(not(unix))]
fn file_identity(_: &std::fs::Metadata) -> Vec<u8> {
	Vec::new()
}

fn convert_policies(
	configured: [tith_config::FailurePolicy; 5],
	override_policy: Option<FailureOverride>,
) -> [FailurePolicy; 5] {
	if let Some(FailureOverride::Policy {
		disposition,
		notification,
	}) = override_policy
	{
		let selected = FailurePolicy {
			disposition: match disposition {
				IpcDisposition::DeadLetter => FailureDisposition::DeadLetter,
				IpcDisposition::Discard => FailureDisposition::Discard,
			},
			notification: match notification {
				IpcNotification::None => FailureNotification::None,
				IpcNotification::Sender => FailureNotification::Sender,
				IpcNotification::OriginSysop => FailureNotification::OriginSysop,
				IpcNotification::Both => FailureNotification::Both,
			},
		};
		return [selected; 5];
	}
	configured.map(|default| FailurePolicy {
		disposition: match default.disposition {
			tith_config::Disposition::DeadLetter => FailureDisposition::DeadLetter,
			tith_config::Disposition::Discard => FailureDisposition::Discard,
		},
		notification: match default.notification {
			tith_config::Notification::None => FailureNotification::None,
			tith_config::Notification::Sender => FailureNotification::Sender,
			tith_config::Notification::OriginSysop => FailureNotification::OriginSysop,
			tith_config::Notification::Both => FailureNotification::Both,
		},
	})
}

fn random_u64() -> Result<u64, BuildFailure> {
	let mut bytes = [0; 8];
	random_bytes(&mut bytes).map_err(|error| BuildFailure::temporary(error.to_string()))?;
	Ok(u64::from_be_bytes(bytes))
}

fn validate_area_name(value: &str) -> Result<(), BuildFailure> {
	if value.is_empty()
		|| value.trim_matches([' ', '\t']) != value
		|| value.chars().any(char::is_control)
	{
		Err(BuildFailure::invalid("invalid Area name"))
	} else {
		Ok(())
	}
}

fn now() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_or(0, |value| value.as_secs())
}

struct BuildFailure {
	kind: JobBuildFailure,
	description: String,
}

impl BuildFailure {
	fn invalid(description: impl Into<String>) -> Self {
		Self {
			kind: JobBuildFailure::Invalid,
			description: description.into(),
		}
	}

	fn permanent(description: impl Into<String>) -> Self {
		Self {
			kind: JobBuildFailure::Permanent,
			description: description.into(),
		}
	}

	fn temporary(description: impl Into<String>) -> Self {
		Self {
			kind: JobBuildFailure::Temporary,
			description: description.into(),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use base64::engine::general_purpose::STANDARD_NO_PAD;
	use tith_crypto::SigningKeyPair;
	use tith_store::{CommitOutcome, InboundStore};
	use tith_wire::item::{ItemKind, validate_item};
	use tith_wire::tlv::parse_sequence;

	#[test]
	fn submits_signs_routes_and_recovers_a_netmail_job() {
		let origin_keys = SigningKeyPair::generate().unwrap();
		let destination_keys = SigningKeyPair::generate().unwrap();
		let peers = format!(
			"Peer local\nAddress p2p#-1\nPublic-Key {}\nEnd\nPeer destination\nAddress p2p#-1\nPublic-Key {}\nEndpoint localhost 24555\nEnd\n",
			STANDARD_NO_PAD.encode(origin_keys.public.as_bytes()),
			STANDARD_NO_PAD.encode(destination_keys.public.as_bytes())
		);
		let configuration = Arc::new(
			ConfigurationSet::parse(
				&peers,
				"Routes @local\nRoute All Using Direct Hold\nEnd\n",
				"",
				"",
			)
			.unwrap(),
		);
		let origin = Identity {
			address: Address::unlisted("p2p".to_owned()).unwrap(),
			public_key: origin_keys.public,
		};
		let engine = SubmissionEngine::new(
			Arc::clone(&configuration),
			Arc::new(Nodelist::default()),
			[(
				"@local".to_owned(),
				LocalSigner {
					reference: IdentityRef::Peer("local".to_owned()),
					identity: origin,
					secret: Arc::new(origin_keys.secret),
				},
			)],
		);
		let request = SubmissionRequest::parse(
			b"TITH-IPC 1\nSubmit\nJob\nApplication \"mailer\"\nIdempotency-Key \"one\"\nOrigin \"@local\"\nDestination \"@destination\"\nTo-User \"You\"\nFrom-User \"Me\"\nSubject \"Hello\"\nMessage-Text \"World\"\nEnd\nEnd\n",
		)
		.unwrap();
		let unique = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_nanos();
		let path = std::env::temp_dir().join(format!("tith-submit-{unique}.redb"));
		let inbound = InboundStore::create(&path).unwrap();
		let store = inbound.outbound().unwrap();
		let BatchCommit::Committed(outcomes) = engine.submit(&request, &store).unwrap() else {
			panic!("commit expected");
		};
		let CommitOutcome::New { job_id, .. } = &outcomes[0] else {
			panic!("new job expected");
		};
		let encoded = store.item(job_id).unwrap();
		let values = parse_sequence(&encoded).unwrap();
		let validated = validate_item(&values[0], &|_: &Address| None)
			.unwrap()
			.unwrap();
		assert_eq!(validated.kind, ItemKind::NetMail);
		assert_eq!(
			validated.destination.unwrap().public_key,
			destination_keys.public
		);
		assert!(matches!(
			engine.submit(&request, &store).unwrap(),
			BatchCommit::Committed(ref values)
				if matches!(values[0], CommitOutcome::Existing { .. })
		));
		let gateway_request = SubmissionRequest::parse(
			b"TITH-IPC 1\nSubmit\nJob\nApplication \"mailer\"\nIdempotency-Key \"gateway\"\nOrigin \"fidonet#1/100\"\nSigned-Origin \"@local\"\nDestination \"@destination\"\nTo-User \"You\"\nFrom-User \"Legacy\"\nEnd\nEnd\n",
		)
		.unwrap();
		let BatchCommit::Committed(gateway_outcomes) =
			engine.submit(&gateway_request, &store).unwrap()
		else {
			panic!("gateway commit expected");
		};
		let CommitOutcome::New { job_id, .. } = &gateway_outcomes[0] else {
			panic!("new gateway job expected");
		};
		let encoded = store.item(job_id).unwrap();
		let values = parse_sequence(&encoded).unwrap();
		let validated = validate_item(&values[0], &|_: &Address| None)
			.unwrap()
			.unwrap();
		let provenance = validated.provenance.unwrap();
		assert_eq!(provenance.origin, "fidonet#1/100".parse().unwrap());
		assert_eq!(
			provenance.signer.unwrap().address,
			Address::unlisted("p2p".to_owned()).unwrap()
		);
		drop(store);
		drop(inbound);
		std::fs::remove_file(path).unwrap();
	}
}
