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
	DeliveryMode as IpcDeliveryMode, FailureDisposition as IpcDisposition,
	FailureNotification as IpcNotification, FailureOverride, FileRequestSubmission, FileSubmission,
	FileTarget, Ingestion, MessageKind, MessageSubmission, NextHop, PeerDelivery, Source,
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
	AttachmentData, ItemProvenance, MessageData, StandaloneFileData, build_file_request,
	build_originated_file, build_originated_message, forward_item, validate_item,
};

pub const SOFTWARE: &str = "tithd 0.1.0";

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
			None,
			&self.nodelist,
		);
		Ok(NewDelivery {
			local_identity: signer.identity.address.to_string(),
			next_hop: target.address.to_string(),
			next_hop_key: unlisted_key(&target),
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
			SubmissionBody::FileRequest(request) => {
				self.build_file_request_job(identity.clone(), request)
			}
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
					None,
					&self.nodelist,
				);
				let delivery = NewDelivery {
					local_identity: signer.identity.address.to_string(),
					next_hop: next_hop.address.to_string(),
					next_hop_key: unlisted_key(&next_hop),
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
					// An unlisted local identity is not representable in SeenBy.
					if signer.identity.address.is_unlisted() {
						Vec::new()
					} else {
						vec![signer.identity.address.clone()]
					},
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
				text: message_text(&message.message_text),
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
		let area = match &file.target {
			FileTarget::Area(area) => {
				validate_area_name(area)?;
				Some(area.clone())
			}
			FileTarget::Peer(_) => None,
		};
		let ingested = ingest_source(&file.source, "", 1, false)?;
		let (kind, target, deliveries) = match &file.target {
			FileTarget::Area(area) => (
				JobKind::File,
				JobTarget::Area(area.clone()),
				self.area_deliveries(&signer.reference, &signer.identity, area, true)?,
			),
			FileTarget::Peer(peer) => {
				let (target, delivery) = self.direct_delivery(signer, peer)?;
				(JobKind::PeerFile, target, vec![delivery])
			}
		};
		let created = now();
		let source_record = ingested.record(SourceKind::File, 1);
		// A distribution File repeats SeenBy, but an unlisted identity is still
		// omitted. A peer-addressed File has no SeenBy at all.
		let seen_by: &[Address] = if area.is_none() || signer.identity.address.is_unlisted() {
			&[]
		} else {
			std::slice::from_ref(&signer.identity.address)
		};
		let item = build_originated_file(
			StandaloneFileData {
				filename: ingested.filename.clone(),
				timestamp: ingested.timestamp,
				contents: ingested.contents,
				area,
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
			seen_by,
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
			sources: vec![source_record],
			created,
			forward_inbound: None,
			forward_claim_token: None,
		})
	}

	fn build_file_request_job(
		&self,
		identity: SubmissionIdentity,
		request: &FileRequestSubmission,
	) -> Result<NewOutboundJob, BuildFailure> {
		// TTS-0005 section 3 type 66 has no Origin or Signature, so the local
		// identity supplies only the AKA and routing configuration. There is no
		// SignedOrigin to resolve and nothing to sign.
		let signer = self.signer(&request.origin)?;
		if request.filename.is_empty() || request.filename.contains(['/', '\\']) {
			return Err(BuildFailure::invalid(
				"FileRequest Filename must be nonempty and contain no path component",
			));
		}
		let (target, delivery) = self.direct_delivery(signer, &request.delivery)?;
		let item = build_file_request(&request.filename, request.newer_than, random_u64()?)
			.map_err(|error| BuildFailure::invalid(error.to_string()))?;
		validate_item(&item, self.nodelist.as_ref())
			.map_err(|error| BuildFailure::invalid(error.to_string()))?
			.ok_or_else(|| BuildFailure::invalid("submission did not construct an item"))?;
		Ok(NewOutboundJob {
			identity,
			kind: JobKind::FileRequest,
			target,
			local_identity: signer.identity.address.to_string(),
			item: item.encode(),
			deliveries: vec![delivery],
			sources: Vec::new(),
			created: now(),
			forward_inbound: None,
			forward_claim_token: None,
		})
	}

	/// The one copy a Peer-File or `FileRequest` commits to its Destination.
	///
	/// TSP-0006 section 6: no Route method applies, because the item carries no
	/// Destination a receiving node could route on. Absent an explicit mode the
	/// copy is Active when the Destination has a usable endpoint at commitment
	/// and Passive otherwise, which is the rule an area copy already uses.
	fn direct_delivery(
		&self,
		signer: &LocalSigner,
		peer: &PeerDelivery,
	) -> Result<(JobTarget, NewDelivery), BuildFailure> {
		let destination = self.resolve_identity(&peer.destination)?;
		let usable = self.has_usable_endpoint(&peer.destination);
		if peer.mode == Some(IpcDeliveryMode::Active) && !usable {
			return Err(BuildFailure::permanent(
				"explicit Active delivery has no usable endpoint",
			));
		}
		// Absent, the mode follows the endpoint, which is the same rule an area
		// copy uses; an explicit line overrides it in either direction.
		let mode = match (peer.mode, usable) {
			(Some(IpcDeliveryMode::Active), _) | (None, true) => DeliveryMode::Active,
			(Some(IpcDeliveryMode::Passive), _) | (None, false) => DeliveryMode::Passive,
		};
		let routes = routes_for(&self.configuration, &signer.reference)
			.ok_or_else(|| BuildFailure::permanent("local signing identity has no Routes block"))?;
		let configured = failure_policies(
			&self.configuration,
			routes,
			&signer.identity,
			&destination,
			// No Route line selected this hop, so no Route override applies.
			None,
			None,
			&self.nodelist,
		);
		Ok((
			JobTarget::Destination(destination.address.to_string()),
			NewDelivery {
				local_identity: signer.identity.address.to_string(),
				next_hop: destination.address.to_string(),
				next_hop_key: unlisted_key(&destination),
				mode,
				class: peer.class.clone().unwrap_or_else(|| "Normal".to_owned()),
				retry_at: None,
				policies: convert_policies(configured, peer.failure_policy),
			},
		))
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
		// TSP-0006 section 3: a peer-addressed File owes no onward copy, so a
		// Forward Job naming one is Invalid rather than an area lookup failure.
		let area = validated.area.clone().ok_or_else(|| {
			BuildFailure::invalid("Forward requires a distribution item, and this one has no Area")
		})?;
		let children = tith_wire::tlv::parse_sequence(&root.value)
			.map_err(|error| BuildFailure::invalid(error.to_string()))?;
		// Each SeenBy is a Trimmed Collection, so it must be expanded before an
		// address can be compared against it.
		let mut seen_by: BTreeSet<Address> = BTreeSet::new();
		for child in &children {
			if child.type_code == tith_wire::types::SEEN_BY {
				seen_by.extend(
					tith_wire::item::seen_by_addresses(child)
						.map_err(|error| BuildFailure::invalid(error.to_string()))?,
				);
			}
		}
		let mut deliveries =
			self.area_deliveries(&signer.reference, &signer.identity, &area, file_area)?;
		deliveries.retain(|copy| {
			copy.next_hop != inbound.record.peer
				&& !copy
					.next_hop
					.parse::<Address>()
					.is_ok_and(|address| seen_by.contains(&address))
		});
		// TSP-0002 section 7: the distributor adds each listed identity known to
		// have or to receive the item -- its local identity, the immediate
		// incoming Peer, and every Send-To Peer it creates a copy for. Unlisted
		// identities are not representable and are omitted.
		let mut record_seen = |address: Address| {
			if !address.is_unlisted() {
				seen_by.insert(address);
			}
		};
		record_seen(signer.identity.address.clone());
		if let Ok(peer) = inbound.record.peer.parse::<Address>() {
			record_seen(peer);
		}
		for copy in &deliveries {
			record_seen(
				copy.next_hop
					.parse()
					.map_err(|_| BuildFailure::invalid("delivery next hop is not an address"))?,
			);
		}
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
					next_hop_key: unlisted_key(&identity),
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
	configured_policies(configured)
}

/// Maps configured failure policies onto their durable form.
pub fn configured_policies(configured: [tith_config::FailurePolicy; 5]) -> [FailurePolicy; 5] {
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

/// The next hop's key, recorded only when its address is the unlisted one.
///
/// TSP-0002 section 9 requires a copy record "its exact next-hop address and
/// unlisted `PublicKey`, if any". A listed address takes its key from the current
/// nodelist, which a stored copy must not override.
fn unlisted_key(identity: &Identity) -> Option<tith_crypto::PublicKey> {
	identity
		.address
		.is_unlisted()
		.then_some(identity.public_key)
}

fn now() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_or(0, |value| value.as_secs())
}

/// The submitted `Message-Text` as the `MessageText` TTS-0005 defines.
///
/// TSP-0006 section 3: `Message-Text` is the text of the message and not that
/// encoding, so the service supplies the final U+000A of a nonempty value which
/// lacks one and folds each CRLF pair and remaining U+000D into one U+000A. An
/// Application never has to know the rule, and none is refused for writing its
/// last paragraph without a trailing line break. This runs before the Message is
/// constructed, so it never alters signed content.
fn message_text(submitted: &str) -> String {
	if submitted.is_empty() {
		return String::new();
	}
	let mut text = submitted.replace("\r\n", "\n").replace('\r', "\n");
	if !text.ends_with('\n') {
		text.push('\n');
	}
	text
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
		// TSP-0006 section 3: the request said Message-Text "World", and TTS-0005
		// type 106 stores paragraphs each terminated by U+000A, so the service
		// supplied the terminator rather than refusing the Application.
		let read = tith_wire::item::read_message(&values[0], &|_: &Address| None).unwrap();
		assert_eq!(read.data.text, "World\n");
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

		// TTS-0005 section 3 type 64 makes TearLine EchoMail control information,
		// so a NetMail Job asking for one is Invalid rather than silently
		// producing a Message no legacy conversion could represent.
		let tear_line = SubmissionRequest::parse(
			b"TITH-IPC 1\nSubmit\nJob\nApplication \"mailer\"\nIdempotency-Key \"tear\"\nOrigin \"@local\"\nDestination \"@destination\"\nTo-User \"You\"\nFrom-User \"Me\"\nTear-Line \"tosser 1.0\"\nEnd\nEnd\n",
		)
		.unwrap();
		match engine.submit(&tear_line, &store) {
			Err(StoreError::JobBuild {
				kind, description, ..
			}) => {
				assert_eq!(kind, JobBuildFailure::Invalid);
				assert!(description.contains("TearLine"), "{description}");
			}
			other => panic!("expected an Invalid job build, got {other:?}"),
		}
		drop(store);
		drop(inbound);
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn forwarding_records_every_listed_identity_in_one_seen_by() {
		// TSP-0002 section 7: the distributor adds its local identity, the
		// immediate incoming Peer, and every listed Send-To Peer it creates a
		// copy for, in exactly one SeenBy, omitting unlisted identities.
		let local_keys = SigningKeyPair::from_seed(&[40; 32]).unwrap();
		let author_keys = SigningKeyPair::from_seed(&[41; 32]).unwrap();
		let incoming_keys = SigningKeyPair::from_seed(&[42; 32]).unwrap();
		let downstream_keys = SigningKeyPair::from_seed(&[43; 32]).unwrap();

		let local: Address = "fidonet#1:104/36".parse().unwrap();
		let author: Address = "fidonet#1:104/99".parse().unwrap();
		let incoming: Address = "fidonet#1:104/1".parse().unwrap();
		let downstream: Address = "fidonet#1:104/7".parse().unwrap();

		let peers = format!(
			"Peer local\nAddress {local}\nEnd\nPeer incoming\nAddress {incoming}\nEnd\n\
			 Peer downstream\nAddress {downstream}\nEnd\nPeer anon\nAddress p2p#-1\nPublic-Key {}\nEnd\n",
			STANDARD_NO_PAD.encode(downstream_keys.public.as_bytes())
		);
		let areas = format!(
			"Areas {local}\nEchoArea SYNCHRONET\nReceive-From @incoming\nSend-To @incoming\n\
			 Send-To @downstream\nSend-To @anon\nEnd\nEnd\n"
		);
		let configuration = Arc::new(
			ConfigurationSet::parse(
				&peers,
				&format!("Routes {local}\nRoute All Using Direct Hold\nEnd\n"),
				&areas,
				"",
			)
			.unwrap(),
		);
		// Every listed address resolves from the nodelist; the unlisted Peer
		// carries its own key in configuration.
		let entry = |number: u16, keys: &SigningKeyPair| {
			format!(
				"\t{number}\tNode\tLocation\tSysop\t\tCM\t\tIIH:mail.example:24554:{}\t\t\n",
				STANDARD_NO_PAD.encode(keys.public.as_bytes())
			)
		};
		let nodelist = Arc::new(
			Nodelist::parse(
				"fidonet",
				&format!(
					"Zone\t1\tNode\tLocation\tSysop\t\tCM\t\t\t\t\n\
					 Host\t104\tNode\tLocation\tSysop\t\tCM\t\t\t\t\n{}{}{}{}",
					entry(1, &incoming_keys),
					entry(7, &downstream_keys),
					entry(36, &local_keys),
					entry(99, &author_keys)
				),
			)
			.unwrap(),
		);

		// An EchoMail signed by its author, already seen by one other node.
		let item = build_originated_message(
			MessageData {
				destination: None,
				timestamp: 1_755_518_400,
				to_user: "All".to_owned(),
				from_user: "Author".to_owned(),
				subject: "Hello".to_owned(),
				text: "Body\n".to_owned(),
				area: Some("SYNCHRONET".to_owned()),
				attachments: Vec::new(),
				legacy_attributes: None,
				timestamp_offset: None,
				tear_line: None,
				origin_line: None,
				message_id: None,
				reply_to: None,
				additional_kludge_lines: Vec::new(),
			},
			&ItemProvenance {
				origin: author.clone(),
				signer: Some(Identity {
					address: author.clone(),
					public_key: author_keys.public,
				}),
			},
			&author_keys.secret,
			5,
			1_755_518_400,
			"peer 1.0",
			&["fidonet#1:104/50".parse().unwrap()],
		)
		.unwrap();

		let unique = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_nanos();
		let path = std::env::temp_dir().join(format!("tith-forward-{unique}.redb"));
		let inbound_store = InboundStore::create(&path).unwrap();
		let record = inbound_store
			.insert(tith_store::NewInbound {
				application: "tosser",
				local_identity: &local.to_string(),
				peer: &incoming.to_string(),
				peer_key: incoming_keys.public,
				received: 1_755_518_400,
				authentication: tith_store::ItemAuthentication::OriginValid,
				payload: &item.encode(),
			})
			.unwrap();
		let claim = match inbound_store.claim("tosser", "worker", now(), 300).unwrap() {
			tith_store::ClaimResult::Completed(claim) => claim,
			other => panic!("expected a claim, got {other:?}"),
		};
		assert_eq!(claim.inbound_id, record.inbound_id);

		let engine = SubmissionEngine::new(
			Arc::clone(&configuration),
			Arc::clone(&nodelist),
			[(
				local.to_string(),
				LocalSigner {
					reference: IdentityRef::Listed(local.clone()),
					identity: Identity {
						address: local.clone(),
						public_key: local_keys.public,
					},
					secret: Arc::new(local_keys.secret),
				},
			)],
		);
		let request = SubmissionRequest::parse(
			format!(
				"TITH-IPC 1\nSubmit-Items\nJob Forward\nApplication \"tosser\"\nIdempotency-Key \"f1\"\nInbound {} {}\nEnd\nEnd\n",
				claim.inbound_id, claim.claim_token
			)
			.as_bytes(),
		)
		.unwrap();
		let store = inbound_store.outbound().unwrap();
		let BatchCommit::Committed(outcomes) = engine.submit(&request, &store).unwrap() else {
			panic!("commit expected");
		};
		let CommitOutcome::New { job_id, .. } = &outcomes[0] else {
			panic!("new job expected");
		};

		let encoded = store.item(job_id).unwrap();
		let values = parse_sequence(&encoded).unwrap();
		let children = parse_sequence(&values[0].value).unwrap();
		let seen: Vec<_> = children
			.iter()
			.filter(|child| child.type_code == tith_wire::types::SEEN_BY)
			.collect();
		assert_eq!(seen.len(), 1, "section 7 requires exactly one SeenBy");
		let addresses = tith_wire::item::seen_by_addresses(seen[0]).unwrap();

		// The existing SeenBy address is retained.
		assert!(addresses.contains(&"fidonet#1:104/50".parse().unwrap()));
		// The local identity.
		assert!(addresses.contains(&local), "{addresses:?}");
		// The immediate incoming Peer, which is also pruned from the copy set.
		assert!(
			addresses.contains(&incoming),
			"the incoming peer is missing: {addresses:?}"
		);
		// A listed Send-To Peer which receives a copy.
		assert!(addresses.contains(&downstream), "{addresses:?}");
		// The unlisted Send-To Peer is not representable and is omitted.
		assert!(
			!addresses.iter().any(Address::is_unlisted),
			"an unlisted identity reached SeenBy: {addresses:?}"
		);

		// No copy is created for the immediate incoming Peer.
		let job = store.query(job_id).unwrap();
		assert!(
			!job.deliveries
				.iter()
				.any(|copy| copy.next_hop == incoming.to_string()),
			"a copy was created back toward the incoming peer"
		);
		std::fs::remove_file(path).unwrap();
	}

	#[test]
	fn a_peer_file_and_a_file_request_commit_one_copy_to_their_destination() {
		let local_keys = SigningKeyPair::from_seed(&[50; 32]).unwrap();
		let reachable_keys = SigningKeyPair::from_seed(&[51; 32]).unwrap();
		let unreachable_keys = SigningKeyPair::from_seed(&[52; 32]).unwrap();
		let local = Address::unlisted("p2p".to_owned()).unwrap();
		// Every identity is unlisted, so no nodelist is needed: each carries its
		// own key, which is exactly what tells two peers sharing `p2p#-1` apart
		// and what a held copy has to record.
		let peers = format!(
			"Peer local\nAddress p2p#-1\nPublic-Key {}\nEnd\n\
			 Peer reachable\nAddress p2p#-1\nPublic-Key {}\nEndpoint localhost 24555\nEnd\n\
			 Peer unreachable\nAddress p2p#-1\nPublic-Key {}\nEnd\n",
			STANDARD_NO_PAD.encode(local_keys.public.as_bytes()),
			STANDARD_NO_PAD.encode(reachable_keys.public.as_bytes()),
			STANDARD_NO_PAD.encode(unreachable_keys.public.as_bytes())
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
		let engine = SubmissionEngine::new(
			Arc::clone(&configuration),
			Arc::new(Nodelist::default()),
			[(
				"@local".to_owned(),
				LocalSigner {
					reference: IdentityRef::Peer("local".to_owned()),
					identity: Identity {
						address: local.clone(),
						public_key: local_keys.public,
					},
					secret: Arc::new(local_keys.secret),
				},
			)],
		);

		let unique = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_nanos();
		let directory = std::env::temp_dir().join(format!("tith-peer-{unique}"));
		std::fs::create_dir_all(&directory).unwrap();
		let source = directory.join("bundle.su0");
		std::fs::write(&source, b"arcmail").unwrap();
		let path = directory.join("state.redb");
		let inbound = InboundStore::create(&path).unwrap();
		let store = inbound.outbound().unwrap();

		// A peer with an endpoint gets an Active copy; one without gets Passive,
		// which is the rule TSP-0006 section 6 states for an absent Next-Hop. An
		// explicit Passive overrides the reachable peer.
		// A path is data, so it is quoted by the writer rather than by hand. A
		// Windows path is full of reverse solidus, which the quoted-string
		// grammar would otherwise read as escape sequences.
		let source = tith_ipc::quote(&source.to_string_lossy());
		let request = SubmissionRequest::parse(
			format!(
				"TITH-IPC 1\nSubmit-Items\n\
				 Job Peer-File\nApplication \"bso\"\nIdempotency-Key \"arc\"\nOrigin \"@local\"\n\
				 Destination \"@reachable\"\nFile\nSource-Path {source}\n\
				 Wire-Filename \"bundle.su0\"\nEnd\nEnd\n\
				 Job Peer-File\nApplication \"bso\"\nIdempotency-Key \"held\"\nOrigin \"@local\"\n\
				 Destination \"@unreachable\"\nFile\nSource-Path {source}\n\
				 Wire-Filename \"bundle.su0\"\nEnd\nEnd\n\
				 Job Peer-File\nApplication \"bso\"\nIdempotency-Key \"forced\"\nOrigin \"@local\"\n\
				 Destination \"@reachable\"\nNext-Hop Passive\nFile\nSource-Path {source}\n\
				 Wire-Filename \"bundle.su0\"\nEnd\nEnd\n\
				 Job FileRequest\nApplication \"bso\"\nIdempotency-Key \"req\"\nOrigin \"@local\"\n\
				 Destination \"@reachable\"\nFilename \"nodediff.zip\"\nNewer-Than 1755400000\nEnd\n\
				 End\n"
			)
			.as_bytes(),
		)
		.unwrap();
		let BatchCommit::Committed(outcomes) = engine.submit(&request, &store).unwrap() else {
			panic!("commit expected");
		};
		let ids: Vec<&str> = outcomes
			.iter()
			.map(|outcome| {
				let CommitOutcome::New { job_id, .. } = outcome else {
					panic!("new job expected");
				};
				job_id.as_str()
			})
			.collect();

		for (id, expected) in ids.iter().zip([
			DeliveryMode::Active,
			DeliveryMode::Passive,
			DeliveryMode::Passive,
			DeliveryMode::Active,
		]) {
			let job = store.query_for("bso", id).unwrap();
			assert_eq!(job.deliveries.len(), 1, "{id} has more than one copy");
			assert_eq!(job.deliveries[0].mode, expected, "{id} has the wrong mode");
			// The next hop is the Destination itself; there is nowhere else to go.
			assert!(matches!(
				&job.target,
				JobTarget::Destination(value) if value == &job.deliveries[0].next_hop
			));
		}
		assert_eq!(
			store.query_for("bso", ids[0]).unwrap().kind,
			JobKind::PeerFile
		);

		// The Peer-File carries no Area, Via, or SeenBy, and the FileRequest is
		// the unsigned request TTS-0005 type 66 defines.
		let values = parse_sequence(&store.item(ids[0]).unwrap()).unwrap();
		let validated = validate_item(&values[0], &|_: &Address| None)
			.unwrap()
			.unwrap();
		assert_eq!(validated.kind, ItemKind::File);
		assert_eq!(validated.area, None);

		let request_job = store.query_for("bso", ids[3]).unwrap();
		assert_eq!(request_job.kind, JobKind::FileRequest);
		assert!(
			request_job.sources.is_empty(),
			"a FileRequest has no Source"
		);
		let values = parse_sequence(&store.item(ids[3]).unwrap()).unwrap();
		let read = tith_wire::item::read_file_request(&values[0]).unwrap();
		assert_eq!(read.filename, "nodediff.zip");
		assert_eq!(read.timestamp, Some(1_755_400_000));

		drop(store);
		drop(inbound);
		std::fs::remove_dir_all(directory).unwrap();
	}
}
