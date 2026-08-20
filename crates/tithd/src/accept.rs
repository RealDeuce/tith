//! Storing an authenticated item and answering for it.
//!
//! An item reaches this node two ways: a peer connects and sends it, or this
//! node polls a peer and the peer returns it. TSP-0002 draws no distinction
//! between them — the same authorization applies and the same response is owed
//! — so both the listener and the outbound driver dispatch through here.

use std::error::Error;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use tith_config::{ConfigurationSet, IdentityRef, RelayAction, RelayRule};
use tith_crypto::{TlvHash, hash_tlv, random_bytes};
use tith_nodelist::Nodelist;
use tith_router::{RouteFailure, failure_policies, route_netmail, routes_for, selector_matches};
use tith_store::{
	AcceptResult, BatchCommit, DeliveryMode, InboundStore, JobKind, JobTarget, NewDelivery,
	NewInbound, NewOutboundJob, SubmissionClass, SubmissionIdentity,
};
use tith_wire::bundle::{Identity, KeyResolver};
use tith_wire::item::{
	ItemKind, RejectionReason, SignedItemIdentity, ValidatedItem, accepted, forward_item,
	item_vias, rejected,
};
use tith_wire::tlv::OwnedTlv;

use crate::submission::{SOFTWARE, configured_policies};

/// The application name relayed jobs are committed under.
///
/// A relayed job belongs to the daemon rather than to any consumer, so it uses
/// a name no IPC client can present. That keeps its idempotency key — which is
/// the item's signed-item identity — out of reach of an application's own keys.
const RELAY_APPLICATION: &str = "tithd-relay";

/// Everything needed to decide an item's fate and record it.
pub struct Acceptance<'a> {
	pub store: &'a InboundStore,
	pub application: &'a str,
	pub configuration: &'a ConfigurationSet,
	pub nodelist: &'a Nodelist,
	pub local_ref: &'a IdentityRef,
	pub local: &'a Identity,
}

impl KeyResolver for Acceptance<'_> {
	fn public_key(&self, address: &tith_wire::Address) -> Option<tith_crypto::PublicKey> {
		self.store
			.key_pins()
			.resolve(&address.to_string(), self.nodelist.public_key(address))
			.ok()
			.flatten()
	}
}

/// A refusal to relay, which is answered rather than raised.
///
/// TSP-0002 section 6 gives each cause a failure kind; the peer learns the
/// corresponding TTS-0005 rejection reason and applies its own policy, because
/// this node never took responsibility for the item.
struct Refusal {
	reason: RejectionReason,
	description: String,
}

impl Refusal {
	/// A cause retrying identical bytes cannot fix.
	fn permanent(description: impl Into<String>) -> Self {
		Self {
			reason: RejectionReason::Permanent,
			description: description.into(),
		}
	}

	/// A cause which says nothing about the item and may clear on its own.
	fn temporary(description: impl Into<String>) -> Self {
		Self {
			reason: RejectionReason::Temporary,
			description: description.into(),
		}
	}
}

/// A relay that passed every check, ready to commit.
struct PreparedRelay {
	job: NewOutboundJob,
	identity: SubmissionIdentity,
}

impl Acceptance<'_> {
	/// Stores an item if it is acceptable, and builds the response either way.
	///
	/// `peer` is the authenticated identity the item arrived from, which for a
	/// polled item is the node that was polled.
	///
	/// # Errors
	///
	/// Returns an error when the item is a response value, which no request
	/// position may contain, when it carries no authentication state, or when
	/// the store fails.
	pub fn dispatch(
		&self,
		item: &ValidatedItem,
		response_to: TlvHash,
		peer: &Identity,
	) -> Result<OwnedTlv, Box<dyn Error>> {
		// A NetMail for anyone else is relayed rather than stored: a hub has to
		// move it with no application running, and no consumer would claim it.
		if item.kind == ItemKind::NetMail && item.destination.as_ref() != Some(self.local) {
			return self.relay(item, response_to, peer);
		}
		let rejection = match item.kind {
			ItemKind::EchoMail if !self.area_allowed(item, false, peer) => {
				Some("EchoMail area is not authorized for this peer")
			}
			ItemKind::File if item.area.is_some() && !self.area_allowed(item, true, peer) => {
				Some("file area is not authorized for this peer")
			}
			// Poll values are answered by the exchange before dispatch; reaching
			// here means the caller did not recognise one.
			ItemKind::PollMessages
			| ItemKind::PollFiles
			| ItemKind::PollFileRequests
			| ItemKind::PublicKeyRequest => Some("request type is not implemented"),
			ItemKind::Accepted | ItemKind::Rejected => {
				return Err("a request position contains a response value".into());
			}
			// A FileRequest becomes an ordinary inbound item. TSP-0011 section 5.1:
			// its authenticated enclosing SignedTLV is its complete and intended
			// authentication, and a receiver unwilling to serve one refuses it
			// before transport acceptance rather than after.
			ItemKind::NetMail | ItemKind::EchoMail | ItemKind::File | ItemKind::FileRequest => None,
		};
		if let Some(description) = rejection {
			let permanent = matches!(item.kind, ItemKind::EchoMail)
				|| matches!(item.kind, ItemKind::File) && item.area.is_some();
			return Ok(rejected(
				item.request_identifier,
				response_to,
				None,
				if permanent {
					RejectionReason::Permanent
				} else {
					RejectionReason::Temporary
				},
				description,
			)?);
		}

		let authentication = item
			.authentication
			.ok_or("locally delivered item has no authentication state")?;
		let result = self.store.accept(
			NewInbound {
				application: self.application,
				local_identity: &self.local.address.to_string(),
				peer: &peer.address.to_string(),
				peer_key: peer.public_key,
				received: crate::now(),
				authentication,
				payload: &item.raw.encode(),
			},
			item.duplicate_identity.as_ref(),
		)?;
		match result {
			AcceptResult::Stored(_) | AcceptResult::Duplicate { .. } => {
				Ok(accepted(item.request_identifier, response_to)?)
			}
		}
	}

	/// Relays a `NetMail` whose ultimate Destination is not this node.
	///
	/// A refusal is answered, not raised: the peer keeps responsibility and
	/// applies its own failure policy, which lets the origin dead-letter and
	/// notify its user. A store failure is raised instead, so the peer retries
	/// rather than being told the item is permanently unacceptable.
	fn relay(
		&self,
		item: &ValidatedItem,
		response_to: TlvHash,
		peer: &Identity,
	) -> Result<OwnedTlv, Box<dyn Error>> {
		// Generated before the decision so an exhausted RNG cannot be mistaken
		// for a permanent property of the item.
		let request_identifier = random_u64()?;
		let prepared = match self.prepare_relay(item, peer, request_identifier) {
			Ok(prepared) => prepared,
			Err(refusal) => {
				// TSP-0002 section 6: every failure is logged locally whatever
				// the disposition and notification say.
				eprintln!(
					"tithd: refused to relay from {}: {}",
					peer.address, refusal.description
				);
				return Ok(rejected(
					item.request_identifier,
					response_to,
					None,
					refusal.reason,
					&refusal.description,
				)?);
			}
		};
		match self.store.outbound()?.commit_batch(
			std::slice::from_ref(&prepared.identity),
			|classes, _| {
				// A retransmission of an item already relayed lands on Existing,
				// so TTS-0005 section 7 is satisfied without a second copy.
				Ok(match classes.first() {
					Some(SubmissionClass::New { .. }) => vec![prepared.job],
					_ => Vec::new(),
				})
			},
		)? {
			BatchCommit::Committed(_) => Ok(accepted(item.request_identifier, response_to)?),
			BatchCommit::Conflict(_) => {
				Err("relay idempotency key collided with a different item".into())
			}
		}
	}

	/// Applies TSP-0002 sections 5 and 6 and builds the job they imply.
	fn prepare_relay(
		&self,
		item: &ValidatedItem,
		peer: &Identity,
		request_identifier: u64,
	) -> Result<PreparedRelay, Refusal> {
		let destination = item
			.destination
			.as_ref()
			.ok_or_else(|| Refusal::permanent("relayed message has no Destination"))?;
		// TSP-0002 section 6: only an Origin-Valid or SignedOrigin-Valid item may
		// be relayed, and attempting otherwise fails as Authentication.
		let signed = match item.authentication {
			Some(
				tith_store::ItemAuthentication::OriginValid
				| tith_store::ItemAuthentication::SignedOriginValid,
			) => item.duplicate_identity.as_ref(),
			_ => None,
		};
		let signed = signed.ok_or_else(|| Refusal {
			reason: RejectionReason::Authentication,
			description: "relay requires a valid end-to-end item signature".to_owned(),
		})?;
		let routes = routes_for(self.configuration, self.local_ref)
			.ok_or_else(|| Refusal::permanent("receiving identity has no Routes block"))?;

		// The Origin selector and the failure Origin both mean the effective
		// signer, which is what the signed-item identity already carries.
		let rule = self.relay_rule(routes, peer, &signed.signer, destination);
		if !rule.is_some_and(|rule| matches!(rule.action, RelayAction::Allow { .. })) {
			return Err(Refusal::permanent(
				"no relay rule authorizes this peer, signer, and destination",
			));
		}

		let vias = self
			.via_identities(&item.raw)
			.map_err(|error| Refusal::permanent(format!("unreadable Via: {error}")))?;
		let commitment = route_netmail(
			self.configuration,
			routes,
			destination,
			&vias,
			self.nodelist,
			self,
		)
		.map_err(|failure| match failure {
			RouteFailure::Loop => {
				Refusal::permanent("routing would return the item to a node it came through")
			}
			RouteFailure::Unroutable => Refusal::permanent("no eligible route to the destination"),
		})?;

		// The signed region is untouched; only the routing suffix is rebuilt.
		let relayed = forward_item(
			&item.raw,
			self.local,
			request_identifier,
			crate::now(),
			SOFTWARE,
			&[],
		)
		.map_err(|error| Refusal::permanent(format!("could not rebuild the item: {error}")))?;

		let policies = configured_policies(failure_policies(
			self.configuration,
			routes,
			&signed.signer,
			&commitment.next_hop,
			commitment.route_rule,
			rule.and_then(|rule| match rule.action {
				RelayAction::Allow { on_failure } => on_failure,
				RelayAction::Deny => None,
			}),
			(self.nodelist, self),
		));
		let identity = relay_identity(signed).map_err(|error| {
			Refusal::temporary(format!("could not derive a spool key: {error}"))
		})?;
		Ok(PreparedRelay {
			job: NewOutboundJob {
				identity: identity.clone(),
				kind: JobKind::NetMail,
				target: JobTarget::Destination(destination.address.to_string()),
				local_identity: self.local.address.to_string(),
				item: relayed.encode(),
				deliveries: vec![NewDelivery {
					local_identity: self.local.address.to_string(),
					next_hop: commitment.next_hop.address.to_string(),
					next_hop_key: commitment
						.next_hop
						.address
						.is_unlisted()
						.then_some(commitment.next_hop.public_key),
					mode: if commitment.passive {
						DeliveryMode::Passive
					} else {
						DeliveryMode::Active
					},
					class: "Normal".to_owned(),
					retry_at: None,
					policies,
				}],
				sources: Vec::new(),
				created: crate::now(),
				forward_inbound: None,
				forward_claim_token: None,
			},
			identity,
		})
	}

	/// The first relay rule whose three selectors all match.
	///
	/// TSP-0002 section 6: Allow-Relay and Deny-Relay are examined together in
	/// file order and the first match decides, so a Deny before a matching Allow
	/// denies. `None` means no rule matched, which is also a denial.
	fn relay_rule<'r>(
		&self,
		routes: &'r tith_config::Routes,
		peer: &Identity,
		signer: &Identity,
		destination: &Identity,
	) -> Option<&'r RelayRule> {
		routes.relay.iter().find(|rule| {
			selector_matches(&rule.from, peer, self.configuration, self.nodelist, self)
				&& selector_matches(
					&rule.origin,
					signer,
					self.configuration,
					self.nodelist,
					self,
				) && selector_matches(
				&rule.destination,
				destination,
				self.configuration,
				self.nodelist,
				self,
			)
		})
	}

	/// The identities an item's Vias name, for loop detection.
	///
	/// A listed Via absent from the nodelist is skipped rather than failing the
	/// relay. The router can only select a next hop backed by a nodelist entry
	/// or a configured Peer, so such a Via can never be the hop it picks and
	/// dropping it cannot conceal a loop.
	fn via_identities(&self, item: &OwnedTlv) -> Result<Vec<Identity>, tith_wire::BundleError> {
		Ok(item_vias(item)?
			.into_iter()
			.filter_map(|via| {
				let public_key = if via.address.is_unlisted() {
					via.public_key?
				} else {
					self.nodelist.public_key(&via.address)?
				};
				Some(Identity {
					address: via.address,
					public_key,
				})
			})
			.collect())
	}

	/// Whether the peer is authorized to send in the item's area.
	///
	/// TSP-0002 section 7: Receive-From authorizes a Peer to send items in the
	/// area, so an area with no Receive-From line naming this peer is refused.
	fn area_allowed(&self, item: &ValidatedItem, file_area: bool, peer: &Identity) -> bool {
		let Some(area_name) = item.area.as_deref() else {
			return false;
		};
		let Some(peer_name) = self
			.configuration
			.peers
			.iter()
			.find_map(|(name, configured)| {
				(configured.address == peer.address
					&& (!peer.address.is_unlisted()
						|| configured.public_key == Some(peer.public_key)))
				.then_some(name.as_str())
			})
		else {
			return false;
		};
		self.configuration
			.areas
			.iter()
			.find(|areas| &areas.local == self.local_ref)
			.and_then(|areas| {
				areas
					.areas
					.iter()
					.find(|area| area.file_area == file_area && area.name == area_name)
			})
			.is_some_and(|area| area.receive_from.iter().any(|name| name == peer_name))
	}
}

/// The spool identity of a relayed item.
///
/// The key is the signed-item identity rather than the bytes about to be
/// spooled, because a retransmission rebuilds the routing suffix with a fresh
/// `RequestIdentifier` and Via timestamp and so is never byte-identical, while
/// its identity is exactly what TTS-0005 section 7 says does not change.
fn relay_identity(signed: &SignedItemIdentity) -> Result<SubmissionIdentity, Box<dyn Error>> {
	let idempotency_key = format!(
		"{} {} {} {}",
		signed.type_code,
		signed.signer.address,
		STANDARD_NO_PAD.encode(signed.signer.public_key.as_bytes()),
		STANDARD_NO_PAD.encode(signed.signature.as_bytes())
	);
	// The digest guards a key against being reused by a different item. Here the
	// key already is the item's identity, so hashing it keeps a retransmission
	// from ever reading as a conflict.
	let digest = hash_tlv(idempotency_key.as_bytes())?;
	Ok(SubmissionIdentity {
		application: RELAY_APPLICATION.to_owned(),
		idempotency_key,
		digest,
	})
}

fn random_u64() -> Result<u64, Box<dyn Error>> {
	let mut bytes = [0; 8];
	random_bytes(&mut bytes)?;
	Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
	use std::time::{SystemTime, UNIX_EPOCH};

	use tith_crypto::{SigningKeyPair, sign_tlv};
	use tith_store::{ClaimResult, JobState};
	use tith_wire::integer::encode_u64;
	use tith_wire::item::validate_item;
	use tith_wire::tlv::parse_sequence;
	use tith_wire::types;

	use super::*;

	/// The four nodes every relay test uses: this node is fidonet#1/2, mail
	/// comes from fidonet#1/3, and it is bound for fidonet#1/4.
	struct World {
		origin: SigningKeyPair,
		identities: Vec<Identity>,
		nodelist: Nodelist,
		store: InboundStore,
		database: std::path::PathBuf,
	}

	impl Drop for World {
		fn drop(&mut self) {
			let _ = std::fs::remove_file(&self.database);
		}
	}

	fn world(name: &str, destination_keyword: &str) -> World {
		let keys: Vec<_> = (2u8..=5)
			.map(|seed| SigningKeyPair::from_seed(&[seed; 32]).unwrap())
			.collect();
		let line = |keyword: &str, number: usize, key: &SigningKeyPair| {
			format!(
				"{keyword}\t{number}\tNode\tLocation\tSysop\t\tCM\t\tIIH:mail.example:24555:{}\t\t\n",
				STANDARD_NO_PAD.encode(key.public.as_bytes())
			)
		};
		let text = [
			line("Zone", 1, &keys[0]),
			line("", 2, &keys[0]),
			line("", 3, &keys[1]),
			line(destination_keyword, 4, &keys[2]),
			line("", 5, &keys[3]),
		]
		.concat();
		let nodelist = Nodelist::parse("fidonet", &text).unwrap();
		let identities = (2usize..=5)
			.map(|number| Identity {
				address: format!("fidonet#1/{number}").parse().unwrap(),
				public_key: keys[number - 2].public,
			})
			.collect();
		let unique = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_nanos();
		let database = std::env::temp_dir().join(format!("tith-relay-{name}-{unique}.redb"));
		World {
			origin: SigningKeyPair::from_seed(&[3; 32]).unwrap(),
			identities,
			nodelist,
			store: InboundStore::create(&database).unwrap(),
			database,
		}
	}

	impl World {
		fn local(&self) -> &Identity {
			&self.identities[0]
		}

		fn peer(&self) -> &Identity {
			&self.identities[1]
		}

		fn destination(&self) -> &Identity {
			&self.identities[2]
		}

		fn resolver(&self) -> &Nodelist {
			&self.nodelist
		}
	}

	/// A `NetMail` from fidonet#1/3 to fidonet#1/4, signed unless `sign` is false.
	fn netmail(world: &World, sign: bool, vias: &[&Identity]) -> OwnedTlv {
		let mut children = vec![
			OwnedTlv::new(types::ORIGIN, world.peer().address.to_string().into_bytes()).unwrap(),
			OwnedTlv::new(
				types::DESTINATION,
				world.destination().address.to_string().into_bytes(),
			)
			.unwrap(),
			OwnedTlv::new(types::TIMESTAMP, encode_u64(1)).unwrap(),
			OwnedTlv::new(types::TO_USER_NAME, b"You".to_vec()).unwrap(),
			OwnedTlv::new(types::FROM_USER_NAME, b"Me".to_vec()).unwrap(),
			OwnedTlv::new(types::SUBJECT, b"Transit".to_vec()).unwrap(),
			OwnedTlv::new(types::MESSAGE_TEXT, b"Please pass this along".to_vec()).unwrap(),
		];
		if sign {
			let mut signed = Vec::new();
			for child in &children {
				child.write_to(&mut signed).unwrap();
			}
			let signature = sign_tlv(&signed, &world.origin.secret).unwrap();
			children.push(OwnedTlv::new(types::SIGNATURE, signature.as_bytes().to_vec()).unwrap());
		}
		children.push(OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(7)).unwrap());
		// A Message must carry at least one Via, so the sender always appears.
		for via in std::iter::once(world.peer()).chain(vias.iter().copied()) {
			let mut value = Vec::new();
			OwnedTlv::new(types::ADDRESS, via.address.to_string().into_bytes())
				.unwrap()
				.write_to(&mut value)
				.unwrap();
			OwnedTlv::new(types::TIMESTAMP, encode_u64(1))
				.unwrap()
				.write_to(&mut value)
				.unwrap();
			value.extend_from_slice(b"upstream");
			children.push(OwnedTlv::new(types::VIA, value).unwrap());
		}
		let mut value = Vec::new();
		for child in &children {
			child.write_to(&mut value).unwrap();
		}
		OwnedTlv::new(types::MESSAGE, value).unwrap()
	}

	fn configuration(relay: &str) -> ConfigurationSet {
		ConfigurationSet::parse(
			"Peer upstream\nAddress fidonet#1/3\nEnd\nPeer far\nAddress fidonet#1/4\nEnd\n",
			&format!("Routes fidonet#1/2\n{relay}End\n"),
			"",
			"",
		)
		.unwrap()
	}

	/// Dispatches one item and returns the response and the resulting jobs.
	fn dispatch(
		world: &World,
		configuration: &ConfigurationSet,
		item: &OwnedTlv,
	) -> (OwnedTlv, Vec<tith_store::OutboundJob>) {
		let validated = validate_item(item, world.resolver()).unwrap().unwrap();
		let local_ref = IdentityRef::Listed(world.local().address.clone());
		let acceptance = Acceptance {
			store: &world.store,
			application: "tosser",
			configuration,
			nodelist: &world.nodelist,
			local_ref: &local_ref,
			local: world.local(),
		};
		let response = acceptance
			.dispatch(&validated, hash_tlv(b"payload").unwrap(), world.peer())
			.unwrap();
		let outbound = world.store.outbound().unwrap();
		let jobs = outbound
			.events(RELAY_APPLICATION)
			.unwrap()
			.into_iter()
			.map(|event| outbound.query(&event.job_id).unwrap())
			.collect();
		(response, jobs)
	}

	fn rejection(response: &OwnedTlv) -> RejectionReason {
		assert_eq!(response.type_code, types::REJECTED);
		let mut suffix = response.value.as_slice();
		for _ in 0..2 {
			let (_, type_bytes) = tith_wire::integer::decode_u64_prefix(suffix).unwrap();
			let (length, length_bytes) =
				tith_wire::integer::decode_u64_prefix(&suffix[type_bytes..]).unwrap();
			suffix = &suffix[type_bytes + length_bytes + usize::try_from(length).unwrap()..];
		}
		RejectionReason::from_code(tith_wire::integer::decode_u64_prefix(suffix).unwrap().0)
			.unwrap()
	}

	fn stored_inbound(world: &World) -> bool {
		!matches!(
			world
				.store
				.claim("tosser", "probe", crate::now() + 1, 60)
				.unwrap(),
			ClaimResult::Empty
		)
	}

	const ALLOW: &str = "Allow-Relay From All Origin All Destination All\n";

	#[test]
	fn an_unsigned_netmail_is_refused_as_authentication_and_never_spooled() {
		let world = world("unsigned", "");
		let (response, jobs) =
			dispatch(&world, &configuration(ALLOW), &netmail(&world, false, &[]));
		assert_eq!(rejection(&response), RejectionReason::Authentication);
		assert!(
			jobs.is_empty(),
			"an unauthenticated item must not be relayed"
		);
		assert!(!stored_inbound(&world), "nor stored for local delivery");
	}

	#[test]
	fn relay_is_denied_when_no_rule_matches() {
		let world = world("norule", "");
		let (response, jobs) = dispatch(&world, &configuration(""), &netmail(&world, true, &[]));
		assert_eq!(rejection(&response), RejectionReason::Permanent);
		assert!(jobs.is_empty(), "relay defaults to denied");
	}

	#[test]
	fn a_deny_rule_before_a_matching_allow_rule_denies() {
		let world = world("deny", "");
		let relay = format!("Deny-Relay From Peer @upstream Origin All Destination All\n{ALLOW}");
		let (response, jobs) =
			dispatch(&world, &configuration(&relay), &netmail(&world, true, &[]));
		assert_eq!(rejection(&response), RejectionReason::Permanent);
		assert!(jobs.is_empty(), "the first matching rule decides");
	}

	#[test]
	fn an_allow_rule_commits_one_delivery_copy_and_no_inbound_item() {
		let world = world("allow", "");
		let (response, jobs) = dispatch(&world, &configuration(ALLOW), &netmail(&world, true, &[]));
		assert_eq!(response.type_code, types::ACCEPTED);
		assert_eq!(jobs.len(), 1);
		assert_eq!(jobs[0].kind, tith_store::JobKind::NetMail);
		assert_eq!(jobs[0].state, JobState::Queued);
		assert_eq!(jobs[0].deliveries.len(), 1);
		assert_eq!(
			jobs[0].deliveries[0].next_hop,
			world.destination().address.to_string(),
			"Direct is the first eligible method"
		);
		assert_eq!(jobs[0].local_identity, world.local().address.to_string());
		assert!(
			!stored_inbound(&world),
			"a relayed item is spooled, never stored for a consumer"
		);
	}

	#[test]
	fn a_next_hop_already_in_a_via_fails_as_loop() {
		let world = world("loop", "");
		let item = netmail(&world, true, &[world.destination()]);
		let (response, jobs) = dispatch(&world, &configuration(ALLOW), &item);
		assert_eq!(rejection(&response), RejectionReason::Permanent);
		assert!(
			jobs.is_empty(),
			"a later method must not conceal the loop by holding the item instead"
		);
	}

	#[test]
	fn a_down_destination_is_refused_as_unroutable() {
		let world = world("down", "Down");
		let (response, jobs) = dispatch(&world, &configuration(ALLOW), &netmail(&world, true, &[]));
		assert_eq!(rejection(&response), RejectionReason::Permanent);
		assert!(jobs.is_empty());
	}

	#[test]
	fn an_inbound_file_request_is_stored_for_a_consumer() {
		// TSP-0011 section 2: a FileRequest is an ordinary inbound item whose
		// ItemAuthentication is Transport, because its authenticated enclosing
		// SignedTLV is its complete and intended authentication. It is never
		// relayed: it carries no Destination a receiver could route on.
		let world = world("filerequest", "");
		let request = tith_wire::item::build_file_request("nodediff.zip", None, 1).unwrap();
		let (response, jobs) = dispatch(&world, &configuration(ALLOW), &request);
		assert_eq!(response.type_code, types::ACCEPTED);
		assert!(jobs.is_empty(), "a FileRequest is never spooled onward");
		assert!(stored_inbound(&world), "it is stored for its consumer");
	}

	#[test]
	fn relaying_the_same_item_twice_accepts_twice_and_spools_once() {
		let world = world("twice", "");
		let configuration = configuration(ALLOW);
		let item = netmail(&world, true, &[]);
		for _ in 0..2 {
			let (response, jobs) = dispatch(&world, &configuration, &item);
			assert_eq!(response.type_code, types::ACCEPTED);
			assert_eq!(
				jobs.len(),
				1,
				"a retransmission must not create a second copy"
			);
		}
	}

	#[test]
	fn the_relayed_item_keeps_its_signed_region_and_gains_one_via() {
		let world = world("rebuild", "");
		let upstream = world.identities[3].clone();
		let original = netmail(&world, true, &[&upstream]);
		let (_, jobs) = dispatch(&world, &configuration(ALLOW), &original);
		let spooled = world
			.store
			.outbound()
			.unwrap()
			.item(&jobs[0].job_id)
			.unwrap();
		let relayed = parse_sequence(&spooled).unwrap().remove(0);

		let signed_region = |value: &OwnedTlv| {
			let children = parse_sequence(&value.value).unwrap();
			let end = children
				.iter()
				.position(|child| child.type_code == types::SIGNATURE)
				.unwrap();
			children[..=end]
				.iter()
				.flat_map(OwnedTlv::encode)
				.collect::<Vec<_>>()
		};
		assert_eq!(
			signed_region(&relayed),
			signed_region(&original),
			"relaying must not disturb end-to-end authentication"
		);

		let vias = item_vias(&relayed).unwrap();
		assert_eq!(
			vias.len(),
			3,
			"the original Vias are kept and ours is added"
		);
		assert_eq!(vias[0].address, world.peer().address);
		assert_eq!(vias[1].address, upstream.address);
		assert_eq!(vias[2].address, world.local().address);
		assert!(
			parse_sequence(&relayed.value)
				.unwrap()
				.iter()
				.all(|child| child.type_code != types::SEEN_BY),
			"a NetMail carries no SeenBy"
		);
	}
}
