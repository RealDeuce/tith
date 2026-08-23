//! TSP-0002 outbound delivery.
//!
//! Submission commits delivery copies into the spool; this drains them. A
//! schedule activation selects copies by Origin, class, and Next-Hop, groups
//! the compatible ones, and sends each group in one connection.
//!
//! TSP-0002 section 9 sets the grouping rule: compatible copies share the same
//! local identity and the same exact next-hop identity, and "A connection MUST
//! NOT combine delivery copies from different local identities". The next-hop identity
//! includes the anonymous `PublicKey` when there is one, because two anonymous
//! peers share the address `p2p#-1`.

use std::error::Error;
use std::io::{self, Read};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use tith_config::{ConfigurationSet, IdentityRef, Schedule};
use tith_crypto::{PublicKey, SecretKey, TlvHash, hash_tlv};
use tith_exchange::{
	ClientSession, CompletedResponse, ExchangeError, ExchangeIo, RequestKind, ResponseKind,
	ResponseTracker, SessionState, send_bundle,
};
use tith_nodelist::Nodelist;
use tith_router::selector_matches;
use tith_store::{
	DeliveryClaim, DeliveryOutcome, DeliveryRecord, InboundStore, OutboundStore,
	PermanentFailureKind, StoreError,
};
use tith_wire::bundle::{
	Bundle, BundleError, Identity, KeyResolver, build_bundle, build_public_key_probe,
};
use tith_wire::integer::encode_u64;
use tith_wire::item::{
	ItemKind, Rejection, RejectionReason, set_request_identifier, validate_item, validate_payload,
};
use tith_wire::tlv::{OwnedTlv, TlvReader, parse_sequence};
use tith_wire::types;

use crate::accept::Acceptance;
use crate::framing::read_header;

/// The most delivery copies one connection carries.
///
/// Nothing in TSP-0002 bounds a group, but an unbounded one would build the
/// whole spool in memory before the first byte is written, so a run of work is
/// split across connections instead.
const MAX_GROUP: usize = 256;

/// One exact local identity this node sends as.
pub struct LocalIdentity {
	pub reference: IdentityRef,
	pub identity: Identity,
	pub secret: Arc<SecretKey>,
}

pub struct Outbound {
	inbound: Arc<InboundStore>,
	store: OutboundStore,
	application: String,
	configuration: Arc<ConfigurationSet>,
	nodelist: Arc<Nodelist>,
	locals: Vec<LocalIdentity>,
	timeout: Duration,
}

impl KeyResolver for Outbound {
	fn public_key(&self, address: &tith_wire::address::Address) -> Option<PublicKey> {
		let nodelist_key = self.nodelist.public_key(address);
		self.inbound
			.key_pins()
			.resolve(address, nodelist_key)
			.ok()
			.flatten()
	}
}

/// What one exchange produced.
struct Exchange {
	responses: Vec<CompletedResponse>,
	/// How many values the peer returned in answer to a Poll or `FileRequest`.
	returned: usize,
}

/// What one round of polling did, for logging by the caller.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PollSummary {
	pub attempted: usize,
	pub received: usize,
	pub failed: usize,
}

/// What one connection attempt did, for logging by the caller.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PassSummary {
	pub connections: usize,
	pub delivered: usize,
	pub retained: usize,
	pub failed: usize,
}

impl PassSummary {
	fn record(&mut self, state: &DeliveryOutcome) {
		match state {
			DeliveryOutcome::Delivered(_) => self.delivered += 1,
			DeliveryOutcome::Deferred { .. } => self.retained += 1,
			DeliveryOutcome::Rejected { .. } | DeliveryOutcome::Failed(_) => self.failed += 1,
		}
	}

	pub fn add(&mut self, other: Self) {
		self.connections += other.connections;
		self.delivered += other.delivered;
		self.retained += other.retained;
		self.failed += other.failed;
	}
}

impl Outbound {
	/// # Errors
	///
	/// Returns an error when the outbound view of the store cannot be opened.
	pub fn new(
		inbound: Arc<InboundStore>,
		application: String,
		configuration: Arc<ConfigurationSet>,
		nodelist: Arc<Nodelist>,
		locals: Vec<LocalIdentity>,
		timeout: Duration,
	) -> Result<Self, StoreError> {
		let store = inbound.outbound()?;
		Ok(Self {
			inbound,
			store,
			application,
			configuration,
			nodelist,
			locals,
			timeout,
		})
	}

	/// Makes one pass over the work a schedule selects.
	///
	/// TSP-0002 section 8: a Duration of zero "makes one pass over the selected
	/// work" and ends, so one call is exactly that pass. An activation with a
	/// nonzero Duration calls again while it remains open, which is how it
	/// claims work that becomes available during the interval.
	///
	/// `next_attempt` is when a copy this pass could not deliver becomes
	/// eligible again: the beginning of the next activation of this schedule.
	///
	/// # Errors
	///
	/// Returns an error only when the spool itself fails. A connection which
	/// fails is recorded against its copies and the pass continues.
	pub fn run_pass(
		&self,
		schedule: &Schedule,
		now: u64,
		next_attempt: u64,
	) -> Result<PassSummary, StoreError> {
		let mut summary = PassSummary::default();
		let Some(local) = self.local_for(&schedule.origin) else {
			return Ok(summary);
		};
		let origin = local.reference.to_string();
		loop {
			let group = self.claim_group(schedule, &origin, now)?;
			if group.is_empty() {
				return Ok(summary);
			}
			summary.connections += 1;
			self.deliver_group(local, &group, now, next_attempt, &mut summary)?;
		}
	}

	/// Polls every Peer a schedule names.
	///
	/// TSP-0002 section 8: a schedule contacts each polled Peer at every
	/// activation "even when no outbound item is queued for it", and sends one
	/// `PollMessages`, one `PollFiles`, and one `PollFileRequests`.
	///
	/// A peer which cannot be reached is reported through the returned summary
	/// rather than stopping the round.
	pub fn run_polls(
		&self,
		schedule: &Schedule,
		now: u64,
		next_attempt: u64,
	) -> (PollSummary, PassSummary) {
		let mut summary = PollSummary::default();
		let mut pass = PassSummary::default();
		let Some(local) = self.local_for(&schedule.origin) else {
			return (summary, pass);
		};
		for name in &schedule.polls {
			summary.attempted += 1;
			match self.poll_peer(local, schedule, name, now, next_attempt, &mut pass) {
				Ok(received) => summary.received += received,
				Err(error) => {
					summary.failed += 1;
					eprintln!("tithd: poll of {name} failed: {error}");
				}
			}
		}
		(summary, pass)
	}

	/// Runs one poll exchange, returning how many values the peer sent back.
	fn poll_peer(
		&self,
		local: &LocalIdentity,
		schedule: &Schedule,
		name: &str,
		now: u64,
		next_attempt: u64,
		pass: &mut PassSummary,
	) -> Result<usize, Box<dyn Error>> {
		let peer = self
			.configuration
			.peers
			.get(name)
			.ok_or("schedule polls an undefined Peer")?;
		let public_key = if peer.address.is_anonymous() {
			peer.public_key.ok_or("anonymous Peer has no public key")?
		} else {
			match self.public_key(&peer.address) {
				Some(key) => key,
				None if peer.trust_on_first_use => {
					self.discover_key(local, &peer.address, None, now)?
				}
				None => return Err("non-anonymous Peer has no trusted key".into()),
			}
		};
		let destination = Identity {
			address: peer.address.clone(),
			public_key,
		};
		let group = self.claim_group_for(schedule, local, &destination, now)?;
		if !group.is_empty() {
			pass.connections += 1;
		}
		match self.exchange_to(local, &destination, &group, true, now, next_attempt) {
			Ok((outcomes, received)) => {
				self.finish_group(&group, outcomes, now, pass)?;
				Ok(received)
			}
			Err(error) => {
				let result = format!("delivery attempt failed: {error}");
				let outcomes = group
					.iter()
					.map(|_| DeliveryOutcome::Deferred {
						retry_at: next_attempt,
						result: result.clone(),
					})
					.collect();
				self.finish_group(&group, outcomes, now, pass)?;
				Err(error)
			}
		}
	}

	/// Claims one connection's worth of compatible copies.
	fn claim_group(
		&self,
		schedule: &Schedule,
		origin: &str,
		now: u64,
	) -> Result<Vec<DeliveryClaim>, StoreError> {
		let Some(first) = self
			.store
			.claim_scheduled(now, |copy| self.selects(schedule, origin, copy))?
		else {
			return Ok(Vec::new());
		};
		let next_hop = first.delivery.next_hop.clone();
		let next_hop_key = first.delivery.next_hop_key;
		let local_identity = first.delivery.local_identity.clone();
		let mut group = vec![first];
		while group.len() < MAX_GROUP {
			let Some(next) = self.store.claim_scheduled(now, |copy| {
				copy.local_identity == local_identity
					&& copy.next_hop == next_hop
					&& copy.next_hop_key == next_hop_key
					&& self.selects(schedule, origin, copy)
			})?
			else {
				break;
			};
			group.push(next);
		}
		Ok(group)
	}

	/// Claims one connection group for an explicitly polled peer.
	fn claim_group_for(
		&self,
		schedule: &Schedule,
		local: &LocalIdentity,
		destination: &Identity,
		now: u64,
	) -> Result<Vec<DeliveryClaim>, StoreError> {
		let origin = local.reference.to_string();
		let mut group = Vec::new();
		while group.len() < MAX_GROUP {
			let Some(next) = self.store.claim_scheduled(now, |copy| {
				self.selects(schedule, &origin, copy)
					&& self.next_hop(copy).as_ref() == Some(destination)
			})?
			else {
				break;
			};
			group.push(next);
		}
		Ok(group)
	}

	/// Whether a schedule selects a copy.
	///
	/// The spool applies the rules it owns — Active mode, a claimable state, and
	/// a passed retry Timestamp — so this adds only the three configured ones.
	fn selects(&self, schedule: &Schedule, origin: &str, copy: &DeliveryRecord) -> bool {
		copy.local_identity == origin
			&& schedule.classes.iter().any(|class| class == &copy.class)
			&& self.next_hop(copy).is_some_and(|identity| {
				schedule.next_hops.iter().any(|selector| {
					selector_matches(
						selector,
						&identity,
						&self.configuration,
						&self.nodelist,
						self,
					)
				})
			})
	}

	fn local_for(&self, reference: &IdentityRef) -> Option<&LocalIdentity> {
		self.locals
			.iter()
			.find(|local| &local.reference == reference)
	}

	/// The full identity of a copy's next hop.
	///
	/// An anonymous next hop carries its key on the copy, because its address
	/// does not identify it; a non-anonymous one is resolved from the nodelist.
	fn next_hop(&self, copy: &DeliveryRecord) -> Option<Identity> {
		let address: tith_wire::address::Address = copy.next_hop.parse().ok()?;
		let public_key = if address.is_anonymous() {
			copy.next_hop_key?
		} else {
			self.public_key(&address)?
		};
		Some(Identity {
			address,
			public_key,
		})
	}

	/// The addresses to try, in the order TSP-0002 gives them.
	///
	/// A configured Peer's Endpoint lines take precedence in file order; a peer
	/// with none falls back to the nodelist entry's usable TITH endpoints.
	fn endpoints_for(
		&self,
		address: &tith_wire::address::Address,
		key: Option<PublicKey>,
	) -> Vec<(String, u16)> {
		let configured = self.configuration.peers.values().find(|peer| {
			peer.address == *address && (!address.is_anonymous() || peer.public_key == key)
		});
		if let Some(peer) = configured
			&& !peer.endpoints.is_empty()
		{
			return peer
				.endpoints
				.iter()
				.map(|endpoint| (endpoint.server.clone(), endpoint.port))
				.collect();
		}
		self.nodelist
			.get(address)
			.and_then(|entry| entry.tith.as_ref())
			.map(|service| {
				service
					.endpoints
					.iter()
					.filter_map(|endpoint| {
						Some((endpoint.server.clone()?, endpoint.resolved_port()?))
					})
					.collect()
			})
			.unwrap_or_default()
	}

	fn discover_key(
		&self,
		local: &LocalIdentity,
		address: &tith_wire::address::Address,
		expected: Option<PublicKey>,
		now: u64,
	) -> Result<PublicKey, Box<dyn Error>> {
		if address.is_anonymous() {
			return Err("PublicKeyRequest is only used for non-anonymous addresses".into());
		}
		if expected.is_none()
			&& !self
				.configuration
				.peers
				.values()
				.any(|peer| peer.address == *address && peer.trust_on_first_use)
		{
			return Err("first-contact key discovery is not trusted for this Peer".into());
		}
		let request =
			build_public_key_probe(&local.identity, &local.secret, address, expected, now, 1)?;
		let request_values = parse_sequence(&request)?;
		let response_to = hash_tlv(
			&request_values
				.last()
				.ok_or("key probe has no payload")?
				.encode(),
		)?;
		let mut stream = self.connect_address(address, expected)?;
		let mut io = StreamIo(stream.try_clone()?);
		send_bundle(&mut io, &request, false)?;
		let mut response = Vec::new();
		stream.read_to_end(&mut response)?;
		let reply = Bundle::parse_public_key_reply(&response, self, expected)?;
		if reply.origin.address != *address || reply.destination != local.identity {
			return Err("PublicKeyRequest reply has the wrong identities".into());
		}
		let item = validate_payload(&reply.payloads[0], self)?
			.into_iter()
			.next()
			.ok_or("PublicKeyRequest reply has no Accepted value")?;
		if item.request_identifier != 1 || item.response_to != Some(response_to) {
			return Err("PublicKeyRequest reply answers a different request".into());
		}
		let current = item
			.response_public_key
			.ok_or("PublicKeyRequest reply has no current key")?;
		let pins = self.inbound.key_pins();
		let accepted = if let Some(predecessor) = expected {
			pins.advance(
				address,
				predecessor,
				current,
				self.nodelist.public_key(address),
				now,
			)?
		} else {
			let observation =
				pins.observe_initial(address, current, self.nodelist.public_key(address), now)?;
			if matches!(observation, tith_store::InitialObservation::Established(_)) {
				eprintln!("{}", initial_trust_message(address));
			}
			return Ok(observation.effective_key());
		};
		Ok(accepted.current)
	}

	/// Sends one group and records an outcome for every copy in it.
	fn deliver_group(
		&self,
		local: &LocalIdentity,
		group: &[DeliveryClaim],
		now: u64,
		next_attempt: u64,
		summary: &mut PassSummary,
	) -> Result<(), StoreError> {
		let outcomes = match self.exchange(local, group, now, next_attempt) {
			Ok(outcomes) => outcomes,
			Err(error) => {
				// A connection which never completed leaves every copy eligible;
				// TSP-0002 section 6 keeps permanent policy for a real response.
				let result = format!("delivery attempt failed: {error}");
				group
					.iter()
					.map(|_| DeliveryOutcome::Deferred {
						retry_at: next_attempt,
						result: result.clone(),
					})
					.collect()
			}
		};
		self.finish_group(group, outcomes, now, summary)
	}

	fn finish_group(
		&self,
		group: &[DeliveryClaim],
		outcomes: Vec<DeliveryOutcome>,
		now: u64,
		summary: &mut PassSummary,
	) -> Result<(), StoreError> {
		for (claim, outcome) in group.iter().zip(outcomes) {
			summary.record(&outcome);
			self.store.finish_delivery(
				&claim.job_id,
				claim.delivery_index,
				&claim.worker_token,
				now,
				outcome,
			)?;
		}
		Ok(())
	}

	/// Runs one client exchange, returning an outcome per copy in order.
	fn exchange(
		&self,
		local: &LocalIdentity,
		group: &[DeliveryClaim],
		now: u64,
		next_attempt: u64,
	) -> Result<Vec<DeliveryOutcome>, Box<dyn Error>> {
		let destination = self
			.next_hop(&group[0].delivery)
			.ok_or("next hop has no resolvable public key")?;
		self.exchange_to(local, &destination, group, false, now, next_attempt)
			.map(|(outcomes, _)| outcomes)
	}

	fn exchange_to(
		&self,
		local: &LocalIdentity,
		destination: &Identity,
		group: &[DeliveryClaim],
		include_polls: bool,
		now: u64,
		next_attempt: u64,
	) -> Result<(Vec<DeliveryOutcome>, usize), Box<dyn Error>> {
		let mut values = Vec::with_capacity(group.len());
		for claim in group {
			let mut parsed = parse_sequence(&claim.item)?;
			if parsed.len() != 1 {
				return Err("spooled item is not a single TLV value".into());
			}
			let value = parsed.remove(0);
			let relayed = is_relay_delivery(&value, destination, self)?;
			values.push((value, relayed));
		}
		// TTS-0005 section 2 RECOMMENDS the first payload SignedTLV hold every
		// FileRequest, so the peer can validate it and start returning files while
		// the rest is still arriving. Splitting reorders the requests, so the
		// original group position travels with each one and the outcomes are
		// scattered back at the end.
		let (mut ordered, mut rest): (Vec<_>, Vec<_>) = values
			.into_iter()
			.enumerate()
			.partition(|(_, (value, _))| value.type_code == types::FILE_REQUEST);
		let first_count = ordered.len();
		ordered.append(&mut rest);

		let mut first = if include_polls {
			poll_values()?
		} else {
			Vec::new()
		};
		for (_, (value, _)) in &ordered[..first_count] {
			let identifier = u64::try_from(first.len()).map_err(|_| "group is too large")? + 1;
			first.push(set_request_identifier(value, identifier)?);
		}
		let mut second = Vec::with_capacity(ordered.len().saturating_sub(first_count));
		for (_, (value, _)) in &ordered[first_count..] {
			let identifier = u64::try_from(second.len()).map_err(|_| "group is too large")? + 1;
			second.push(set_request_identifier(value, identifier)?);
		}
		let payloads = if first.is_empty() {
			vec![second]
		} else if second.is_empty() {
			vec![first]
		} else {
			vec![first, second]
		};
		let encoded = build_bundle(
			&local.identity,
			&local.secret,
			destination,
			now,
			payloads.clone(),
		)?;
		let bundle = Bundle::parse(&encoded, self)?;
		let tracker = ResponseTracker::for_bundle(&bundle, self)?;
		let mut session = ClientSession::new(tracker);
		let mut stream = self.connect(destination)?;
		let exchange = match self.converse(&mut stream, &encoded, &mut session, local, destination)
		{
			Ok(exchange) => exchange,
			Err(error) if !destination.address.is_anonymous() && is_signature_failure(&*error) => {
				let key = self.discover_key(
					local,
					&destination.address,
					Some(destination.public_key),
					now,
				)?;
				let destination = Identity {
					address: destination.address.clone(),
					public_key: key,
				};
				let encoded =
					build_bundle(&local.identity, &local.secret, &destination, now, payloads)?;
				let bundle = Bundle::parse(&encoded, self)?;
				let tracker = ResponseTracker::for_bundle(&bundle, self)?;
				let mut retry = ClientSession::new(tracker);
				let mut stream = self.connect(&destination)?;
				self.converse(&mut stream, &encoded, &mut retry, local, &destination)?
			}
			Err(error) => return Err(error),
		};
		let sent: Vec<(usize, bool)> = ordered
			.into_iter()
			.map(|(index, (_, relayed))| (index, relayed))
			.collect();
		let copy_responses = exchange
			.responses
			.iter()
			.filter(|response| {
				!matches!(
					response.request.kind,
					RequestKind::PollMessages
						| RequestKind::PollFiles
						| RequestKind::PollFileRequests
				)
			})
			.cloned()
			.collect::<Vec<_>>();
		Ok((
			Self::outcomes(&sent, &copy_responses, next_attempt),
			exchange.returned,
		))
	}

	fn connect(&self, destination: &Identity) -> Result<TcpStream, Box<dyn Error>> {
		self.connect_address(&destination.address, Some(destination.public_key))
	}

	fn connect_address(
		&self,
		address: &tith_wire::address::Address,
		key: Option<PublicKey>,
	) -> Result<TcpStream, Box<dyn Error>> {
		let endpoints = self.endpoints_for(address, key);
		if endpoints.is_empty() {
			return Err("next hop has no usable endpoint".into());
		}
		let mut last: Option<io::Error> = None;
		for (server, port) in endpoints {
			let resolved = match (server.as_str(), port).to_socket_addrs() {
				Ok(resolved) => resolved,
				Err(error) => {
					last = Some(error);
					continue;
				}
			};
			for address in resolved {
				match TcpStream::connect_timeout(&address, self.timeout) {
					Ok(stream) => {
						stream.set_read_timeout(Some(self.timeout))?;
						stream.set_write_timeout(Some(self.timeout))?;
						return Ok(stream);
					}
					Err(error) => last = Some(error),
				}
			}
		}
		Err(last.map_or_else(
			|| Box::<dyn Error>::from("no endpoint address resolved"),
			Into::into,
		))
	}

	/// Sends the Bundle and reads responses until the session is satisfied.
	///
	/// A Bundle carrying a Poll or `FileRequest` also gets values back, which are
	/// dispatched as they arrive and answered in the final Reply Bundle this
	/// then sends. TTS-0006 section 4 is why the write side stays open for
	/// exactly those exchanges and is closed immediately for every other.
	fn converse(
		&self,
		stream: &mut TcpStream,
		encoded: &[u8],
		session: &mut ClientSession,
		local: &LocalIdentity,
		destination: &Identity,
	) -> Result<Exchange, Box<dyn Error>> {
		let keep_open = session.requires_return_bundle();
		let writer = if keep_open {
			let mut io = StreamIo(stream.try_clone()?);
			let encoded = encoded.to_vec();
			Some(std::thread::spawn(move || {
				send_bundle(&mut io, &encoded, true)
			}))
		} else {
			let mut io = StreamIo(stream.try_clone()?);
			send_bundle(&mut io, encoded, false)?;
			None
		};
		session.initial_sent();

		let received = (|| -> Result<(Vec<OwnedTlv>, usize), Box<dyn Error>> {
			let mut reader = TlvReader::new(stream.try_clone()?);
			let reply = read_header(&mut reader, None, self)?
				.ok_or("peer closed before sending a Reply Header")?;
			let mut answers = Vec::new();
			let mut returned = 0;
			while session.state() == SessionState::AwaitingResponses {
				let Some(value) = reader.read_next()? else {
					break;
				};
				let value = value.read_owned()?;
				match value.type_code {
					types::SIGNED_TLV => {
						let mut bytes = reply.prefix.clone();
						bytes.extend_from_slice(&value.encode());
						let payload = Bundle::parse(&bytes, self)?;
						if keep_open {
							let response_to = hash_tlv(&value.encode())?;
							returned += self.dispatch_returned(
								&payload,
								response_to,
								local,
								&reply.bundle.origin,
								&mut answers,
							)?;
						}
						session.reply_received(&payload, self)?;
					}
					type_code if types::is_defined(type_code) => {
						return Err("unexpected defined value in a reply".into());
					}
					_ => {}
				}
			}
			Ok((answers, returned))
		})();
		if let Some(writer) = writer {
			writer.join().map_err(|_| "Bundle writer panicked")??;
		}
		let (answers, returned) = received?;
		if keep_open {
			// TTS-0005 section 6: one Accepted or Rejected for every value the
			// peer returned, in a Reply Bundle of our own.
			let final_reply = build_bundle(
				&local.identity,
				&local.secret,
				destination,
				crate::now(),
				vec![answers],
			)?;
			let mut io = StreamIo(stream.try_clone()?);
			send_bundle(&mut io, &final_reply, false)?;
			session.final_reply_sent();
		}
		let responses = session.responses().to_vec();
		session.closed()?;
		// The write side was closed when the last Bundle was sent, so closing the
		// read side completes the client's active close. The peer has usually gone
		// by now, which some systems report as ENOTCONN; that is not a failure.
		drop(stream.shutdown(Shutdown::Read));
		Ok(Exchange {
			responses,
			returned,
		})
	}

	/// Stores every request value a Poll or `FileRequest` reply carried.
	fn dispatch_returned(
		&self,
		payload: &Bundle,
		response_to: TlvHash,
		local: &LocalIdentity,
		peer: &Identity,
		answers: &mut Vec<OwnedTlv>,
	) -> Result<usize, Box<dyn Error>> {
		let acceptance = Acceptance {
			store: &self.inbound,
			application: &self.application,
			configuration: &self.configuration,
			nodelist: &self.nodelist,
			local_ref: &local.reference,
			local: &local.identity,
		};
		let mut count = 0;
		for signed in &payload.payloads {
			for item in validate_payload(signed, self)? {
				if matches!(item.kind, ItemKind::Accepted | ItemKind::Rejected) {
					continue;
				}
				count += 1;
				answers.push(acceptance.dispatch(&item, response_to, peer)?);
			}
		}
		Ok(count)
	}

	/// Applies TSP-0002 section 6 to each response.
	/// One outcome per claim, in the caller's group order.
	///
	/// `sent[position]` is the group index of the value sent at that position, so
	/// a Bundle whose requests were reordered still reports each copy's own
	/// response. A copy with no response is Deferred: TSP-0002 section 9 requires
	/// an unacknowledged request be retried to the same next hop.
	fn outcomes(
		sent: &[(usize, bool)],
		responses: &[CompletedResponse],
		next_attempt: u64,
	) -> Vec<DeliveryOutcome> {
		let mut outcomes: Vec<DeliveryOutcome> = (0..sent.len())
			.map(|_| DeliveryOutcome::Deferred {
				retry_at: next_attempt,
				result: "no response was received".to_owned(),
			})
			.collect();
		for (position, &(index, relayed)) in sent.iter().enumerate() {
			if let Some(response) = responses.get(position) {
				outcomes[index] = outcome_for(response, next_attempt, relayed);
			}
		}
		outcomes
	}
}

fn initial_trust_message(address: &tith_wire::Address) -> String {
	format!("tithd: established a new key pin for {address}")
}

fn poll_values() -> Result<Vec<OwnedTlv>, BundleError> {
	[
		types::POLL_MESSAGES,
		types::POLL_FILES,
		types::POLL_FILE_REQUESTS,
	]
	.into_iter()
	.enumerate()
	.map(|(offset, type_code)| {
		let identifier = u64::try_from(offset).expect("three Poll values fit in u64") + 1;
		let identifier = OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(identifier))?;
		OwnedTlv::new(type_code, identifier.encode()).map_err(Into::into)
	})
	.collect()
}

fn is_signature_failure(error: &(dyn Error + 'static)) -> bool {
	if matches!(
		error.downcast_ref::<BundleError>(),
		Some(BundleError::InvalidSignature)
	) {
		return true;
	}
	matches!(
		error.downcast_ref::<ExchangeError>(),
		Some(ExchangeError::Bundle(BundleError::InvalidSignature))
	)
}

/// The TSP-0002 section 6 rule for one completed response.
///
/// Reason 1 fails as Relay-Denied for an intermediate next hop and Rejected for
/// the ultimate Destination. Reason 2 fails a request with a peer-correctable
/// condition as Rejected. Reason 3 retains the unchanged item for retry no
/// earlier than its Timestamp, or for the next applicable schedule when it
/// carries none.
fn outcome_for(response: &CompletedResponse, next_attempt: u64, relayed: bool) -> DeliveryOutcome {
	match response.response {
		ResponseKind::Accepted => DeliveryOutcome::Delivered("accepted".to_owned()),
		ResponseKind::Rejected => {
			rejection_outcome(response.rejection.as_ref(), next_attempt, relayed)
		}
	}
}

/// The outcome for a Rejected response, whose reason decides everything.
///
/// A Rejected which carries no readable reason cannot be acted on as a
/// permanent failure, so the copy is retried rather than discarded.
pub fn rejection_outcome(
	rejection: Option<&Rejection>,
	next_attempt: u64,
	relayed: bool,
) -> DeliveryOutcome {
	let Some(rejection) = rejection else {
		return DeliveryOutcome::Deferred {
			retry_at: next_attempt,
			result: "rejected without a usable reason".to_owned(),
		};
	};
	let description = rejection.description.clone();
	match rejection.reason {
		RejectionReason::Permanent => DeliveryOutcome::Rejected {
			kind: if relayed {
				PermanentFailureKind::RelayDenied
			} else {
				PermanentFailureKind::Rejected
			},
			result: description,
		},
		RejectionReason::ConditionUnmet => DeliveryOutcome::Rejected {
			kind: PermanentFailureKind::Rejected,
			result: description,
		},
		RejectionReason::Temporary => DeliveryOutcome::Deferred {
			retry_at: rejection.retry_after.unwrap_or(next_attempt),
			result: description,
		},
	}
}

/// Whether this delivery asks its next hop to relay a `NetMail` Message.
pub(crate) fn is_relay_delivery(
	value: &OwnedTlv,
	next_hop: &Identity,
	resolver: &impl KeyResolver,
) -> Result<bool, BundleError> {
	Ok(validate_item(value, resolver)?
		.and_then(|item| item.destination)
		.is_some_and(|destination| destination != *next_hop))
}

struct StreamIo(TcpStream);

impl io::Read for StreamIo {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		self.0.read(buffer)
	}
}

impl io::Write for StreamIo {
	fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
		self.0.write(buffer)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.0.flush()
	}
}

impl ExchangeIo for StreamIo {
	fn shutdown_write(&mut self) -> io::Result<()> {
		match self.0.shutdown(Shutdown::Write) {
			// The peer may close immediately after reading the final complete
			// Bundle.  At this binding boundary that already-completed close is
			// equivalent to completing our own write-side shutdown.
			Err(error) if error.kind() == io::ErrorKind::NotConnected => Ok(()),
			result => result,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use tith_crypto::SigningKeyPair;
	use tith_wire::address::Address;
	use tith_wire::item::{ItemProvenance, MessageData, build_originated_message};

	fn rejection(reason: RejectionReason) -> Rejection {
		Rejection {
			reason,
			retry_after: None,
			description: "refused".to_owned(),
		}
	}

	#[test]
	fn permanent_rejection_uses_the_next_hop_role() {
		assert_eq!(
			rejection_outcome(Some(&rejection(RejectionReason::Permanent)), 10, true),
			DeliveryOutcome::Rejected {
				kind: PermanentFailureKind::RelayDenied,
				result: "refused".to_owned(),
			}
		);
		assert_eq!(
			rejection_outcome(Some(&rejection(RejectionReason::Permanent)), 10, false),
			DeliveryOutcome::Rejected {
				kind: PermanentFailureKind::Rejected,
				result: "refused".to_owned(),
			}
		);
	}

	#[test]
	fn an_unmet_condition_is_a_terminal_rejection() {
		assert_eq!(
			rejection_outcome(Some(&rejection(RejectionReason::ConditionUnmet)), 10, false),
			DeliveryOutcome::Rejected {
				kind: PermanentFailureKind::Rejected,
				result: "refused".to_owned(),
			}
		);
	}

	#[test]
	fn an_anonymous_next_hop_is_compared_by_address_and_key() {
		let origin_keys = SigningKeyPair::from_seed(&[71; 32]).unwrap();
		let destination_keys = SigningKeyPair::from_seed(&[72; 32]).unwrap();
		let other_keys = SigningKeyPair::from_seed(&[73; 32]).unwrap();
		let anonymous = Address::anonymous("p2p".to_owned()).unwrap();
		let origin = Identity {
			address: anonymous.clone(),
			public_key: origin_keys.public,
		};
		let destination = Identity {
			address: anonymous,
			public_key: destination_keys.public,
		};
		let message = build_originated_message(
			&MessageData {
				destination: Some(destination.clone()),
				timestamp: 1,
				to_user: "You".to_owned(),
				from_user: "Me".to_owned(),
				subject: String::new(),
				text: "Body\n".to_owned(),
				area: None,
				attachments: Vec::new(),
				legacy_attributes: None,
				timestamp_offset: None,
				tear_line: None,
				origin_line: None,
				message_id: None,
				reply_to: None,
				original_character_set: None,
				additional_kludge_lines: Vec::new(),
			},
			&ItemProvenance {
				origin: origin.address.clone(),
				signer: Some(origin),
			},
			&origin_keys.secret,
			1,
			1,
			"test",
			&[],
		)
		.unwrap();
		let resolver = Nodelist::default();
		assert!(!is_relay_delivery(&message, &destination, &resolver).unwrap());
		assert!(
			is_relay_delivery(
				&message,
				&Identity {
					address: destination.address,
					public_key: other_keys.public,
				},
				&resolver,
			)
			.unwrap()
		);
	}

	#[test]
	fn a_new_initial_trust_decision_has_an_explicit_audit_message() {
		let address: Address = "fidonet#1/2".parse().unwrap();
		assert_eq!(
			initial_trust_message(&address),
			"tithd: established a new key pin for fidonet#1/2"
		);
	}
}
