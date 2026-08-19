//! TSP-0002 outbound delivery.
//!
//! Submission commits delivery copies into the spool; this drains them. A
//! schedule activation selects copies by Origin, class, and Next-Hop, groups
//! the compatible ones, and sends each group in one connection.
//!
//! TSP-0002 section 9 sets the grouping rule: compatible copies share the same
//! local AKA and the same exact next-hop identity, and "A connection MUST NOT
//! combine delivery copies from different local AKAs". The next-hop identity
//! includes the unlisted `PublicKey` when there is one, because two unlisted
//! peers share the address `p2p#-1`.

use std::error::Error;
use std::io;
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use tith_config::{ConfigurationSet, IdentityRef, Schedule};
use tith_crypto::{PublicKey, SecretKey, TlvHash, hash_tlv};
use tith_exchange::{
	ClientSession, CompletedResponse, ExchangeIo, ResponseKind, ResponseTracker, SessionState,
	send_bundle,
};
use tith_nodelist::Nodelist;
use tith_router::selector_matches;
use tith_store::{
	DeliveryClaim, DeliveryOutcome, DeliveryRecord, InboundStore, OutboundStore, StoreError,
};
use tith_wire::bundle::{Bundle, Identity, KeyResolver, build_bundle};
use tith_wire::integer::encode_u64;
use tith_wire::item::{
	ItemKind, Rejection, RejectionReason, set_request_identifier, validate_payload,
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

/// A local AKA this node sends as.
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
		self.nodelist.public_key(address)
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
			DeliveryOutcome::Rejected(_) | DeliveryOutcome::Failed(_) => self.failed += 1,
		}
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
		let origin = local.identity.address.to_string();
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
	#[must_use]
	pub fn run_polls(&self, schedule: &Schedule, now: u64) -> PollSummary {
		let mut summary = PollSummary::default();
		let Some(local) = self.local_for(&schedule.origin) else {
			return summary;
		};
		for name in &schedule.polls {
			summary.attempted += 1;
			match self.poll_peer(local, name, now) {
				Ok(received) => summary.received += received,
				Err(error) => {
					summary.failed += 1;
					eprintln!("tithd: poll of {name} failed: {error}");
				}
			}
		}
		summary
	}

	/// Runs one poll exchange, returning how many values the peer sent back.
	fn poll_peer(
		&self,
		local: &LocalIdentity,
		name: &str,
		now: u64,
	) -> Result<usize, Box<dyn Error>> {
		let peer = self
			.configuration
			.peers
			.get(name)
			.ok_or("schedule polls an undefined Peer")?;
		let public_key = if peer.address.is_unlisted() {
			peer.public_key.ok_or("unlisted Peer has no public key")?
		} else {
			self.nodelist
				.public_key(&peer.address)
				.ok_or("listed Peer has no nodelist key")?
		};
		let destination = Identity {
			address: peer.address.clone(),
			public_key,
		};
		let mut polls = Vec::with_capacity(3);
		for (offset, type_code) in [
			types::POLL_MESSAGES,
			types::POLL_FILES,
			types::POLL_FILE_REQUESTS,
		]
		.into_iter()
		.enumerate()
		{
			let identifier =
				OwnedTlv::new(types::REQUEST_IDENTIFIER, encode_u64(offset as u64 + 1))?;
			polls.push(OwnedTlv::new(type_code, identifier.encode())?);
		}
		let encoded = build_bundle(
			&local.identity,
			&local.secret,
			&destination,
			now,
			vec![polls],
		)?;
		let bundle = Bundle::parse(&encoded, self)?;
		let mut session = ClientSession::new(ResponseTracker::for_bundle(&bundle, self)?);
		let mut stream = self.connect(&destination)?;
		let exchange = self.converse(&mut stream, &encoded, &mut session, local, &destination)?;
		Ok(exchange.returned)
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

	/// Whether a schedule selects a copy.
	///
	/// The spool applies the rules it owns — Active mode, a claimable state, and
	/// a passed retry Timestamp — so this adds only the three configured ones.
	fn selects(&self, schedule: &Schedule, origin: &str, copy: &DeliveryRecord) -> bool {
		copy.local_identity == origin
			&& schedule.classes.iter().any(|class| class == &copy.class)
			&& self.next_hop(copy).is_some_and(|identity| {
				schedule.next_hops.iter().any(|selector| {
					selector_matches(selector, &identity, &self.configuration, &self.nodelist)
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
	/// An unlisted next hop carries its key on the copy, because its address
	/// does not identify it; a listed one is resolved from the nodelist.
	fn next_hop(&self, copy: &DeliveryRecord) -> Option<Identity> {
		let address: tith_wire::address::Address = copy.next_hop.parse().ok()?;
		let public_key = if address.is_unlisted() {
			copy.next_hop_key?
		} else {
			self.nodelist.public_key(&address)?
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
	fn endpoints(&self, identity: &Identity) -> Vec<(String, u16)> {
		let configured = self.configuration.peers.values().find(|peer| {
			peer.address == identity.address
				&& (!identity.address.is_unlisted() || peer.public_key == Some(identity.public_key))
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
			.get(&identity.address)
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
		let mut items = Vec::with_capacity(group.len());
		for (index, claim) in group.iter().enumerate() {
			let mut values = parse_sequence(&claim.item)?;
			if values.len() != 1 {
				return Err("spooled item is not a single TLV value".into());
			}
			// Every request in a Bundle needs its own RequestIdentifier, and these
			// were numbered when they were spooled, independently of each other.
			let identifier = u64::try_from(index).map_err(|_| "group is too large")? + 1;
			items.push(set_request_identifier(&values.remove(0), identifier)?);
		}
		let encoded = build_bundle(
			&local.identity,
			&local.secret,
			&destination,
			now,
			vec![items],
		)?;
		let bundle = Bundle::parse(&encoded, self)?;
		let tracker = ResponseTracker::for_bundle(&bundle, self)?;
		let mut session = ClientSession::new(tracker);
		let mut stream = self.connect(&destination)?;
		let exchange = self.converse(&mut stream, &encoded, &mut session, local, &destination)?;
		Ok(Self::outcomes(group, &exchange.responses, next_attempt))
	}

	fn connect(&self, destination: &Identity) -> Result<TcpStream, Box<dyn Error>> {
		let endpoints = self.endpoints(destination);
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
		let mut io = StreamIo(stream.try_clone()?);
		let keep_open = session.requires_return_bundle();
		send_bundle(&mut io, encoded, keep_open)?;
		session.initial_sent();

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
	fn outcomes(
		group: &[DeliveryClaim],
		responses: &[CompletedResponse],
		next_attempt: u64,
	) -> Vec<DeliveryOutcome> {
		group
			.iter()
			.enumerate()
			.map(|(index, _)| {
				responses.get(index).map_or_else(
					|| DeliveryOutcome::Deferred {
						retry_at: next_attempt,
						result: "no response was received".to_owned(),
					},
					|response| outcome_for(response, next_attempt),
				)
			})
			.collect()
	}
}

/// The TSP-0002 section 6 rule for one completed response.
///
/// Reason 1 fails as Rejected and reason 2 as Authentication, which are
/// different failure kinds and so select different stored policies. Reason 3
/// completes a conditional request and is not a failure at all. Reason 4
/// retains the item for retry no earlier than its Timestamp, or for the next
/// applicable schedule when it carries none.
fn outcome_for(response: &CompletedResponse, next_attempt: u64) -> DeliveryOutcome {
	match response.response {
		ResponseKind::Accepted => DeliveryOutcome::Delivered("accepted".to_owned()),
		ResponseKind::Rejected => rejection_outcome(response.rejection.as_ref(), next_attempt),
	}
}

/// The outcome for a Rejected response, whose reason decides everything.
///
/// A Rejected which carries no readable reason cannot be acted on as a
/// permanent failure, so the copy is retried rather than discarded.
pub fn rejection_outcome(rejection: Option<&Rejection>, next_attempt: u64) -> DeliveryOutcome {
	let Some(rejection) = rejection else {
		return DeliveryOutcome::Deferred {
			retry_at: next_attempt,
			result: "rejected without a usable reason".to_owned(),
		};
	};
	let description = rejection.description.clone();
	match rejection.reason {
		RejectionReason::Permanent => DeliveryOutcome::Rejected(description),
		RejectionReason::Authentication => {
			DeliveryOutcome::Failed(format!("authentication: {description}"))
		}
		RejectionReason::Condition => DeliveryOutcome::Delivered(description),
		RejectionReason::Temporary => DeliveryOutcome::Deferred {
			retry_at: rejection.retry_after.unwrap_or(next_attempt),
			result: description,
		},
	}
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
		self.0.shutdown(Shutdown::Write)
	}
}
