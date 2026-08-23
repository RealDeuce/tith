//! TTS-0006 Server exchange engine.
//!
//! This module owns the live Server protocol. Application acceptance and the
//! durable spool remain behind their existing policy and storage boundaries.

use std::error::Error;
use std::io::Write;
use std::net::{Shutdown, TcpStream};

use tith_crypto::{TlvHash, hash_tlv};
use tith_exchange::{ReceivedRequest, ServerReply, receive_payload};
use tith_store::{DeliveryClaim, DeliveryOutcome, JobKind, OutboundStore};
use tith_wire::bundle::{Bundle, unauthenticated_signed_data};
use tith_wire::item::{
	ItemKind, RejectionReason, ValidatedItem, accepted, rejected, set_request_identifier,
};
use tith_wire::tlv::{OwnedTlv, TlvReader, parse_sequence};
use tith_wire::types;

use crate::framing::{IncomingBundle, read_header};
use crate::mail::Mailer;
use crate::now;

/// A delivery copy returned in a poll snapshot, awaiting its response.
///
/// The copy stays claimed until the peer's final Reply Bundle says what became
/// of it, so a connection which dies mid-transfer does not lose the item.
pub(super) struct PollHold {
	pub(super) signed_tlv_hash: TlvHash,
	pub(super) request_identifier: u64,
	pub(super) relayed: bool,
	pub(super) claim: DeliveryClaim,
}

pub(super) fn transaction(mut stream: TcpStream, mailer: &Mailer) -> Result<(), Box<dyn Error>> {
	let mut writer = stream.try_clone()?;
	let mut reader = TlvReader::new(&mut stream as &mut dyn std::io::Read);
	let request = read_header(&mut reader, None, mailer)?.ok_or("empty mail connection")?;
	let first = reader
		.read_next()?
		.map(tith_wire::tlv::TlvValue::read_owned)
		.transpose()?;
	if let Some(value) = first.as_ref()
		&& value.type_code == types::SIGNED_TLV
		&& unauthenticated_signed_data(value).is_ok_and(|data| {
			data.len() == 2
				&& data[0].type_code == types::TLV_HASH
				&& data[1].type_code == types::PUBLIC_KEY_REQUEST
		}) {
		let mut encoded = request.prefix.clone();
		encoded.extend_from_slice(&value.encode());
		let probe = Bundle::parse(&encoded, mailer)?;
		let (request_identifier, response_to) = probe
			.public_key_request()?
			.ok_or("classified PublicKeyRequest has no request")?;
		if reader.read_next()?.is_some() {
			return Err("PublicKeyRequest must be the sole request in its Bundle".into());
		}
		return answer_public_key_request(
			&mut writer,
			&request,
			request_identifier,
			response_to,
			mailer,
		);
	}
	let reply =
		ServerReply::for_request(&request.bundle, &mailer.local, &mailer.local_secret, now())?;
	writer.write_all(reply.prefix())?;
	writer.flush()?;

	let mut holds = Vec::new();
	let result = respond(
		&mut reader,
		&mut writer,
		&request,
		&reply,
		mailer,
		&mut holds,
		first,
	);
	// Whatever happened, every copy this connection claimed needs an outcome.
	// TSP-0002 section 6: a request with no complete response remains eligible
	// and does not invoke permanent failure policy.
	release_holds(&holds, mailer)?;
	result?;
	writer.shutdown(Shutdown::Write)?;
	Ok(())
}

fn answer_public_key_request(
	writer: &mut TcpStream,
	request: &IncomingBundle,
	request_identifier: u64,
	response_to: TlvHash,
	mailer: &Mailer,
) -> Result<(), Box<dyn Error>> {
	if request.bundle.destination.address != mailer.local.address {
		return Err("PublicKeyRequest names a different local address".into());
	}
	let parameters = crate::public_key_response::Parameters {
		destination: &request.bundle.origin,
		requested: request.bundle.destination.public_key,
		timestamp: now(),
		identifier: request_identifier,
		response_to,
	};
	let local = &mailer.local;
	let secret = &mailer.local_secret;
	let retired = &mailer.retired_secrets;
	let encoded = crate::public_key_response::build(local, secret, retired, parameters)?;
	writer.write_all(&encoded)?;
	writer.flush()?;
	writer.shutdown(Shutdown::Write)?;
	Ok(())
}

fn respond(
	reader: &mut TlvReader<&mut dyn std::io::Read>,
	writer: &mut TcpStream,
	request: &IncomingBundle,
	reply: &ServerReply,
	mailer: &Mailer,
	holds: &mut Vec<PollHold>,
	mut first: Option<OwnedTlv>,
) -> Result<(), Box<dyn Error>> {
	let mut wait_for_client_reply = false;
	loop {
		let value = if let Some(value) = first.take() {
			value
		} else {
			let Some(value) = reader.read_next()? else {
				break;
			};
			value.read_owned()?
		};
		match value.type_code {
			types::SIGNED_TLV => {
				let responses = payload_responses(&value, request, mailer, holds, false)?;
				wait_for_client_reply |= responses.requires_return_bundle;
				if !responses.values.is_empty() {
					let encoded = reply.payload(responses.values, &mailer.local_secret)?;
					writer.write_all(&encoded)?;
					writer.flush()?;
					// The peer answers a returned value by naming the SignedTLV it
					// arrived in, which is the one just written.
					let signed_tlv_hash = hash_tlv(&encoded)?;
					let first_new_hold = holds.len() - responses.new_holds;
					for hold in &mut holds[first_new_hold..] {
						hold.signed_tlv_hash = signed_tlv_hash;
					}
				}
				if responses.close_after_reply {
					return Err("payload has a missing or incorrect Header TLVHash".into());
				}
			}
			types::ORIGIN => {
				require_continuation(wait_for_client_reply)?;
				respond_to_client_replies(reader, writer, value, request, mailer, holds)?;
				break;
			}
			type_code if types::is_defined(type_code) => {
				return Err("unexpected defined top-level value".into());
			}
			_ => {}
		}
	}
	Ok(())
}

/// Processes as many Client Reply Bundles as the requests exchanged require.
///
/// A later Client Reply may contain both responses to values returned by the
/// Server and new requests of its own. Each such Bundle can therefore produce
/// another Server Reply; the loop has no round-count limit.
fn respond_to_client_replies(
	reader: &mut TlvReader<&mut dyn std::io::Read>,
	writer: &mut TcpStream,
	first: OwnedTlv,
	initial: &IncomingBundle,
	mailer: &Mailer,
	holds: &mut Vec<PollHold>,
) -> Result<(), Box<dyn Error>> {
	let peer = initial.bundle.origin.clone();
	let mut incoming =
		read_header(reader, Some(first), mailer)?.ok_or("missing Client Reply Bundle")?;
	loop {
		if incoming.bundle.origin != peer || incoming.bundle.destination != mailer.local {
			return Err("Client Reply Bundle has the wrong identities".into());
		}
		let reply =
			ServerReply::for_request(&incoming.bundle, &mailer.local, &mailer.local_secret, now())?;
		let mut reply_started = false;
		let mut wait_for_client_reply = false;
		loop {
			let Some(value) = reader.read_next()? else {
				return if holds.is_empty() {
					Ok(())
				} else {
					Err(format!(
						"Client Reply Bundle ended with {} response(s) missing",
						holds.len()
					)
					.into())
				};
			};
			let value = value.read_owned()?;
			match value.type_code {
				types::SIGNED_TLV => {
					let responses = payload_responses(&value, &incoming, mailer, holds, true)?;
					wait_for_client_reply |= responses.requires_return_bundle;
					if !responses.values.is_empty() {
						if !reply_started {
							writer.write_all(reply.prefix())?;
							writer.flush()?;
							reply_started = true;
						}
						let encoded = reply.payload(responses.values, &mailer.local_secret)?;
						writer.write_all(&encoded)?;
						writer.flush()?;
						let signed_tlv_hash = hash_tlv(&encoded)?;
						let first_new_hold = holds.len() - responses.new_holds;
						for hold in &mut holds[first_new_hold..] {
							hold.signed_tlv_hash = signed_tlv_hash;
						}
					}
					if responses.close_after_reply {
						return Err("payload has a missing or incorrect Header TLVHash".into());
					}
					if holds.is_empty() && !wait_for_client_reply {
						return Ok(());
					}
				}
				types::ORIGIN => {
					require_continuation(wait_for_client_reply)?;
					incoming = read_header(reader, Some(value), mailer)?
						.ok_or("missing next Client Reply Bundle")?;
					break;
				}
				type_code if types::is_defined(type_code) => {
					return Err("unexpected defined top-level Client Reply value".into());
				}
				_ => {}
			}
		}
	}
}

fn require_continuation(permitted: bool) -> Result<(), Box<dyn Error>> {
	if permitted {
		Ok(())
	} else {
		Err("Client continued after a Bundle without a FileRequest or Poll".into())
	}
}

/// Retains every copy still held when the connection ends.
fn release_holds(holds: &[PollHold], mailer: &Mailer) -> Result<(), Box<dyn Error>> {
	if holds.is_empty() {
		return Ok(());
	}
	let outbound = mailer.store.outbound()?;
	for hold in holds {
		let job_id = &hold.claim.job_id;
		let index = hold.claim.delivery_index;
		let token = &hold.claim.worker_token;
		let outcome = DeliveryOutcome::Deferred {
			retry_at: now(),
			result: "poll ended without a response for this value".to_owned(),
		};
		outbound.finish_delivery(job_id, index, token, now(), outcome)?;
	}
	Ok(())
}

struct PayloadResponses {
	values: Vec<OwnedTlv>,
	close_after_reply: bool,
	requires_return_bundle: bool,
	new_holds: usize,
}

fn payload_responses(
	value: &OwnedTlv,
	request: &IncomingBundle,
	mailer: &Mailer,
	holds: &mut Vec<PollHold>,
	allow_responses: bool,
) -> Result<PayloadResponses, Box<dyn Error>> {
	let payload = receive_payload(value, &request.bundle.origin, request.header_hash, mailer)?;
	if !allow_responses && !payload.responses.is_empty() {
		return Err("an initial Bundle contains a response value".into());
	}
	if allow_responses && !payload.responses.is_empty() {
		let outbound = mailer.store.outbound()?;
		for response in &payload.responses {
			resolve_hold(response, holds, &outbound)?;
		}
	}
	let mut responses = Vec::new();
	let mut returned_identifier = 0u64;
	let mut requires_return_bundle = false;
	let mut new_holds = 0usize;
	for request_value in payload.requests {
		match request_value {
			ReceivedRequest::Valid(item) => {
				requires_return_bundle |= matches!(
					item.kind,
					ItemKind::FileRequest
						| ItemKind::PollMessages
						| ItemKind::PollFiles
						| ItemKind::PollFileRequests
				);
				if let Some(kinds) = poll_kinds(item.kind) {
					let claims = poll_snapshot(kinds, request, mailer)?;
					// TTS-0005 section 3: every value in the snapshot is returned in
					// the same `SignedTLV` as the Accepted, which is the one these
					// responses are about to be built into.
					for claim in claims {
						returned_identifier = returned_identifier
							.checked_add(1)
							.ok_or("too many values returned in one SignedTLV")?;
						// Register the claim before parsing or encoding its item. Any
						// later error reaches `transaction`'s common release path; the
						// real response hash is filled in after this SignedTLV is sent.
						holds.push(PollHold {
							signed_tlv_hash: TlvHash::from_bytes([0; 32]),
							request_identifier: returned_identifier,
							relayed: false,
							claim,
						});
						new_holds += 1;
						let returned =
							single_value(&holds.last().expect("hold was pushed").claim.item)?;
						let relayed = crate::deliver::is_relay_delivery(
							&returned,
							&request.bundle.origin,
							mailer,
						)?;
						holds.last_mut().expect("hold was pushed").relayed = relayed;
						responses.push(set_request_identifier(&returned, returned_identifier)?);
					}
					responses.push(accepted(item.request_identifier, payload.response_to)?);
				} else {
					let acceptance = mailer.acceptance();
					let origin = &request.bundle.origin;
					let response = acceptance.dispatch(&item, payload.response_to, origin)?;
					responses.push(response);
				}
			}
			ReceivedRequest::DataError { request_identifier } => {
				responses.push(data_error_response(
					request_identifier,
					payload.response_to,
				)?);
			}
		}
	}
	Ok(PayloadResponses {
		values: responses,
		close_after_reply: payload.close_after_reply,
		requires_return_bundle,
		new_holds,
	})
}

fn data_error_response(
	request_identifier: u64,
	response_to: TlvHash,
) -> Result<OwnedTlv, tith_wire::bundle::BundleError> {
	rejected(
		request_identifier,
		response_to,
		None,
		RejectionReason::Permanent,
		"request has a data error",
	)
}

/// The spool kinds a Poll value asks for.
///
/// TSP-0002 section 8: `PollFiles` returns both held distribution Files and
/// held peer-addressed Files, because TTS-0005 section 3 type 70 asks for held
/// standalone Files without distinguishing them.
fn poll_kinds(kind: ItemKind) -> Option<&'static [JobKind]> {
	match kind {
		ItemKind::PollMessages => Some(&[JobKind::NetMail, JobKind::EchoMail]),
		ItemKind::PollFiles => Some(&[JobKind::File, JobKind::PeerFile]),
		ItemKind::PollFileRequests => Some(&[JobKind::FileRequest]),
		_ => None,
	}
}

/// Atomically claims everything held for the authenticated Bundle Origin.
fn poll_snapshot(
	kinds: &[JobKind],
	request: &IncomingBundle,
	mailer: &Mailer,
) -> Result<Vec<DeliveryClaim>, Box<dyn Error>> {
	let origin = &request.bundle.origin;
	// An anonymous Origin is only identified together with its PublicKey, so the
	// key is part of the match rather than the address alone.
	let key = origin.address.is_anonymous().then_some(&origin.public_key);
	let outbound = mailer.store.outbound()?;
	let claims = outbound.claim_poll_snapshot(&origin.address.to_string(), key, kinds, now())?;
	Ok(claims)
}

fn single_value(encoded: &[u8]) -> Result<OwnedTlv, Box<dyn Error>> {
	let mut values = parse_sequence(encoded)?;
	if values.len() != 1 {
		return Err("spooled item is not a single TLV value".into());
	}
	Ok(values.remove(0))
}

#[cfg(test)]
pub(super) fn validate_final_reply(
	reader: &mut TlvReader<&mut dyn std::io::Read>,
	first: OwnedTlv,
	request: &IncomingBundle,
	mailer: &Mailer,
	holds: &mut Vec<PollHold>,
) -> Result<(), Box<dyn Error>> {
	let reply = read_header(reader, Some(first), mailer)?.ok_or("missing final Reply Bundle")?;
	if reply.bundle.origin != request.bundle.origin || reply.bundle.destination != mailer.local {
		return Err("final Reply Bundle has the wrong identities".into());
	}
	if holds.is_empty() {
		return Ok(());
	}
	let outbound = mailer.store.outbound()?;
	while let Some(value) = reader.read_next()? {
		let value = value.read_owned()?;
		if value.type_code == types::SIGNED_TLV {
			let payload = receive_payload(&value, &reply.bundle.origin, reply.header_hash, mailer)?;
			if !payload.requests.is_empty() {
				return Err("unexpected request in final Reply Bundle".into());
			}
			for response in &payload.responses {
				resolve_hold(response, holds, &outbound)?;
			}
			// TTS-0005 section 6 makes the Reply Bundle complete once the
			// authenticated SignedTLV containing the last expected response has
			// arrived. The Server must not wait for the Client's FIN.
			if holds.is_empty() {
				return Ok(());
			}
		} else if types::is_defined(value.type_code) {
			return Err("unexpected top-level value after final Reply Header".into());
		}
	}
	Err(format!(
		"final Reply Bundle ended with {} response(s) missing",
		holds.len()
	)
	.into())
}

/// Applies one peer response to the copy it answers.
///
/// TTS-0005 section 6 permits responses in any order, so the hash and identifier
/// select the outstanding hold directly.
fn resolve_hold(
	item: &ValidatedItem,
	holds: &mut Vec<PollHold>,
	outbound: &OutboundStore,
) -> Result<(), Box<dyn Error>> {
	let response_to = item
		.response_to
		.ok_or("final Reply Bundle response has no ResponseTo")?;
	let position = holds
		.iter()
		.position(|hold| {
			hold.signed_tlv_hash == response_to
				&& hold.request_identifier == item.request_identifier
		})
		.ok_or("final Reply Bundle has a duplicate or unexpected response")?;
	let hold = &holds[position];
	let outcome = match item.kind {
		ItemKind::Accepted => DeliveryOutcome::Delivered("accepted by poll".to_owned()),
		_ => crate::deliver::rejection_outcome(item.rejection.as_ref(), now(), hold.relayed),
	};
	let job_id = &hold.claim.job_id;
	let index = hold.claim.delivery_index;
	let token = &hold.claim.worker_token;
	outbound.finish_delivery(job_id, index, token, now(), outcome)?;
	holds.remove(position);
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn only_a_file_request_or_poll_permits_another_reply_round() {
		assert!(require_continuation(true).is_ok());
		assert!(require_continuation(false).is_err());
	}

	#[test]
	fn every_poll_kind_keeps_its_distinct_snapshot_class() {
		assert_eq!(
			poll_kinds(ItemKind::PollMessages),
			Some(&[JobKind::NetMail, JobKind::EchoMail][..])
		);
		assert_eq!(
			poll_kinds(ItemKind::PollFiles),
			Some(&[JobKind::File, JobKind::PeerFile][..])
		);
		assert_eq!(
			poll_kinds(ItemKind::PollFileRequests),
			Some(&[JobKind::FileRequest][..])
		);
		assert_eq!(poll_kinds(ItemKind::NetMail), None);
	}

	#[test]
	fn a_spooled_value_must_be_exactly_one_tlv() {
		let one = OwnedTlv::new(types::CONTENTS, b"one".to_vec()).unwrap();
		assert_eq!(single_value(&one.encode()).unwrap(), one);
		assert!(single_value(&[]).is_err());
		let mut two = one.encode();
		two.extend_from_slice(
			&OwnedTlv::new(types::FILENAME, b"two".to_vec())
				.unwrap()
				.encode(),
		);
		assert!(single_value(&two).is_err());
	}
}
