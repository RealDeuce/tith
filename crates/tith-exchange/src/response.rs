//! TTS-0006 request accounting and Reply Bundle construction.

use tith_crypto::{SecretKey, TlvHash, hash_tlv};
use tith_wire::bundle::{Bundle, Identity, KeyResolver, build_bundle, build_signed_tlv};
use tith_wire::item::{ItemKind, Rejection, ValidatedItem, validate_payload};
use tith_wire::tlv::{OwnedTlv, parse_sequence};
use tith_wire::types;

use crate::ExchangeError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestKind {
	Message,
	File,
	FileRequest,
	PollMessages,
	PollFiles,
	PollFileRequests,
	PublicKeyRequest,
}

impl RequestKind {
	#[must_use]
	pub const fn requires_return_bundle(self) -> bool {
		matches!(
			self,
			Self::FileRequest | Self::PollMessages | Self::PollFiles | Self::PollFileRequests
		)
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutstandingRequest {
	pub signed_tlv_hash: TlvHash,
	pub request_identifier: u64,
	pub kind: RequestKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseKind {
	Accepted,
	Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedResponse {
	pub request: OutstandingRequest,
	pub response: ResponseKind,
	/// The reason, retry Timestamp, and description of a Rejected response.
	pub rejection: Option<Rejection>,
}

fn request_kind(item: &ValidatedItem) -> Option<RequestKind> {
	match item.kind {
		ItemKind::NetMail | ItemKind::EchoMail => Some(RequestKind::Message),
		ItemKind::File => Some(RequestKind::File),
		ItemKind::FileRequest => Some(RequestKind::FileRequest),
		ItemKind::PollMessages => Some(RequestKind::PollMessages),
		ItemKind::PollFiles => Some(RequestKind::PollFiles),
		ItemKind::PollFileRequests => Some(RequestKind::PollFileRequests),
		ItemKind::PublicKeyRequest => Some(RequestKind::PublicKeyRequest),
		ItemKind::Accepted | ItemKind::Rejected => None,
	}
}

#[derive(Clone, Debug)]
pub struct ResponseTracker {
	origin: Identity,
	destination: Identity,
	pub(crate) outstanding: Vec<OutstandingRequest>,
	completed: Vec<CompletedResponse>,
}

impl ResponseTracker {
	pub fn for_bundle(bundle: &Bundle, resolver: &dyn KeyResolver) -> Result<Self, ExchangeError> {
		let mut outstanding = Vec::new();
		for payload in &bundle.payloads {
			let signed_tlv_hash = hash_tlv(&payload.encoded)?;
			for item in validate_payload(payload, resolver)? {
				if let Some(kind) = request_kind(&item) {
					outstanding.push(OutstandingRequest {
						signed_tlv_hash,
						request_identifier: item.request_identifier,
						kind,
					});
				}
			}
		}
		Ok(Self {
			origin: bundle.origin.clone(),
			destination: bundle.destination.clone(),
			outstanding,
			completed: Vec::new(),
		})
	}

	#[must_use]
	pub fn expected(&self) -> usize {
		self.outstanding.len()
	}

	#[must_use]
	pub fn received(&self) -> usize {
		self.completed.len()
	}

	#[must_use]
	pub fn is_complete(&self) -> bool {
		self.received() == self.expected()
	}

	#[must_use]
	pub fn requires_return_bundle(&self) -> bool {
		self.outstanding
			.iter()
			.any(|request| request.kind.requires_return_bundle())
	}

	#[must_use]
	pub fn completed(&self) -> &[CompletedResponse] {
		&self.completed
	}

	pub fn observe_reply(
		&mut self,
		reply: &Bundle,
		resolver: &dyn KeyResolver,
	) -> Result<(), ExchangeError> {
		if reply.origin != self.destination {
			return Err(ExchangeError::WrongReplyOrigin);
		}
		if reply.destination != self.origin {
			return Err(ExchangeError::WrongReplyDestination);
		}
		for payload in &reply.payloads {
			for item in validate_payload(payload, resolver)? {
				let response = match item.kind {
					ItemKind::Accepted => ResponseKind::Accepted,
					ItemKind::Rejected => ResponseKind::Rejected,
					_ => continue,
				};
				let rejection = item.rejection.clone();
				let response_hash = item.response_to.ok_or(ExchangeError::UnexpectedResponse)?;
				let Some(position) = self.outstanding.iter().position(|request| {
					request.signed_tlv_hash == response_hash
						&& request.request_identifier == item.request_identifier
				}) else {
					return Err(ExchangeError::UnexpectedResponse);
				};
				if item.response_public_key.is_some()
					&& self.outstanding[position].kind != RequestKind::PublicKeyRequest
				{
					return Err(ExchangeError::UnexpectedResponse);
				}
				if self.completed.iter().any(|completed| {
					completed.request.signed_tlv_hash == response_hash
						&& completed.request.request_identifier == item.request_identifier
				}) {
					return Err(ExchangeError::DuplicateResponse);
				}
				let completed = CompletedResponse {
					request: self.outstanding[position].clone(),
					response,
					rejection,
				};
				let insertion = self.completed.partition_point(|existing| {
					let existing_position = self
						.outstanding
						.iter()
						.position(|request| {
							request.signed_tlv_hash == existing.request.signed_tlv_hash
								&& request.request_identifier == existing.request.request_identifier
						})
						.expect("completed responses name outstanding requests");
					existing_position < position
				});
				self.completed.insert(insertion, completed);
			}
		}
		Ok(())
	}

	pub fn require_complete(&self) -> Result<(), ExchangeError> {
		if self.is_complete() {
			Ok(())
		} else {
			Err(ExchangeError::IncompleteResponse {
				expected: self.expected(),
				received: self.received(),
			})
		}
	}
}

#[derive(Clone, Debug)]
pub struct ServerReply {
	prefix: Vec<u8>,
	header_hash: TlvHash,
	pub origin: Identity,
	pub destination: Identity,
}

impl ServerReply {
	pub fn for_request(
		request: &Bundle,
		local: &Identity,
		local_secret: &SecretKey,
		timestamp: u64,
	) -> Result<Self, ExchangeError> {
		if request.destination != *local {
			return Err(ExchangeError::WrongDestination);
		}
		let prefix = build_bundle(local, local_secret, &request.origin, timestamp, Vec::new())?;
		let top = parse_sequence(&prefix).map_err(tith_wire::BundleError::from)?;
		let header = top
			.iter()
			.find(|value| value.type_code == types::SIGNED_TLV)
			.ok_or(tith_wire::BundleError::Missing("Reply Header SignedTLV"))?;
		Ok(Self {
			header_hash: hash_tlv(&header.encode())?,
			prefix,
			origin: local.clone(),
			destination: request.origin.clone(),
		})
	}

	#[must_use]
	pub fn prefix(&self) -> &[u8] {
		&self.prefix
	}

	pub fn payload(
		&self,
		responses: Vec<OwnedTlv>,
		local_secret: &SecretKey,
	) -> Result<Vec<u8>, ExchangeError> {
		let mut data = Vec::with_capacity(responses.len() + 1);
		data.push(
			OwnedTlv::new(types::TLV_HASH, self.header_hash.as_bytes().to_vec())
				.map_err(tith_wire::BundleError::from)?,
		);
		data.extend(responses);
		Ok(build_signed_tlv(&data, None, local_secret)?.encode())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn item(kind: ItemKind) -> ValidatedItem {
		ValidatedItem {
			kind,
			request_identifier: 1,
			duplicate_identity: None,
			authentication: None,
			response_to: None,
			response_public_key: None,
			rejection: None,
			provenance: None,
			destination: None,
			area: None,
			raw: OwnedTlv::new(200, Vec::new()).unwrap(),
		}
	}

	#[test]
	fn every_item_and_request_kind_has_one_accounting_class() {
		for kind in [ItemKind::NetMail, ItemKind::EchoMail] {
			assert_eq!(request_kind(&item(kind)), Some(RequestKind::Message));
		}
		for (item_kind, request_kind_value) in [
			(ItemKind::File, RequestKind::File),
			(ItemKind::FileRequest, RequestKind::FileRequest),
			(ItemKind::PollMessages, RequestKind::PollMessages),
			(ItemKind::PollFiles, RequestKind::PollFiles),
			(ItemKind::PollFileRequests, RequestKind::PollFileRequests),
			(ItemKind::PublicKeyRequest, RequestKind::PublicKeyRequest),
		] {
			assert_eq!(request_kind(&item(item_kind)), Some(request_kind_value));
		}
		for kind in [ItemKind::Accepted, ItemKind::Rejected] {
			assert_eq!(request_kind(&item(kind)), None);
		}
		for kind in [
			RequestKind::Message,
			RequestKind::File,
			RequestKind::PublicKeyRequest,
		] {
			assert!(!kind.requires_return_bundle());
		}
		for kind in [
			RequestKind::FileRequest,
			RequestKind::PollMessages,
			RequestKind::PollFiles,
			RequestKind::PollFileRequests,
		] {
			assert!(kind.requires_return_bundle());
		}
	}
}
