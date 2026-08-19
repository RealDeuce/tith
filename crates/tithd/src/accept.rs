//! Storing an authenticated item and answering for it.
//!
//! An item reaches this node two ways: a peer connects and sends it, or this
//! node polls a peer and the peer returns it. TSP-0002 draws no distinction
//! between them — the same authorization applies and the same response is owed
//! — so both the listener and the outbound driver dispatch through here.

use std::error::Error;

use tith_config::{ConfigurationSet, IdentityRef};
use tith_crypto::TlvHash;
use tith_store::{AcceptResult, InboundStore, NewInbound};
use tith_wire::bundle::Identity;
use tith_wire::item::{ItemKind, RejectionReason, ValidatedItem, accepted, rejected};
use tith_wire::tlv::OwnedTlv;

/// Everything needed to decide an item's fate and record it.
pub struct Acceptance<'a> {
	pub store: &'a InboundStore,
	pub application: &'a str,
	pub configuration: &'a ConfigurationSet,
	pub local_ref: &'a IdentityRef,
	pub local: &'a Identity,
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
		let rejection = match item.kind {
			ItemKind::NetMail if item.destination.as_ref() != Some(self.local) => {
				Some("relay delivery is not implemented")
			}
			ItemKind::EchoMail if !self.area_allowed(item, false, peer) => {
				Some("EchoMail area is not authorized for this peer")
			}
			ItemKind::File if item.area.is_some() && !self.area_allowed(item, true, peer) => {
				Some("file area is not authorized for this peer")
			}
			ItemKind::FileRequest
			| ItemKind::PollMessages
			| ItemKind::PollFiles
			| ItemKind::PollFileRequests => Some("request type is not implemented"),
			ItemKind::Accepted | ItemKind::Rejected => {
				return Err("a request position contains a response value".into());
			}
			ItemKind::NetMail | ItemKind::EchoMail | ItemKind::File => None,
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
