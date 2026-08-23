//! Server-side construction of `PublicKeyRequest` replies.

use std::sync::Arc;

use tith_crypto::{PublicKey, SecretKey, TlvHash};
use tith_wire::bundle::{
	BundleError, Identity, build_public_key_reply, build_public_key_unavailable_reply,
};

#[derive(Clone, Copy)]
pub(crate) struct Parameters<'a> {
	pub destination: &'a Identity,
	pub requested: PublicKey,
	pub timestamp: u64,
	pub identifier: u64,
	pub response_to: TlvHash,
}

pub(crate) fn build(
	local: &Identity,
	current_secret: &SecretKey,
	retired_secrets: &[Arc<SecretKey>],
	request: Parameters<'_>,
) -> Result<Vec<u8>, BundleError> {
	let signing_secret = std::iter::once(current_secret)
		.chain(retired_secrets.iter().map(AsRef::as_ref))
		.find(|secret| secret.public_key() == request.requested);
	if let Some(signing_secret) = signing_secret {
		let signing_origin = Identity {
			address: local.address.clone(),
			public_key: request.requested,
		};
		return build_public_key_reply(
			&signing_origin,
			signing_secret,
			request.destination,
			request.timestamp,
			request.identifier,
			request.response_to,
			current_secret.public_key(),
		);
	}
	build_public_key_unavailable_reply(
		local,
		current_secret,
		request.destination,
		request.timestamp,
		request.identifier,
		request.response_to,
	)
}
