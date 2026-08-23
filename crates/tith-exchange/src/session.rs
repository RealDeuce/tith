//! TTS-0006 Client session order and active-close policy.

use std::io::{self, Read, Write};

use tith_wire::bundle::Bundle;

use crate::{CompletedResponse, ExchangeError, OutstandingRequest, ResponseTracker};

pub trait ExchangeIo: Read + Write {
	fn shutdown_write(&mut self) -> io::Result<()>;
}

pub fn send_bundle(
	io: &mut dyn ExchangeIo,
	encoded: &[u8],
	keep_write_open: bool,
) -> Result<(), ExchangeError> {
	io.write_all(encoded)?;
	io.flush()?;
	if !keep_write_open {
		io.shutdown_write()?;
	}
	Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
	Ready,
	AwaitingReplyHeader,
	AwaitingResponses,
	MustSendReply,
	Closing,
	Complete,
	Failed,
}

#[derive(Clone, Debug)]
pub struct ClientSession {
	state: SessionState,
	tracker: ResponseTracker,
}

impl ClientSession {
	#[must_use]
	pub fn new(tracker: ResponseTracker) -> Self {
		Self {
			state: SessionState::Ready,
			tracker,
		}
	}

	#[must_use]
	pub const fn state(&self) -> SessionState {
		self.state
	}

	/// Whether this exchange owes the peer a final Reply Bundle.
	#[must_use]
	pub fn requires_return_bundle(&self) -> bool {
		self.tracker.requires_return_bundle()
	}

	/// The responses received so far, in request order.
	#[must_use]
	pub fn responses(&self) -> &[CompletedResponse] {
		self.tracker.completed()
	}

	/// The requests sent in this round, in transmission order.
	#[must_use]
	pub fn requests(&self) -> &[OutstandingRequest] {
		self.tracker.outstanding()
	}

	pub fn initial_sent(&mut self) -> Result<(), ExchangeError> {
		if self.state != SessionState::Ready {
			self.state = SessionState::Failed;
			return Err(ExchangeError::UnexpectedResponse);
		}
		self.state = SessionState::AwaitingReplyHeader;
		Ok(())
	}

	/// Validates the transport identities before any Reply payload is acted on.
	pub fn reply_header_received(&mut self, reply: &Bundle) -> Result<(), ExchangeError> {
		if self.state != SessionState::AwaitingReplyHeader {
			self.state = SessionState::Failed;
			return Err(ExchangeError::UnexpectedResponse);
		}
		if let Err(error) = self.tracker.validate_reply_identity(reply) {
			self.state = SessionState::Failed;
			return Err(error);
		}
		if self.tracker.is_complete() {
			self.state = SessionState::Closing;
		} else {
			self.state = SessionState::AwaitingResponses;
		}
		Ok(())
	}

	/// Records the already authenticated responses in one received `SignedTLV`.
	pub fn responses_received(
		&mut self,
		responses: &[tith_wire::item::ValidatedItem],
	) -> Result<(), ExchangeError> {
		if self.state != SessionState::AwaitingResponses {
			self.state = SessionState::Failed;
			return Err(ExchangeError::UnexpectedResponse);
		}
		if let Err(error) = self.tracker.observe_responses(responses) {
			self.state = SessionState::Failed;
			return Err(error);
		}
		if self.tracker.is_complete() {
			self.state = if self.tracker.requires_return_bundle() {
				SessionState::MustSendReply
			} else {
				SessionState::Closing
			};
		}
		Ok(())
	}

	pub fn final_reply_sent(&mut self) -> Result<(), ExchangeError> {
		if self.state != SessionState::MustSendReply {
			self.state = SessionState::Failed;
			return Err(ExchangeError::UnexpectedResponse);
		}
		self.state = SessionState::Closing;
		Ok(())
	}

	pub fn closed(&mut self) -> Result<(), ExchangeError> {
		if self.state == SessionState::Closing && self.tracker.is_complete() {
			self.state = SessionState::Complete;
			Ok(())
		} else {
			self.state = SessionState::Failed;
			if self.tracker.is_complete() {
				Err(ExchangeError::UnexpectedResponse)
			} else {
				self.tracker.require_complete()
			}
		}
	}
}
