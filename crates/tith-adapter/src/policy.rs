//! The TSP-0011 section 5.1 final item authentication policy, and the local
//! refusal policy TSP-0013 section 4 requires trusted configuration for.

use tith_wire::item::ItemAuthentication;

/// What to do with an item at final delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
	/// Deliver with a prominent local diagnostic.
	DeliverWarn,
	/// Do not deliver to the addressed user or area. The consumer takes durable
	/// administrative ownership of the exact payload first.
	Orphan,
	/// Origin-Valid is delivered normally, without a warning or a reply.
	Deliver,
}

/// The per-state policy.
///
/// TSP-0011 section 5.1: absent configuration uses Deliver-Warn for Unsigned
/// and `SignedOrigin-Valid`, Orphan for both Invalid states, and disables
/// Reply-Origin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
	pub unsigned: Action,
	pub signed_origin_valid: Action,
	pub signed_origin_invalid: Action,
	pub origin_invalid: Action,
	/// Reply-Origin is explicit local policy, disabled by default, because a
	/// forged Origin makes an automatic reply a backscatter amplifier.
	pub reply_origin: bool,
}

impl Default for Policy {
	fn default() -> Self {
		Self {
			unsigned: Action::DeliverWarn,
			signed_origin_valid: Action::DeliverWarn,
			signed_origin_invalid: Action::Orphan,
			origin_invalid: Action::Orphan,
			reply_origin: false,
		}
	}
}

impl Policy {
	#[must_use]
	pub const fn action(&self, authentication: ItemAuthentication) -> Action {
		match authentication {
			ItemAuthentication::Unsigned => self.unsigned,
			ItemAuthentication::SignedOriginValid => self.signed_origin_valid,
			ItemAuthentication::SignedOriginInvalid => self.signed_origin_invalid,
			ItemAuthentication::OriginInvalid => self.origin_invalid,
			// Origin-Valid needs no policy, and Transport occurs only for a
			// FileRequest, whose enclosing SignedTLV is its complete and intended
			// authentication rather than a reduced one.
			ItemAuthentication::OriginValid | ItemAuthentication::Transport => Action::Deliver,
		}
	}
}

/// The exact diagnostic TSP-0011 section 5.1 gives for each state.
#[must_use]
pub const fn diagnostic(authentication: ItemAuthentication) -> Option<&'static str> {
	Some(match authentication {
		ItemAuthentication::Unsigned => {
			"NOTICE: This message was not signed by its Origin, or its\nsignature was removed before delivery."
		}
		ItemAuthentication::SignedOriginValid => {
			"NOTICE: This message was not signed by its Origin.  Its\nintermediate gateway signature was valid."
		}
		ItemAuthentication::SignedOriginInvalid => {
			"ERROR: This message's intermediate gateway signature does not verify\nunder the public key selected for that gateway."
		}
		ItemAuthentication::OriginInvalid => {
			"ERROR: This message's signature does not verify under the public key\nselected for its claimed Origin."
		}
		ItemAuthentication::OriginValid | ItemAuthentication::Transport => return None,
	})
}

/// Why an item could not be converted, and what the adapter is allowed to do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Refusal {
	/// The conversion itself failed.
	Unconvertible(String),
}

impl std::fmt::Display for Refusal {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Unconvertible(reason) => write!(f, "{reason}"),
		}
	}
}

/// What the adapter does with a refused item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
	/// Terminal. TSP-0013 section 4 permits this "only when trusted policy
	/// authorizes the local terminal outcome".
	Reject,
	/// Retried later. Nothing is lost, but an item which can never succeed will
	/// keep returning, because claim selection is oldest first.
	Defer,
}

/// The configurable refusal policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Refusals {
	/// A conversion which will never succeed for this item.
	pub unconvertible: Disposition,
}

impl Default for Refusals {
	fn default() -> Self {
		Self {
			unconvertible: Disposition::Reject,
		}
	}
}

impl Refusals {
	#[must_use]
	pub const fn disposition(&self, refusal: &Refusal) -> Disposition {
		match refusal {
			Refusal::Unconvertible(_) => self.unconvertible,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_default_policy_is_the_one_the_standard_names() {
		let policy = Policy::default();
		assert_eq!(
			policy.action(ItemAuthentication::Unsigned),
			Action::DeliverWarn
		);
		assert_eq!(
			policy.action(ItemAuthentication::SignedOriginValid),
			Action::DeliverWarn
		);
		assert_eq!(
			policy.action(ItemAuthentication::SignedOriginInvalid),
			Action::Orphan
		);
		assert_eq!(
			policy.action(ItemAuthentication::OriginInvalid),
			Action::Orphan
		);
		assert_eq!(
			policy.action(ItemAuthentication::OriginValid),
			Action::Deliver
		);
		assert!(!policy.reply_origin, "Reply-Origin is disabled by default");
	}

	#[test]
	fn only_the_states_needing_one_have_a_diagnostic() {
		assert!(
			diagnostic(ItemAuthentication::Unsigned)
				.unwrap()
				.starts_with("NOTICE:")
		);
		assert!(
			diagnostic(ItemAuthentication::SignedOriginValid)
				.unwrap()
				.starts_with("NOTICE:")
		);
		assert!(
			diagnostic(ItemAuthentication::OriginInvalid).is_some(),
			"Origin-Invalid has a diagnostic"
		);
		assert_eq!(diagnostic(ItemAuthentication::OriginValid), None);
		assert_eq!(diagnostic(ItemAuthentication::Transport), None);
	}

	#[test]
	fn invalid_states_have_signer_specific_verification_diagnostics() {
		assert_eq!(
			diagnostic(ItemAuthentication::SignedOriginInvalid),
			Some(
				"ERROR: This message's intermediate gateway signature does not verify\nunder the public key selected for that gateway."
			)
		);
		assert_eq!(
			diagnostic(ItemAuthentication::OriginInvalid),
			Some(
				"ERROR: This message's signature does not verify under the public key\nselected for its claimed Origin."
			)
		);
	}

	#[test]
	fn an_unconvertible_item_is_rejected_and_carries_its_reason() {
		let refusals = Refusals::default();
		let refusal = Refusal::Unconvertible("a TIC for a File with no Area".to_owned());
		assert_eq!(refusals.disposition(&refusal), Disposition::Reject);
		assert_eq!(refusal.to_string(), "a TIC for a File with no Area");
		// Deferring is a deployment choice, not a property of the refusal.
		let deferring = Refusals {
			unconvertible: Disposition::Defer,
		};
		assert_eq!(deferring.disposition(&refusal), Disposition::Defer);
	}
}
