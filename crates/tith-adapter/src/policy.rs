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
	/// How an `EchoMail` or file distribution obligation is discharged.
	pub distribution: Distribution,
}

impl Default for Policy {
	fn default() -> Self {
		Self {
			unsigned: Action::DeliverWarn,
			signed_origin_valid: Action::DeliverWarn,
			signed_origin_invalid: Action::Orphan,
			origin_invalid: Action::Orphan,
			reply_origin: false,
			// Native by default: it preserves the authentication state exactly,
			// and it makes the legacy copy genuinely terminal, which is what
			// TSP-0003 section 10.1's "local compatibility presentation" assumes.
			distribution: Distribution::Native,
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
		ItemAuthentication::SignedOriginInvalid | ItemAuthentication::OriginInvalid => {
			"ERROR: This signed message or its signature was modified in\ntransit.  It does not match the bytes authenticated by its signer."
		}
		ItemAuthentication::OriginValid | ItemAuthentication::Transport => return None,
	})
}

/// Which TSP-0013 section 4 branch discharges a distribution obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Distribution {
	/// The adapter commits the equivalent native copies with a TSP-0006
	/// `Job Forward` while the claim is current, and the legacy object it
	/// publishes is for local reading only.
	///
	/// A Forward Job preserves the exact signed children and Signature, so the
	/// item's authentication state survives the fan-out unchanged. The legacy
	/// side must be configured not to forward these areas onward.
	Native,
	/// The legacy tosser creates every required outbound copy.
	///
	/// TSP-0013 section 4 permits this, but an item re-entering TITH from a
	/// legacy area carries no TITHSIG and is re-imported as
	/// `SignedOrigin-Valid` whatever it was before, so an item known to be
	/// modified in transit can be relabelled as gateway-attested.
	Legacy,
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
		assert_eq!(policy.distribution, Distribution::Native);
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
			diagnostic(ItemAuthentication::OriginInvalid)
				.unwrap()
				.starts_with("ERROR:")
		);
		assert_eq!(diagnostic(ItemAuthentication::OriginValid), None);
		assert_eq!(diagnostic(ItemAuthentication::Transport), None);
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
