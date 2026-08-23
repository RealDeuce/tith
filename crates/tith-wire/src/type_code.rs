//! TTS-0003 type-code validity and the terminal Type-0 sequence state.

use crate::tlv::FramingError;

pub(crate) fn require_defined_type(type_code: u64) -> Result<(), FramingError> {
	if type_code == 0 {
		Err(FramingError::InvalidType)
	} else {
		Ok(())
	}
}

#[derive(Default)]
pub(crate) struct SequenceTypeState {
	invalid: bool,
}

impl SequenceTypeState {
	pub(crate) const fn new() -> Self {
		Self { invalid: false }
	}

	pub(crate) fn ensure_active(&self) -> Result<(), FramingError> {
		if self.invalid {
			Err(FramingError::InvalidType)
		} else {
			Ok(())
		}
	}

	pub(crate) fn accept(&mut self, type_code: u64) -> Result<(), FramingError> {
		self.ensure_active()?;
		if type_code == 0 {
			self.invalid = true;
			Err(FramingError::InvalidType)
		} else {
			Ok(())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn producers_accept_every_nonzero_type_and_reject_zero() {
		assert!(matches!(
			require_defined_type(0),
			Err(FramingError::InvalidType)
		));
		assert!(require_defined_type(1).is_ok());
		assert!(require_defined_type(u64::MAX).is_ok());
	}

	#[test]
	fn a_type_zero_permanently_terminates_the_sequence_state() {
		let mut state = SequenceTypeState::new();
		assert!(state.ensure_active().is_ok());
		assert!(state.accept(1).is_ok());
		assert!(matches!(state.accept(0), Err(FramingError::InvalidType)));
		assert!(matches!(
			state.ensure_active(),
			Err(FramingError::InvalidType)
		));
		assert!(matches!(state.accept(2), Err(FramingError::InvalidType)));
	}
}
