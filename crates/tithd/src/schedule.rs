//! TSP-0002 section 8 schedule activation.
//!
//! A schedule decides *when* work runs; which work it selects is the caller's
//! business. This owns only the timing rules: Start gives the first nominal
//! beginning, Duration gives the nominal end relative to it, and Repeat-After
//! gives the interval from one nominal end to the next beginning.
//!
//! Three rules make this less obvious than a timer. Missed activations are
//! coalesced, so an idle schedule with several due beginnings runs only the
//! most recent. A schedule has at most one active activation. And a beginning
//! which passes while that schedule is active is not separately queued.

use tith_config::Schedule;
use tith_message_legacy::{ExportError, civil_from_local};

/// One schedule's timing state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct State {
	/// The next nominal beginning, in seconds since the epoch.
	next_beginning: u64,
	/// The nominal end while an activation is running.
	active_until: Option<u64>,
}

/// An activation which has just begun.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Activation {
	/// Index into the schedules the [`Scheduler`] was built from.
	pub schedule: usize,
	/// The nominal beginning this activation represents, which is the most
	/// recent due one rather than necessarily the current instant.
	pub beginning: u64,
	/// The nominal end. Already past when the activation started late, in which
	/// case it still makes one pass.
	pub nominal_end: u64,
}

impl Activation {
	/// Whether the activation may still claim work at `now`.
	///
	/// A Duration of zero makes exactly one pass and then ends, so this is false
	/// for it from the outset; the caller makes its single pass regardless.
	#[must_use]
	pub const fn is_open(&self, now: u64) -> bool {
		now < self.nominal_end
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduleError {
	/// A schedule uses `Start Local` but no UTC offset was configured.
	///
	/// Safe portable Rust cannot read the host's civil offset, so the daemon is
	/// told it explicitly rather than silently treating local time as UTC.
	MissingLocalOffset,
	/// The configured Start does not resolve to a representable instant.
	UnrepresentableStart,
}

impl std::fmt::Display for ScheduleError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(match self {
			Self::MissingLocalOffset => {
				"a schedule uses Start Local but no --local-offset was given, and the host civil offset cannot be determined"
			}
			Self::UnrepresentableStart => "a schedule Start does not resolve to a usable instant",
		})
	}
}

impl std::error::Error for ScheduleError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scheduler {
	states: Vec<State>,
}

impl Scheduler {
	/// Builds the timing state for a configuration taking effect at `effective`.
	///
	/// TSP-0002 section 8: Start is "the nominal beginning of the first
	/// activation, on the UTC or local civil date when the configuration set
	/// takes effect". `local_offset` is seconds east of UTC and is required only
	/// when some schedule uses `Start Local`.
	pub fn new(
		schedules: &[Schedule],
		effective: u64,
		local_offset: Option<i64>,
	) -> Result<Self, ScheduleError> {
		let mut states = Vec::with_capacity(schedules.len());
		for schedule in schedules {
			let offset = if schedule.start_local {
				local_offset.ok_or(ScheduleError::MissingLocalOffset)?
			} else {
				0
			};
			states.push(State {
				next_beginning: first_beginning(schedule, effective, offset)?,
				active_until: None,
			});
		}
		Ok(Self { states })
	}

	/// Ends any activation whose nominal end has passed, and begins every
	/// schedule which is due.
	///
	/// An activation is reported once, when it begins. A schedule which is
	/// already active is skipped entirely, which is what keeps a beginning
	/// passing during an activation from being separately queued.
	pub fn poll(&mut self, schedules: &[Schedule], now: u64) -> Vec<Activation> {
		let mut begun = Vec::new();
		for (index, state) in self.states.iter_mut().enumerate() {
			if state.active_until.is_some_and(|end| now >= end) {
				state.active_until = None;
			}
			if state.active_until.is_some() || state.next_beginning > now {
				continue;
			}
			let schedule = &schedules[index];
			let duration = schedule.duration_minutes.saturating_mul(60);
			// One beginning to the next is Duration then Repeat-After. Repeat-After
			// defaults to one minute and must be greater than zero, so a period is
			// never zero and this cannot spin.
			let period = duration.saturating_add(schedule.repeat_after_minutes.saturating_mul(60));
			// Coalesce: only the most recent due beginning runs. Repeat-After
			// must be greater than zero so a period never is, but a checked
			// division keeps that a local fact rather than an assumption.
			let beginning = (now - state.next_beginning)
				.checked_div(period)
				.map_or(state.next_beginning, |skipped| {
					state.next_beginning + skipped * period
				});
			let nominal_end = beginning.saturating_add(duration);
			state.next_beginning = beginning.saturating_add(period.max(1));
			// A Duration of zero makes one pass and ends, so it never occupies the
			// schedule; a nonzero one holds it until its nominal end.
			state.active_until = (nominal_end > now).then_some(nominal_end);
			begun.push(Activation {
				schedule: index,
				beginning,
				nominal_end,
			});
		}
		begun
	}

	/// Reports that an activation's work has finished.
	///
	/// A Duration zero activation is over as soon as its pass completes; a
	/// nonzero one keeps its slot until its nominal end so that a beginning
	/// passing meanwhile is not queued.
	pub fn finished(&mut self, activation: &Activation, now: u64) {
		if let Some(state) = self.states.get_mut(activation.schedule)
			&& state.active_until.is_some_and(|end| now >= end)
		{
			state.active_until = None;
		}
	}

	/// The next nominal beginning of one schedule.
	///
	/// TSP-0002 section 6 retains a copy which could not be delivered "for the
	/// next applicable schedule", which is exactly this.
	#[must_use]
	pub fn next_beginning(&self, schedule: usize) -> Option<u64> {
		self.states.get(schedule).map(|state| state.next_beginning)
	}

	/// The next instant at which [`poll`](Self::poll) could return anything.
	#[must_use]
	pub fn next_wakeup(&self) -> Option<u64> {
		self.states
			.iter()
			.map(|state| match state.active_until {
				Some(end) => end.min(state.next_beginning),
				None => state.next_beginning,
			})
			.min()
	}
}

/// The first nominal beginning: the Start time of day on the date the
/// configuration took effect, in the schedule's own zone.
fn first_beginning(schedule: &Schedule, effective: u64, offset: i64) -> Result<u64, ScheduleError> {
	let local = i64::try_from(effective)
		.map_err(|_| ScheduleError::UnrepresentableStart)?
		.checked_add(offset)
		.ok_or(ScheduleError::UnrepresentableStart)?;
	// civil_from_local exists for the legacy exporter and does exactly the
	// proleptic Gregorian arithmetic needed here.
	let civil =
		civil_from_local(local).map_err(|_: ExportError| ScheduleError::UnrepresentableStart)?;
	let midnight = local
		- i64::from(civil.hour) * 3600
		- i64::from(civil.minute) * 60
		- i64::from(civil.second);
	let beginning = midnight + i64::from(schedule.start_minutes) * 60 - offset;
	u64::try_from(beginning).map_err(|_| ScheduleError::UnrepresentableStart)
}

#[cfg(test)]
mod tests {
	use super::*;
	use tith_config::{IdentityRef, Selector};

	fn schedule(duration: u64, repeat: u64, start_minutes: u16) -> Schedule {
		Schedule {
			name: "test".to_owned(),
			origin: IdentityRef::Peer("local".to_owned()),
			classes: vec!["Normal".to_owned()],
			next_hops: vec![Selector::All],
			polls: Vec::new(),
			start_local: false,
			start_minutes,
			duration_minutes: duration,
			repeat_after_minutes: repeat,
		}
	}

	/// 2026-08-18 00:00:00 UTC.
	const MIDNIGHT: u64 = 1_787_011_200;

	#[test]
	fn a_zero_duration_schedule_makes_exactly_one_pass_per_period() {
		// Start 00:10, Duration 0, Repeat-After 30.
		let schedules = [schedule(0, 30, 10)];
		let mut clock = Scheduler::new(&schedules, MIDNIGHT, None).unwrap();
		let start = MIDNIGHT + 600;

		assert!(clock.poll(&schedules, start - 1).is_empty());
		let begun = clock.poll(&schedules, start);
		assert_eq!(begun.len(), 1);
		assert_eq!(begun[0].beginning, start);
		assert_eq!(begun[0].nominal_end, start);
		// Duration zero: the activation is not open, so the caller makes its one
		// pass and stops.
		assert!(!begun[0].is_open(start));
		// And it does not run again until the next period.
		assert!(clock.poll(&schedules, start + 1).is_empty());
		assert!(clock.poll(&schedules, start + 1799).is_empty());
		assert_eq!(clock.poll(&schedules, start + 1800).len(), 1);
	}

	#[test]
	fn a_nonzero_duration_stays_open_and_occupies_its_schedule() {
		// Duration 60 minutes, Repeat-After 30.
		let schedules = [schedule(60, 30, 0)];
		let mut clock = Scheduler::new(&schedules, MIDNIGHT, None).unwrap();
		let begun = clock.poll(&schedules, MIDNIGHT);
		assert_eq!(begun.len(), 1);
		assert_eq!(begun[0].nominal_end, MIDNIGHT + 3600);
		// It may claim work which appears during the interval.
		assert!(begun[0].is_open(MIDNIGHT + 3599));
		assert!(!begun[0].is_open(MIDNIGHT + 3600));

		// A beginning passing while it is active is not separately queued.
		assert!(clock.poll(&schedules, MIDNIGHT + 3599).is_empty());
		// The next beginning is Duration then Repeat-After after the first.
		assert!(clock.poll(&schedules, MIDNIGHT + 3600).is_empty());
		let next = clock.poll(&schedules, MIDNIGHT + 3600 + 1800);
		assert_eq!(next.len(), 1);
		assert_eq!(next[0].beginning, MIDNIGHT + 5400);
	}

	#[test]
	fn missed_beginnings_coalesce_to_the_most_recent() {
		// Duration 0, Repeat-After 10. The daemon was down for an hour.
		let schedules = [schedule(0, 10, 0)];
		let mut clock = Scheduler::new(&schedules, MIDNIGHT, None).unwrap();
		let late = MIDNIGHT + 3600;
		let begun = clock.poll(&schedules, late);
		assert_eq!(
			begun.len(),
			1,
			"six due beginnings must run once, not six times"
		);
		// The most recent due beginning, not the oldest.
		assert_eq!(begun[0].beginning, late);
		// The following one is a full period later.
		assert!(clock.poll(&schedules, late + 599).is_empty());
		assert_eq!(clock.poll(&schedules, late + 600).len(), 1);
	}

	#[test]
	fn an_activation_beginning_after_its_nominal_end_still_makes_one_pass() {
		// Duration 10 minutes, Repeat-After 10, so a period is 20 minutes. The
		// daemon wakes 71 minutes late: the most recent due beginning was at 60
		// minutes and its nominal end passed at 70.
		let schedules = [schedule(10, 10, 0)];
		let mut clock = Scheduler::new(&schedules, MIDNIGHT, None).unwrap();
		let late = MIDNIGHT + 4260;
		let begun = clock.poll(&schedules, late);
		assert_eq!(begun.len(), 1);
		assert_eq!(begun[0].beginning, MIDNIGHT + 3600);
		assert!(
			!begun[0].is_open(late),
			"its nominal end has passed, so it makes one pass rather than staying open"
		);
		// Having made that pass it does not occupy the schedule.
		assert_eq!(clock.poll(&schedules, MIDNIGHT + 4800).len(), 1);
	}

	#[test]
	fn start_places_the_first_beginning_on_the_effective_date() {
		// Start 09:30 with the configuration taking effect at 08:00.
		let schedules = [schedule(0, 60, 9 * 60 + 30)];
		let mut clock = Scheduler::new(&schedules, MIDNIGHT + 8 * 3600, None).unwrap();
		let expected = MIDNIGHT + 9 * 3600 + 1800;
		assert!(clock.poll(&schedules, expected - 1).is_empty());
		assert_eq!(clock.poll(&schedules, expected)[0].beginning, expected);
	}

	#[test]
	fn a_local_start_needs_an_offset_and_applies_it() {
		let mut local = schedule(0, 60, 9 * 60);
		local.start_local = true;
		let schedules = [local];
		assert_eq!(
			Scheduler::new(&schedules, MIDNIGHT, None).unwrap_err(),
			ScheduleError::MissingLocalOffset
		);
		// Seven hours west: 09:00 local is 16:00 UTC.
		let mut clock = Scheduler::new(&schedules, MIDNIGHT + 12 * 3600, Some(-25_200)).unwrap();
		let expected = MIDNIGHT + 16 * 3600;
		assert!(clock.poll(&schedules, expected - 1).is_empty());
		assert_eq!(clock.poll(&schedules, expected)[0].beginning, expected);
	}

	#[test]
	fn different_schedules_run_concurrently() {
		let schedules = [schedule(60, 30, 0), schedule(0, 10, 0)];
		let mut clock = Scheduler::new(&schedules, MIDNIGHT, None).unwrap();
		let begun = clock.poll(&schedules, MIDNIGHT);
		assert_eq!(begun.len(), 2);
		assert_eq!(begun[0].schedule, 0);
		assert_eq!(begun[1].schedule, 1);
		// The first is still active and the second is free to run again.
		let again = clock.poll(&schedules, MIDNIGHT + 600);
		assert_eq!(again.len(), 1);
		assert_eq!(again[0].schedule, 1);
	}
}
