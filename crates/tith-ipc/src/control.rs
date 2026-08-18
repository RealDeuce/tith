use super::{
	Document, EnvelopeKind, FailureDisposition, FailureNotification, FailureOverride, Field,
	IpcError, Line, NextHop, fail,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JobRequest {
	Query {
		job_id: String,
		item_aware: bool,
		paths: bool,
	},
	Cancel {
		job_id: String,
	},
	Retry {
		job_id: String,
	},
	Reroute {
		job_id: String,
		next_hop: NextHop,
		failure_policy: Option<FailureOverride>,
	},
	Events {
		application: String,
		wait: bool,
	},
	Acknowledge {
		application: String,
		event_id: String,
	},
}

impl JobRequest {
	pub fn parse(input: &[u8]) -> Result<Self, IpcError> {
		let document = Document::parse(input, EnvelopeKind::Request)?;
		let Some(first) = document.lines.first() else {
			return Err(fail(2, "missing operation"));
		};
		match first.fields.as_slice() {
			[
				Field {
					text: op,
					quoted: false,
				},
				Field {
					text: id,
					quoted: false,
				},
			] if matches!(op.as_str(), "Query" | "Query-Job")
				&& valid_job_id(id)
				&& document.lines.len() == 1 =>
			{
				Ok(Self::Query {
					job_id: id.clone(),
					item_aware: op == "Query-Job",
					paths: false,
				})
			}
			[
				Field {
					text: op,
					quoted: false,
				},
				Field {
					text: id,
					quoted: false,
				},
				Field {
					text: paths,
					quoted: false,
				},
			] if matches!(op.as_str(), "Query" | "Query-Job")
				&& valid_job_id(id)
				&& paths == "Paths"
				&& document.lines.len() == 1 =>
			{
				Ok(Self::Query {
					job_id: id.clone(),
					item_aware: op == "Query-Job",
					paths: true,
				})
			}
			[
				Field {
					text: op,
					quoted: false,
				},
				Field {
					text: id,
					quoted: false,
				},
			] if matches!(op.as_str(), "Cancel" | "Retry")
				&& valid_job_id(id)
				&& document.lines.len() == 1 =>
			{
				if op == "Cancel" {
					Ok(Self::Cancel { job_id: id.clone() })
				} else {
					Ok(Self::Retry { job_id: id.clone() })
				}
			}
			[
				Field {
					text: op,
					quoted: false,
				},
				Field {
					text: id,
					quoted: false,
				},
			] if op == "Reroute" && valid_job_id(id) => parse_reroute(id, &document.lines),
			[
				Field {
					text: op,
					quoted: false,
				},
				Field {
					text: application,
					quoted: true,
				},
				Field {
					text: mode,
					quoted: false,
				},
			] if op == "Events"
				&& !application.is_empty()
				&& matches!(mode.as_str(), "Now" | "Wait")
				&& document.lines.len() == 1 =>
			{
				Ok(Self::Events {
					application: application.clone(),
					wait: mode == "Wait",
				})
			}
			[
				Field {
					text: op,
					quoted: false,
				},
				Field {
					text: application,
					quoted: true,
				},
				Field {
					text: event,
					quoted: true,
				},
			] if op == "Acknowledge"
				&& !application.is_empty()
				&& valid_event_id(event)
				&& document.lines.len() == 1 =>
			{
				Ok(Self::Acknowledge {
					application: application.clone(),
					event_id: event.clone(),
				})
			}
			_ => Err(fail(2, "not a job query, control, or event operation")),
		}
	}
}

fn parse_reroute(id: &str, lines: &[Line]) -> Result<JobRequest, IpcError> {
	if !(2..=3).contains(&lines.len()) {
		return Err(fail(2, "invalid Reroute operation"));
	}
	let next_hop = match lines[1].fields.as_slice() {
		[
			Field {
				text: name,
				quoted: false,
			},
			Field {
				text: mode,
				quoted: false,
			},
		] if name == "Next-Hop" && mode == "Route" => NextHop::Route,
		[
			Field {
				text: name,
				quoted: false,
			},
			Field {
				text: mode,
				quoted: false,
			},
			Field {
				text: target,
				quoted: true,
			},
		] if name == "Next-Hop" && mode == "Active" && !target.is_empty() => {
			NextHop::Active(target.clone())
		}
		[
			Field {
				text: name,
				quoted: false,
			},
			Field {
				text: mode,
				quoted: false,
			},
			Field {
				text: target,
				quoted: true,
			},
		] if name == "Next-Hop" && mode == "Passive" && !target.is_empty() => {
			NextHop::Passive(target.clone())
		}
		_ => return Err(fail(3, "invalid Next-Hop")),
	};
	let failure_policy = if lines.len() == 3 {
		Some(match lines[2].fields.as_slice() {
			[
				Field {
					text: name,
					quoted: false,
				},
				Field {
					text: route,
					quoted: false,
				},
			] if name == "Failure-Policy" && route == "Route" => FailureOverride::Route,
			[
				Field {
					text: name,
					quoted: false,
				},
				Field {
					text: disposition,
					quoted: false,
				},
				Field {
					text: notify,
					quoted: false,
				},
				Field {
					text: notification,
					quoted: false,
				},
			] if name == "Failure-Policy" && notify == "Notify" => FailureOverride::Policy {
				disposition: match disposition.as_str() {
					"Dead-Letter" => FailureDisposition::DeadLetter,
					"Discard" => FailureDisposition::Discard,
					_ => return Err(fail(4, "invalid Failure-Policy disposition")),
				},
				notification: match notification.as_str() {
					"None" => FailureNotification::None,
					"Sender" => FailureNotification::Sender,
					"Origin-Sysop" => FailureNotification::OriginSysop,
					"Both" => FailureNotification::Both,
					_ => return Err(fail(4, "invalid Failure-Policy notification")),
				},
			},
			_ => return Err(fail(4, "invalid Failure-Policy")),
		})
	} else {
		None
	};
	Ok(JobRequest::Reroute {
		job_id: id.to_owned(),
		next_hop,
		failure_policy,
	})
}

fn valid_job_id(value: &str) -> bool {
	value.len() == 33
		&& value.starts_with('J')
		&& value[1..]
			.bytes()
			.all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_event_id(value: &str) -> bool {
	let Some((job, sequence)) = value.rsplit_once(':') else {
		return false;
	};
	valid_job_id(job)
		&& !sequence.is_empty()
		&& sequence.bytes().all(|byte| byte.is_ascii_digit())
		&& !sequence.starts_with('0')
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_queries_controls_and_events() {
		let id = "J0123456789abcdef0123456789abcdef";
		assert!(matches!(
			JobRequest::parse(format!("TITH-IPC 1\nQuery-Job {id} Paths\nEnd\n").as_bytes())
				.unwrap(),
			JobRequest::Query {
				item_aware: true,
				paths: true,
				..
			}
		));
		assert!(matches!(JobRequest::parse(format!("TITH-IPC 1\nReroute {id}\nNext-Hop Active \"@peer\"\nFailure-Policy Discard Notify Both\nEnd\n").as_bytes()).unwrap(), JobRequest::Reroute { .. }));
		assert!(matches!(
			JobRequest::parse(b"TITH-IPC 1\nEvents \"tosser\" Wait\nEnd\n").unwrap(),
			JobRequest::Events { wait: true, .. }
		));
		assert!(
			JobRequest::parse(
				format!("TITH-IPC 1\nAcknowledge \"tosser\" \"{id}:0\"\nEnd\n").as_bytes()
			)
			.is_err()
		);
	}
}
