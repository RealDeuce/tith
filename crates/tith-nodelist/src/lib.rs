//! TTS-5000 nodelist parsing and TTS-5001 flag handling.

#![forbid(unsafe_code)]

mod document;
mod flags;

pub use document::{
	AlternatePublicationName, Branch, Comment, Endpoint, EndpointPort, Entry, EntryInput, Keyword,
	Nodelist, NodelistError, NodelistErrorKind, NodelistReader, NodelistWriter, PublicationName,
	PublicationSource, REGISTERED_TITH_PORT, Record, SegmentContext, TithService,
	compress_zstd_frame, decompress_zstd_frame,
};

pub use flags::{
	EmailAddress, EmailFlag, EmailFlags, EmailMethod, EndpointSpec, ExtensionFlag, FileRequestFlag,
	HalfHour, InternetFlag, InternetFlags, InternetProtocol, MailPeriod, OnlinePeriod, OtherFlag,
	OtherFlags, PstnIsdnFlag, PstnIsdnFlags, ResolvedEmailMethod, ResolvedInternetEndpoint,
	ResolvedInternetService, ServerAddress, SystemFlag, SystemFlags,
};
#[cfg(test)]
mod tests {
	use super::*;
	use base64::Engine as _;
	use base64::engine::general_purpose::STANDARD_NO_PAD;
	use tith_crypto::PublicKey;
	use tith_wire::address::Address;
	use tith_wire::bundle::KeyResolver;

	use crate::document::{parse_node_number, validate_phone};

	fn line(keyword: &str, number: u16, internet: &str) -> String {
		let phone = if keyword.is_empty() { "1-1" } else { "" };
		format!("{keyword}\t{number}\tNode\tLocation\tSysop\t{phone}\tCM\t\t{internet}\t\t\n")
	}

	fn flagged_line(keyword: &str, number: u16, system: &str, other: &str) -> String {
		let phone = if keyword.is_empty() { "1-1" } else { "" };
		format!("{keyword}\t{number}\tNode\tLocation\tSysop\t{phone}\t{system}\t\t\t\t{other}\n")
	}

	#[test]
	fn parses_hierarchy_and_tith_key() {
		let key = STANDARD_NO_PAD.encode([9; 32]);
		let input = [
			line("Zone", 1, ""),
			line("Region", 10, ""),
			line("Host", 100, ""),
			line("Hub", 20, ""),
			line("", 21, &format!("IIH:mail.example:24554:{key}")),
		]
		.concat();
		let list = Nodelist::parse("fidonet", &input).unwrap();
		let address: Address = "fidonet#1:100/21".parse().unwrap();
		let entry = list.get(&address).unwrap();
		assert_eq!(
			entry.branch.hub.as_ref().unwrap().to_string(),
			"fidonet#1:100/20"
		);
		assert_eq!(
			entry.tith.as_ref().unwrap().endpoints[0].port,
			EndpointPort::Explicit(24_554)
		);
		assert_eq!(
			list.public_key(&address),
			Some(PublicKey::from_bytes([9; 32]))
		);
	}

	#[test]
	fn addresses_region_independent_nodes_in_the_regions_logical_net() {
		let input = [
			line("Zone", 1, ""),
			line("Region", 10, ""),
			line("", 21, ""),
		]
		.concat();
		let list = Nodelist::parse("fidonet", &input).unwrap();
		let address: Address = "fidonet#1:10/21".parse().unwrap();
		let entry = list
			.get(&address)
			.expect("Region Independent Node uses the Region's logical net");
		assert_eq!(entry.branch.region.as_ref().unwrap().net(), 10);
		assert!(list.get(&"fidonet#1/21".parse().unwrap()).is_none());
	}

	#[test]
	fn rejects_missing_newline_and_duplicate_address() {
		assert!(matches!(
			Nodelist::parse("fidonet", "Zone\t1\tx\tx\tx\t\t\t\t\t\t"),
			Err(NodelistError {
				kind: NodelistErrorKind::MissingFinalLineFeed,
				..
			})
		));
		let input = [line("Zone", 1, ""), line("", 2, ""), line("", 2, "")].concat();
		assert!(matches!(
			Nodelist::parse("fidonet", &input),
			Err(NodelistError {
				kind: NodelistErrorKind::DuplicateAddress,
				..
			})
		));
	}

	#[test]
	fn node_numbers_use_the_canonical_decimal_spelling() {
		for value in ["1", "9", "10", "32767"] {
			assert!(parse_node_number(value).is_some(), "{value}");
		}
		for value in ["", "-1", "0", "00", "01", "+1", " 1", "1 ", "32768", "１"] {
			assert!(parse_node_number(value).is_none(), "{value}");
		}
	}

	#[test]
	fn phone_numbers_have_the_documented_grammar_and_bound() {
		let longest = format!("1-{}", "2".repeat(27));
		let too_long = format!("1-{}", "2".repeat(28));
		for value in ["", "1-1", "1-800-555-0100", &longest] {
			assert!(validate_phone(value), "{value}");
		}
		for value in ["1", "-1", "1-", "1--2", "1 2", "1-٢", &too_long] {
			assert!(!validate_phone(value), "{value}");
		}
	}

	#[test]
	fn parses_ordered_iih_endpoints_and_inherits_ina() {
		let key = STANDARD_NO_PAD.encode([10; 32]);
		let internet =
			format!("INA:default.example,IIH::1234:{key},IIH:[2001:db8::1]:5678:{key},IIH:{key}");
		let input = [line("Zone", 1, ""), line("", 2, &internet)].concat();
		let list = Nodelist::parse("fidonet", &input).unwrap();
		let address: Address = "fidonet#1/2".parse().unwrap();
		let service = list.get(&address).unwrap().tith.as_ref().unwrap();
		assert_eq!(
			service.endpoints,
			vec![
				Endpoint {
					server: Some("default.example".to_owned()),
					port: EndpointPort::Explicit(1234),
				},
				Endpoint {
					server: Some("[2001:db8::1]".to_owned()),
					port: EndpointPort::Explicit(5678),
				},
				Endpoint {
					server: Some("default.example".to_owned()),
					port: EndpointPort::RegisteredDefault,
				},
			]
		);
		assert!(service.endpoints[0].is_usable());
		assert!(!service.endpoints[2].is_usable());
	}

	#[test]
	fn expands_each_default_server_without_losing_preference_order() {
		let key = STANDARD_NO_PAD.encode([15; 32]);
		let internet = format!("INA:first.example,INA:second.example,IIH::24555:{key}");
		let input = [line("Zone", 1, ""), line("", 2, &internet)].concat();
		let list = Nodelist::parse("fidonet", &input).unwrap();
		let service = list
			.get(&"fidonet#1/2".parse().unwrap())
			.unwrap()
			.tith
			.as_ref()
			.unwrap();
		assert_eq!(
			service.endpoints,
			[
				Endpoint {
					server: Some("first.example".to_owned()),
					port: EndpointPort::Explicit(24_555),
				},
				Endpoint {
					server: Some("second.example".to_owned()),
					port: EndpointPort::Explicit(24_555),
				},
			]
		);
	}

	#[test]
	fn enforces_nodelist_specific_flag_relationships() {
		for system in ["CM,ICM", "CM,#02", "CM,TAB", "XA,XB"] {
			let input = [
				flagged_line("Zone", 1, "", ""),
				flagged_line("", 2, system, ""),
			]
			.concat();
			assert!(
				matches!(
					Nodelist::parse("fidonet", &input),
					Err(NodelistError {
						kind: NodelistErrorKind::InvalidFlag,
						..
					})
				),
				"{system}"
			);
		}
	}

	#[test]
	fn enforces_coordinator_scope_and_cardinality() {
		let duplicate_zec = [
			flagged_line("Zone", 1, "", "ZEC"),
			flagged_line("", 2, "", "ZEC"),
		]
		.concat();
		assert!(Nodelist::parse("fidonet", &duplicate_zec).is_err());

		let rec_outside_region = flagged_line("Zone", 1, "", "REC");
		assert!(Nodelist::parse("fidonet", &rec_outside_region).is_err());

		let nc_on_host = [
			flagged_line("Zone", 1, "", ""),
			flagged_line("Host", 10, "", "NC"),
		]
		.concat();
		assert!(Nodelist::parse("fidonet", &nc_on_host).is_err());

		let valid = [
			flagged_line("Zone", 1, "", "ZEC"),
			flagged_line("Region", 2, "", "REC,RPK"),
			flagged_line("Host", 10, "", "NEC,NPK"),
			flagged_line("", 20, "", "NC"),
		]
		.concat();
		assert!(Nodelist::parse("fidonet", &valid).is_ok());
	}

	#[test]
	fn rejects_a_private_entry_which_publishes_contact_information() {
		let key = STANDARD_NO_PAD.encode([13; 32]);
		let prefix = [line("Zone", 1, ""), line("Host", 10, "")].concat();
		for field_9 in [
			"IBN:example.org:24554",
			&format!("IIH:example.org:24555:{key}"),
		] {
			let input = format!("{prefix}Pvt\t20\tNode\tLocation\tSysop\t\tCM\t\t{field_9}\t\t\n");
			assert!(
				matches!(
					Nodelist::parse("fidonet", &input),
					Err(NodelistError {
						kind: NodelistErrorKind::PrivateContact,
						line: 3,
					})
				),
				"field 9 {field_9}"
			);
		}

		// Field 10 and the phone number are the same rule.
		let with_email =
			format!("{prefix}Pvt\t20\tNode\tLocation\tSysop\t\t\t\t\tIEM:sysop@example.org\t\n");
		let with_phone =
			format!("{prefix}Pvt\t20\tNode\tLocation\tSysop\t1-616-555-0100\t\t\t\t\t\n");
		for input in [with_email, with_phone] {
			assert!(matches!(
				Nodelist::parse("fidonet", &input),
				Err(NodelistError {
					kind: NodelistErrorKind::PrivateContact,
					..
				})
			));
		}
	}

	#[test]
	fn accepts_a_private_entry_carrying_only_an_endpointless_iih_key() {
		// TTS-5000 section 5.2 field 1 excepts this form, so a Private node is
		// still authenticated from its own nodelist key.
		let key = STANDARD_NO_PAD.encode([14; 32]);
		let input = [
			line("Zone", 1, ""),
			line("Host", 10, ""),
			format!("Pvt\t20\tNode\tLocation\tSysop\t\tCM\t\tIIH:{key},IBN\t\t\n"),
		]
		.concat();
		let list = Nodelist::parse("fidonet", &input).unwrap();
		let address: Address = "fidonet#1:10/20".parse().unwrap();
		let entry = list.get(&address).unwrap();
		assert_eq!(entry.keyword, Keyword::Private);
		assert_eq!(
			list.public_key(&address),
			Some(PublicKey::from_bytes([14; 32]))
		);
		// The key is published, but it supplies no endpoint to contact.
		let service = entry.tith.as_ref().unwrap();
		assert!(!service.endpoints[0].is_usable());
	}

	#[test]
	fn rejects_unbracketed_ipv6_and_different_iih_keys() {
		let first_key = STANDARD_NO_PAD.encode([11; 32]);
		let second_key = STANDARD_NO_PAD.encode([12; 32]);
		let invalid_ipv6 = [
			line("Zone", 1, ""),
			line("", 2, &format!("IIH:2001:db8::1:1234:{first_key}")),
		]
		.concat();
		assert!(matches!(
			Nodelist::parse("fidonet", &invalid_ipv6),
			Err(NodelistError {
				kind: NodelistErrorKind::InvalidEndpoint,
				..
			})
		));

		let different_keys = [
			line("Zone", 1, ""),
			line(
				"",
				2,
				&format!("IIH:a.example:1234:{first_key},IIH:b.example:1234:{second_key}"),
			),
		]
		.concat();
		assert!(matches!(
			Nodelist::parse("fidonet", &different_keys),
			Err(NodelistError {
				kind: NodelistErrorKind::InvalidPublicKey,
				..
			})
		));
	}
}
