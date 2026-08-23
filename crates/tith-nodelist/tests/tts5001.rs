use std::str::FromStr as _;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use tith_crypto::PublicKey;
use tith_nodelist::{
	EmailAddress, EmailFlag, EmailFlags, EmailMethod, EndpointSpec, ExtensionFlag, FileRequestFlag,
	HalfHour, InternetFlag, InternetFlags, InternetProtocol, MailPeriod, OnlinePeriod, OtherFlag,
	OtherFlags, PstnIsdnFlag, PstnIsdnFlags, ServerAddress, SystemFlag, SystemFlags,
};

fn key(byte: u8) -> String {
	STANDARD_NO_PAD.encode([byte; 32])
}

#[test]
fn validated_components_cannot_spell_invalid_flags() {
	let server = ServerAddress::from_str("mail.example").unwrap();
	assert_eq!(server.as_str(), "mail.example");
	assert_eq!(server.to_string(), "mail.example");
	assert!(ServerAddress::from_str("MAIL.example").is_err());

	let email = EmailAddress::from_str("雪@example").unwrap();
	assert_eq!(email.as_str(), "雪@example");
	assert_eq!(email.to_string(), "雪@example");
	assert!(EmailAddress::from_str("").is_err());

	let inherited = EndpointSpec::new(None, None).unwrap();
	assert_eq!(inherited.to_string(), "");
	assert!(inherited.server().is_none());
	assert_eq!(inherited.port(), None);
	let server_only = EndpointSpec::new(Some(server.clone()), None).unwrap();
	assert_eq!(server_only.to_string(), "mail.example");
	let port_only = EndpointSpec::new(None, Some(24_555)).unwrap();
	assert_eq!(port_only.to_string(), ":24555");
	let complete = EndpointSpec::new(Some(server), Some(24_555)).unwrap();
	assert_eq!(complete.to_string(), "mail.example:24555");
	assert!(EndpointSpec::new(None, Some(0)).is_err());

	let mail = MailPeriod::new(true, 23).unwrap();
	assert!(mail.bell_212a());
	assert_eq!(mail.hour(), 23);
	assert!(MailPeriod::new(false, 24).is_err());
	let start = HalfHour::new(0).unwrap();
	let end = HalfHour::new(47).unwrap();
	assert_eq!(start.index(), 0);
	assert_eq!(end.minutes_after_midnight(), 1410);
	assert!(HalfHour::new(48).is_err());
	let online = OnlinePeriod::new(start, end);
	assert_eq!(online.start(), start);
	assert_eq!(online.end(), end);

	let extension = ExtensionFlag::from_str("V32B").unwrap();
	assert_eq!(extension.as_str(), "V32B");
	assert_eq!(extension.to_string(), "V32B");
	assert!(ExtensionFlag::from_str("V32b").is_err());
	assert!(ExtensionFlag::from_str("bad-flag").is_err());
}

#[test]
fn file_request_flags_expose_the_exact_capability_table() {
	let cases = [
		(FileRequestFlag::Xa, [true, true, true, true]),
		(FileRequestFlag::Xb, [true, true, true, false]),
		(FileRequestFlag::Xc, [true, false, true, true]),
		(FileRequestFlag::Xp, [true, true, false, false]),
		(FileRequestFlag::Xr, [true, false, true, false]),
		(FileRequestFlag::Xw, [false, false, true, false]),
		(FileRequestFlag::Xx, [false, false, true, true]),
	];
	for (flag, expected) in cases {
		assert_eq!(
			[
				flag.supports_bark_file(),
				flag.supports_bark_update(),
				flag.supports_wazoo_file(),
				flag.supports_wazoo_update(),
			],
			expected
		);
	}
}

#[test]
fn standalone_lists_parse_format_iterate_and_validate_construction() {
	let system: SystemFlags = "CM,LO,MN,ICM,XA,#02,!09,TAB,TuB".parse().unwrap();
	assert_eq!(system.to_string(), "CM,LO,MN,ICM,XA,#02,!09,TAB,TuB");
	assert_eq!(system.as_ref().len(), 9);
	assert_eq!(system.clone().into_vec().len(), 9);
	assert_eq!((&system).into_iter().count(), 9);
	assert_eq!(SystemFlags::default().to_string(), "");

	let pstn_text = "V22,V29,V32,V32b,V34,V90C,V90S,V32T,VFC,HST,H14,H16,X2C,X2S,ZYX,Z19,H96,PEP,CSP,MNP,V42,V42b,V110L,V110H,V120L,V120H,X75,ISDN";
	let pstn: PstnIsdnFlags = pstn_text.parse().unwrap();
	assert_eq!(pstn.to_string(), pstn_text);
	assert_eq!(pstn.clone().into_vec().len(), 28);

	let email: EmailFlags = "IEM:a@example,IEM:b@example,ITX,IUC:u@example,IMI,ISE,EVY,EMA"
		.parse()
		.unwrap();
	assert_eq!(
		email.to_string(),
		"IEM:a@example,IEM:b@example,ITX,IUC:u@example,IMI,ISE,EVY,EMA"
	);
	assert_eq!(email.clone().into_vec().len(), 8);

	let other: OtherFlags =
		"MO,GUUCP,PING,ZEC,REC,NEC,NC,SDS,SMH,RPK,NPK,ENC,CDP,TRACE,U,V32B,V42B"
			.parse()
			.unwrap();
	assert_eq!(other.clone().into_vec().len(), 17);
	assert_eq!(
		other.to_string(),
		"MO,GUUCP,PING,ZEC,REC,NEC,NC,SDS,SMH,RPK,NPK,ENC,CDP,TRACE,U,V32B,V42B"
	);

	let constructed = SystemFlags::try_from(vec![SystemFlag::ContinuousMail]).unwrap();
	assert_eq!(constructed.to_string(), "CM");
	assert!(
		SystemFlags::try_from(vec![SystemFlag::ListedOnly, SystemFlag::ContinuousMail]).is_err()
	);
	assert!(PstnIsdnFlags::try_from(vec![PstnIsdnFlag::V29, PstnIsdnFlag::V22]).is_err());
	assert!(EmailFlags::try_from(vec![EmailFlag::Transx(None), EmailFlag::Default(None)]).is_err());
	assert!(OtherFlags::try_from(vec![OtherFlag::Ping, OtherFlag::MailOnly]).is_err());
}

#[test]
fn system_lists_cover_period_boundaries_and_rejections() {
	for hour in 0..=23 {
		let positive = format!("#{hour:02}");
		let negative = format!("!{hour:02}");
		assert_eq!(
			positive.parse::<SystemFlags>().unwrap().to_string(),
			positive
		);
		assert_eq!(
			negative.parse::<SystemFlags>().unwrap().to_string(),
			negative
		);
	}
	for start in b'A'..=b'X' {
		for end in *b"Ax" {
			let value = format!("T{}{}", char::from(start), char::from(end));
			assert_eq!(value.parse::<SystemFlags>().unwrap().to_string(), value);
		}
	}
	for start in b'a'..=b'x' {
		let value = format!("T{}A", char::from(start));
		assert_eq!(value.parse::<SystemFlags>().unwrap().to_string(), value);
	}
	for invalid in [
		",", "CM,", ",CM", "CM,,LO", "cm", "CM:x", "#0", "#000", "#24", "!99", "#02,!02",
		"!02,#02", "TAY", "TYA", "TAA,TAA", "TuB,TAB",
	] {
		assert!(invalid.parse::<SystemFlags>().is_err(), "{invalid}");
	}
}

#[test]
fn ipv6_has_one_exact_native_spelling() {
	for valid in [
		"INA:[::]",
		"INA:[::1]",
		"INA:[1::]",
		"INA:[2001:db8::1]",
		"INA:[1::2:0:0:3]",
		"INA:[1:2:3:4:5:6:7:8]",
		"INA:[::ffff:c000:201]",
	] {
		assert_eq!(valid.parse::<InternetFlags>().unwrap().to_string(), valid);
	}
	for invalid in [
		"INA:[0:0:0:0:0:0:0:0]",
		"INA:[0::1]",
		"INA:[1:0:0:2::3:4]",
		"INA:[2001:0db8::1]",
		"INA:[2001:DB8::1]",
		"INA:[::ffff:192.0.2.1]",
		"INA:2001:db8::1",
	] {
		assert!(invalid.parse::<InternetFlags>().is_err(), "{invalid}");
	}
}

#[test]
fn internet_resolution_covers_every_protocol_and_default_path() {
	let value = format!(
		"INA:a.example,INA:b.example,IIH:{key},IBN,IFC::60180,IFT:ftp.example,ITN:telnet.example:24,IVM,IP,INO4",
		key = key(7)
	);
	let flags: InternetFlags = value.parse().unwrap();
	assert!(flags.no_incoming_ipv4());
	let services = flags.resolved_services();
	assert_eq!(services.len(), 7);
	assert_eq!(services[0].protocol, InternetProtocol::Tith);
	assert_eq!(services[0].public_key, Some(PublicKey::from_bytes([7; 32])));
	assert_eq!(services[0].endpoints.len(), 2);
	assert_eq!(services[0].endpoints[0].port, None);
	assert!(!services[0].endpoints[0].is_usable());
	assert_eq!(services[1].protocol, InternetProtocol::Binkp);
	assert_eq!(services[1].endpoints[0].port, Some(24_554));
	assert!(services[1].endpoints[0].is_usable());
	assert_eq!(services[2].protocol, InternetProtocol::Ifcico);
	assert_eq!(services[2].endpoints[0].port, Some(60_180));
	assert_eq!(services[3].protocol, InternetProtocol::Ftp);
	assert_eq!(services[3].endpoints[0].port, Some(21));
	assert_eq!(services[4].protocol, InternetProtocol::Telnet);
	assert_eq!(services[4].endpoints[0].port, Some(24));
	assert_eq!(services[5].protocol, InternetProtocol::Vmodem);
	assert_eq!(services[5].endpoints[0].port, Some(3141));
	assert_eq!(services[6].protocol, InternetProtocol::Unspecified);
	assert_eq!(services[6].endpoints[0].port, None);

	let no_defaults: InternetFlags = "IBN::24555".parse().unwrap();
	let endpoint = &no_defaults.resolved_services()[0].endpoints[0];
	assert!(endpoint.server.is_none());
	assert_eq!(endpoint.port, Some(24_555));
	assert!(!endpoint.is_usable());
	assert!(!no_defaults.no_incoming_ipv4());

	for flag in [
		InternetFlag::DefaultServer("a.example".parse().unwrap()),
		InternetFlag::Tith {
			endpoint: EndpointSpec::new(None, None).unwrap(),
			public_key: PublicKey::from_bytes([1; 32]),
		},
		InternetFlag::Binkp(EndpointSpec::new(None, None).unwrap()),
		InternetFlag::Ifcico(EndpointSpec::new(None, None).unwrap()),
		InternetFlag::Ftp(EndpointSpec::new(None, None).unwrap()),
		InternetFlag::Telnet(EndpointSpec::new(None, None).unwrap()),
		InternetFlag::Vmodem(EndpointSpec::new(None, None).unwrap()),
		InternetFlag::Unspecified(EndpointSpec::new(None, None).unwrap()),
		InternetFlag::NoIncomingIpv4,
	] {
		let _ = flag.registered_default_port();
	}
}

#[test]
fn internet_grammar_and_public_keys_are_canonical() {
	let encoded_key = key(9);
	for valid in [
		"IBN".to_owned(),
		"IBN:24555".to_owned(),
		"IBN::1".to_owned(),
		"IBN::65535".to_owned(),
		"IBN:192.0.2.1:24555".to_owned(),
		format!("IIH:{encoded_key}"),
		format!("IIH:mail.example:{encoded_key}"),
		format!("IIH::24555:{encoded_key}"),
		format!("IIH:[2001:db8::1]:24555:{encoded_key}"),
	] {
		assert_eq!(valid.parse::<InternetFlags>().unwrap().to_string(), valid);
	}
	let other_key = key(10);
	for invalid in [
		"INA:".to_owned(),
		"INA:a..example".to_owned(),
		"INA:-a.example".to_owned(),
		"INA:a-.example".to_owned(),
		"INA:A.example".to_owned(),
		"IBN:".to_owned(),
		"IBN::0".to_owned(),
		"IBN::01".to_owned(),
		"IBN::65536".to_owned(),
		"IBN:+1".to_owned(),
		"IBNx".to_owned(),
		"INO4:x".to_owned(),
		"IP,IP".to_owned(),
		"IBN,INA:a.example".to_owned(),
		"IIH:key".to_owned(),
		format!("IIH:{encoded_key}="),
		format!("IIH:a.example:1:{encoded_key},IIH:b.example:1:{other_key}"),
	] {
		assert!(invalid.parse::<InternetFlags>().is_err(), "{invalid}");
	}
	let mut noncanonical_pad = encoded_key;
	noncanonical_pad.replace_range(42..43, "p");
	assert!(
		format!("IIH:{noncanonical_pad}")
			.parse::<InternetFlags>()
			.is_err()
	);
}

#[test]
fn email_defaults_expand_in_preference_order() {
	let flags: EmailFlags = "IEM:a@example,IEM:b@example,IEM,ITX,IUC:u@example,IMI,ISE,EVY,EMA"
		.parse()
		.unwrap();
	let methods = flags.resolved_methods();
	assert_eq!(methods[0].method, EmailMethod::Unspecified);
	assert!(methods[0].address.is_none());
	assert_eq!(methods[1].method, EmailMethod::Transx);
	assert_eq!(methods[1].address.as_ref().unwrap().as_str(), "a@example");
	assert_eq!(methods[2].address.as_ref().unwrap().as_str(), "b@example");
	assert_eq!(methods[3].method, EmailMethod::Uuencode);
	assert_eq!(methods[3].address.as_ref().unwrap().as_str(), "u@example");
	assert_eq!(methods[4].method, EmailMethod::Mime);
	assert_eq!(methods[6].method, EmailMethod::Seat);
	assert_eq!(methods[8].method, EmailMethod::Voyager);
	assert_eq!(methods[10].method, EmailMethod::Other);

	let no_default: EmailFlags = "ITX".parse().unwrap();
	assert_eq!(
		no_default.resolved_methods(),
		[tith_nodelist::ResolvedEmailMethod {
			method: EmailMethod::Transx,
			address: None,
		}]
	);
	for invalid in [
		"IEM:",
		"IEM:a@example,IEM:a@example",
		"ITX,IEM:a@example",
		"ITX,ITX",
		"ITX:",
		"ITX:a,b",
		"ITX:\u{7f}",
		"ITX:\u{1f}",
		"itx",
	] {
		assert!(invalid.parse::<EmailFlags>().is_err(), "{invalid:?}");
	}
	assert!("ITX:\u{80}".parse::<EmailFlags>().is_ok());
}

#[test]
fn other_extensions_reserve_only_exact_assigned_names() {
	let longest = "A".repeat(32);
	for valid in ["U", "TRACE", "V32B", "V42B", "a9", &longest] {
		let parsed: OtherFlags = valid.parse().unwrap();
		assert_eq!(parsed.to_string(), valid);
	}
	for invalid in [
		"",
		"A,A",
		"B,A",
		"TRACE,MO",
		"CM",
		"V32b",
		"INA",
		"IEM",
		"TAB",
		"A-B",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567",
	] {
		if invalid.is_empty() {
			assert_eq!(invalid.parse::<OtherFlags>().unwrap().to_string(), "");
		} else {
			assert!(invalid.parse::<OtherFlags>().is_err(), "{invalid}");
		}
	}
}
