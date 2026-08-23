use std::io::{self, BufRead, BufReader, Cursor, Read, Write};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use tith_crypto::PublicKey;
use tith_nodelist::{
	AlternatePublicationName, Comment, EmailFlags, EntryInput, InternetFlags, Keyword, Nodelist,
	NodelistErrorKind, NodelistReader, NodelistWriter, OtherFlags, PstnIsdnFlags, PublicationName,
	PublicationSource, Record, SegmentContext, SystemFlags, compress_zstd_frame,
	decompress_zstd_frame,
};

// `zstd` 1.5.2 command-line output for `hello\n`, with its content checksum.
const CLI_FRAME: &[u8] = &[
	0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58, 0x31, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x0a, 0x53,
	0x88, 0xbd, 0x91,
];

fn line(keyword: &str, number: u16, phone: &str, internet: &str, email: &str) -> String {
	format!("{keyword}\t{number}\tNode\tLocation\tSysop\t{phone}\t\t\t{internet}\t{email}\t\n")
}

fn prefix() -> String {
	[line("Zone", 1, "", "", ""), line("Host", 10, "", "", "")].concat()
}

fn flagged_line(keyword: &str, number: u16, system: &str, other: &str) -> String {
	let phone = if keyword.is_empty() { "1-1" } else { "" };
	format!("{keyword}\t{number}\tNode\tLocation\tSysop\t{phone}\t{system}\t\t\t\t{other}\n")
}

fn input(keyword: Keyword, number: u16) -> EntryInput {
	EntryInput {
		keyword,
		number,
		node_name: "Node".to_owned(),
		location: "Location".to_owned(),
		sysop_name: "Sysop".to_owned(),
		phone: String::new(),
		system_flags: SystemFlags::default(),
		pstn_isdn_flags: PstnIsdnFlags::default(),
		internet_flags: InternetFlags::default(),
		email_flags: EmailFlags::default(),
		other_flags: OtherFlags::default(),
	}
}

#[test]
fn streaming_records_define_utf8_controls_and_comment_interests() {
	let text = concat!(
		";SUx free Ελληνικά\n",
		";A assigned\n",
		";9literal\n",
		";étext\n",
		"Zone\t1\tNode\tPlace\tSysop\t\t\t\t\t\t\n"
	);
	let records = NodelistReader::distribution("fidonet", Cursor::new(text))
		.unwrap()
		.collect::<Result<Vec<_>, _>>()
		.unwrap();
	assert_eq!(
		records[0],
		Record::Comment(Comment {
			interests: "SUx".to_owned(),
			text: " free Ελληνικά".to_owned(),
		})
	);
	assert_eq!(
		records[1],
		Record::Comment(Comment {
			interests: "A".to_owned(),
			text: " assigned".to_owned(),
		})
	);
	assert_eq!(
		records[2],
		Record::Comment(Comment {
			interests: String::new(),
			text: "9literal".to_owned(),
		})
	);
	assert_eq!(
		records[3],
		Record::Comment(Comment {
			interests: String::new(),
			text: "étext".to_owned(),
		})
	);
	assert!(matches!(records[4], Record::Entry(_)));

	for bytes in [
		b";comment\ttext\n".as_slice(),
		b";comment\x7f\n",
		b";comment\xc2\x80\n",
		b";comment\xc2\x9f\n",
		b";comment\r\n",
	] {
		let error = NodelistReader::distribution("fidonet", Cursor::new(bytes))
			.unwrap()
			.next()
			.unwrap()
			.unwrap_err();
		assert!(matches!(error.kind, NodelistErrorKind::ControlCharacter));
	}
	let invalid_utf8 = b";\xff\n";
	let mut stopped = NodelistReader::distribution("fidonet", Cursor::new(invalid_utf8)).unwrap();
	let error = stopped.next().unwrap().unwrap_err();
	assert!(matches!(error.kind, NodelistErrorKind::InvalidUtf8));
	assert!(stopped.next().is_none());
	let error = NodelistReader::distribution("fidonet", Cursor::new(b";unfinished"))
		.unwrap()
		.next()
		.unwrap()
		.unwrap_err();
	assert!(matches!(
		error.kind,
		NodelistErrorKind::MissingFinalLineFeed
	));

	for character in ['\0', '\u{1f}', '\u{7f}', '\u{80}', '\u{9f}'] {
		let text = format!(";text{character}\n");
		let error = NodelistReader::distribution("fidonet", Cursor::new(text))
			.unwrap()
			.next()
			.unwrap()
			.unwrap_err();
		assert!(matches!(error.kind, NodelistErrorKind::ControlCharacter));
	}
	for character in [' ', '~', '\u{a0}'] {
		let text = format!(";text{character}\n");
		assert!(
			NodelistReader::distribution("fidonet", Cursor::new(text))
				.unwrap()
				.next()
				.unwrap()
				.is_ok()
		);
	}
	for keyword in ["Point", "point", "Private", "Boss"] {
		let text = line(keyword, 1, "", "", "");
		let error = NodelistReader::distribution("fidonet", Cursor::new(text))
			.unwrap()
			.next()
			.unwrap()
			.unwrap_err();
		assert!(matches!(error.kind, NodelistErrorKind::InvalidKeyword));
	}
}

#[test]
fn hierarchy_and_segment_initial_context_are_exact() {
	let complete = [
		line("Zone", 1, "", "", ""),
		line("", 2, "1-1", "", ""),
		line("Region", 20, "", "", ""),
		line("", 3, "1-1", "", ""),
		line("Host", 10, "", "", ""),
		line("Hub", 4, "", "", ""),
		line("", 5, "1-1", "", ""),
		line("Host", 11, "", "", ""),
		line("", 6, "1-1", "", ""),
		line("Region", 21, "", "", ""),
		line("Host", 12, "", "", ""),
	]
	.concat();
	assert_eq!(Nodelist::parse("fidonet", &complete).unwrap().len(), 11);

	for bad in [
		line("Host", 10, "", "", ""),
		[line("Zone", 1, "", "", ""), line("Hub", 2, "", "", "")].concat(),
		[
			line("Zone", 1, "", "", ""),
			line("Region", 10, "", "", ""),
			line("Hub", 2, "", "", ""),
		]
		.concat(),
	] {
		assert!(matches!(
			Nodelist::parse("fidonet", &bad),
			Err(error) if matches!(error.kind, NodelistErrorKind::InvalidHierarchy)
		));
	}

	let region = line("Region", 20, "", "", "");
	let context = SegmentContext::within_zone("fidonet", 1).unwrap();
	assert!(
		NodelistReader::segment(context, Cursor::new(region))
			.unwrap()
			.next()
			.unwrap()
			.is_ok()
	);
	let hub = line("Hub", 2, "", "", "");
	let context = SegmentContext::within_local_net("fidonet", 1, 10).unwrap();
	let Record::Entry(hub) = NodelistReader::segment(context, Cursor::new(hub))
		.unwrap()
		.next()
		.unwrap()
		.unwrap()
	else {
		panic!("expected Hub entry");
	};
	assert_eq!(hub.address.to_string(), "fidonet#1:10/2");

	let transitions = [
		line("Zone", 1, "", "", ""),
		line("", 2, "1-1", "", ""),
		line("Region", 10, "", "", ""),
		line("", 2, "1-1", "", ""),
		line("Host", 20, "", "", ""),
		line("", 2, "1-1", "", ""),
		line("Hub", 3, "", "", ""),
		line("", 4, "1-1", "", ""),
		line("Hub", 5, "", "", ""),
		line("Hold", 6, "", "", ""),
		line("Host", 21, "", "", ""),
		line("Down", 7, "", "", ""),
		line("Region", 11, "", "", ""),
		line("Host", 22, "", "", ""),
		line("Zone", 2, "", "", ""),
		line("Host", 30, "", "", ""),
	]
	.concat();
	assert_eq!(Nodelist::parse("fidonet", &transitions).unwrap().len(), 16);

	let duplicate_namespace = [
		line("Zone", 1, "", "", ""),
		line("Region", 10, "", "", ""),
		line("Host", 10, "", "", ""),
	]
	.concat();
	assert!(matches!(
		Nodelist::parse("fidonet", &duplicate_namespace),
		Err(error) if matches!(error.kind, NodelistErrorKind::DuplicateAddress)
	));
	let duplicate_hub_member = [
		line("Zone", 1, "", "", ""),
		line("Host", 10, "", "", ""),
		line("Hub", 2, "", "", ""),
		line("", 2, "1-1", "", ""),
	]
	.concat();
	assert!(matches!(
		Nodelist::parse("fidonet", &duplicate_hub_member),
		Err(error) if matches!(error.kind, NodelistErrorKind::DuplicateAddress)
	));

	let zone_context = SegmentContext::zone("fidonet").unwrap();
	let within_zone = SegmentContext::within_zone("fidonet", 1).unwrap();
	let within_net = SegmentContext::within_local_net("fidonet", 1, 10).unwrap();
	for (context, accepted, rejected) in [
		(
			zone_context,
			vec!["Zone"],
			vec!["Region", "Host", "Hub", ""],
		),
		(within_zone, vec!["Region", "Host"], vec!["Zone", "Hub", ""]),
		(within_net, vec!["Hub"], vec!["Zone", "Region", "Host", ""]),
	] {
		for keyword in accepted {
			let text = line(keyword, 20, "", "", "");
			assert!(
				NodelistReader::segment(context.clone(), Cursor::new(text))
					.unwrap()
					.collect::<Result<Vec<_>, _>>()
					.is_ok(),
				"{keyword}"
			);
		}
		for keyword in rejected {
			let text = line(keyword, 20, "1-1", "", "");
			assert!(
				NodelistReader::segment(context.clone(), Cursor::new(text))
					.unwrap()
					.collect::<Result<Vec<_>, _>>()
					.is_err(),
				"{keyword}"
			);
		}
		assert!(
			NodelistReader::segment(context.clone(), Cursor::new(""))
				.unwrap()
				.collect::<Result<Vec<_>, _>>()
				.is_err()
		);
		assert!(
			NodelistReader::segment(context, Cursor::new(";A comment only\n"))
				.unwrap()
				.collect::<Result<Vec<_>, _>>()
				.is_err()
		);
	}
	for context in [
		SegmentContext::within_zone("fidonet", 0),
		SegmentContext::within_zone("p2p", 1),
		SegmentContext::within_local_net("fidonet", 1, 0),
	] {
		assert!(context.is_err());
	}
}

#[test]
fn coordinator_assertions_use_their_exact_scopes() {
	let valid = [
		flagged_line("Zone", 1, "", "ZEC"),
		flagged_line("Region", 10, "", "REC,RPK"),
		flagged_line("Host", 20, "", "NEC,NPK"),
		flagged_line("", 2, "", "NC"),
		flagged_line("Region", 11, "", "REC,RPK"),
		flagged_line("Host", 21, "", "NEC,NPK"),
		flagged_line("", 2, "", "NC"),
		flagged_line("Zone", 2, "", "ZEC"),
		flagged_line("Region", 10, "", "REC,NEC,RPK,NPK"),
		flagged_line("Host", 20, "", "NEC,NPK"),
		flagged_line("", 2, "", "NC"),
	]
	.concat();
	assert!(Nodelist::parse("fidonet", &valid).is_ok());

	for text in [
		[
			flagged_line("Zone", 1, "", "ZEC"),
			flagged_line("", 2, "", "ZEC"),
		]
		.concat(),
		flagged_line("Zone", 1, "", "REC"),
		flagged_line("Zone", 1, "", "RPK"),
		[
			flagged_line("Zone", 1, "", ""),
			flagged_line("Region", 10, "", "REC,RPK"),
			flagged_line("Host", 20, "", "REC"),
		]
		.concat(),
		[
			flagged_line("Zone", 1, "", ""),
			flagged_line("Host", 20, "", "NEC,NPK"),
			flagged_line("", 2, "", "NEC"),
		]
		.concat(),
		[
			flagged_line("Zone", 1, "", ""),
			flagged_line("Host", 20, "", ""),
			flagged_line("", 2, "", "NC"),
			flagged_line("Hold", 3, "", "NC"),
		]
		.concat(),
		[
			flagged_line("Zone", 1, "", ""),
			flagged_line("", 2, "", "NC"),
		]
		.concat(),
		[
			flagged_line("Zone", 1, "", ""),
			flagged_line("Region", 10, "", ""),
			flagged_line("", 2, "", "NC"),
		]
		.concat(),
		[
			flagged_line("Zone", 1, "", ""),
			flagged_line("Host", 20, "", "NC"),
		]
		.concat(),
		[
			flagged_line("Zone", 1, "", ""),
			flagged_line("Host", 20, "", ""),
			flagged_line("Hub", 2, "", "NC"),
		]
		.concat(),
	] {
		assert!(matches!(
			Nodelist::parse("fidonet", &text),
			Err(error) if matches!(error.kind, NodelistErrorKind::InvalidFlag)
		));
	}
}

#[test]
fn pvt_is_exactly_the_absence_of_a_usable_contact_target() {
	let key = STANDARD_NO_PAD.encode([7; 32]);
	for (internet, email) in [
		("INA:host.example", ""),
		("IBN::24555", ""),
		("IP:host.example", ""),
		(&format!("IIH:{key}"), ""),
		("", "ITX"),
	] {
		let text = format!("{}{}", prefix(), line("Pvt", 20, "", internet, email));
		assert!(
			Nodelist::parse("fidonet", &text).is_ok(),
			"{internet} {email}"
		);
	}

	for (phone, internet, email) in [
		("1-1", "", ""),
		("", "IBN:host.example", ""),
		("", "INA:host.example,IBN", ""),
		("", "", "IEM:sysop@example.org"),
		("", "", "IEM:sysop@example.org,ITX"),
	] {
		let text = format!("{}{}", prefix(), line("Pvt", 20, phone, internet, email));
		assert!(matches!(
			Nodelist::parse("fidonet", &text),
			Err(error) if matches!(error.kind, NodelistErrorKind::PrivateContact)
		));
	}

	for (phone, internet, email) in [
		("", "", ""),
		("", "INA:host.example", ""),
		("", "IBN::24555", ""),
		("", "", "ITX"),
	] {
		let text = format!("{}{}", prefix(), line("", 20, phone, internet, email));
		assert!(matches!(
			Nodelist::parse("fidonet", &text),
			Err(error) if matches!(error.kind, NodelistErrorKind::PrivateContact)
		));
	}
	assert!(
		Nodelist::parse(
			"fidonet",
			&format!("{}{}", prefix(), line("", 20, "", "IBN:host.example", ""))
		)
		.is_ok()
	);
}

#[test]
fn writer_round_trips_records_and_checks_application_keys() {
	let key = PublicKey::from_bytes([9; 32]);
	let key_text = STANDARD_NO_PAD.encode(key.as_bytes());
	let mut writer = NodelistWriter::distribution("fidonet", Vec::new()).unwrap();
	writer
		.write_comment(&Comment {
			interests: "Sx".to_owned(),
			text: " notice".to_owned(),
		})
		.unwrap();
	writer
		.write_entry(&input(Keyword::Zone, 1), PublicationSource::Ordinary)
		.unwrap();
	writer
		.write_entry(&input(Keyword::Host, 10), PublicationSource::Ordinary)
		.unwrap();
	let mut member = input(Keyword::Normal, 20);
	member.internet_flags = format!("IIH:node.example:24555:{key_text}")
		.parse()
		.unwrap();
	writer
		.write_entry(
			&member,
			PublicationSource::FirstPublicationFromAnonymousApplication(key),
		)
		.unwrap();
	let bytes = writer.finish().unwrap();
	let text = String::from_utf8(bytes).unwrap();
	let parsed = Nodelist::parse("fidonet", &text).unwrap();
	assert_eq!(parsed.len(), 3);

	let mut wrong = NodelistWriter::distribution("fidonet", Vec::new()).unwrap();
	wrong
		.write_entry(&input(Keyword::Zone, 1), PublicationSource::Ordinary)
		.unwrap();
	wrong
		.write_entry(&input(Keyword::Host, 10), PublicationSource::Ordinary)
		.unwrap();
	let error = wrong
		.write_entry(
			&member,
			PublicationSource::FirstPublicationFromAnonymousApplication(PublicKey::from_bytes(
				[8; 32],
			)),
		)
		.unwrap_err();
	assert!(matches!(
		error.kind,
		NodelistErrorKind::ApplicationKeyMismatch
	));

	let mut comments = NodelistWriter::distribution("fidonet", Vec::new()).unwrap();
	let error = comments
		.write_comment(&Comment {
			interests: "S1".to_owned(),
			text: " text".to_owned(),
		})
		.unwrap_err();
	assert!(matches!(error.kind, NodelistErrorKind::InvalidComment));
	let error = comments
		.write_comment(&Comment {
			interests: "S".to_owned(),
			text: "notice".to_owned(),
		})
		.unwrap_err();
	assert!(matches!(error.kind, NodelistErrorKind::InvalidComment));
	let error = comments
		.write_comment(&Comment {
			interests: "S".to_owned(),
			text: "\tcontrol".to_owned(),
		})
		.unwrap_err();
	assert!(matches!(error.kind, NodelistErrorKind::ControlCharacter));

	let empty_segment = NodelistWriter::segment(
		SegmentContext::within_local_net("fidonet", 1, 10).unwrap(),
		Vec::new(),
	)
	.unwrap();
	assert!(matches!(
		empty_segment.finish(),
		Err(error) if matches!(error.kind, NodelistErrorKind::InvalidHierarchy)
	));
	let mut segment = NodelistWriter::segment(
		SegmentContext::within_local_net("fidonet", 1, 10).unwrap(),
		Vec::new(),
	)
	.unwrap();
	segment
		.write_entry(&input(Keyword::Hub, 2), PublicationSource::Ordinary)
		.unwrap();
	assert!(!segment.finish().unwrap().is_empty());

	let mut every_keyword = NodelistWriter::distribution("other", Vec::new()).unwrap();
	every_keyword
		.write_entry(&input(Keyword::Zone, 1), PublicationSource::Ordinary)
		.unwrap();
	every_keyword
		.write_entry(&input(Keyword::Region, 2), PublicationSource::Ordinary)
		.unwrap();
	every_keyword
		.write_entry(&input(Keyword::Host, 10), PublicationSource::Ordinary)
		.unwrap();
	every_keyword
		.write_entry(&input(Keyword::Private, 2), PublicationSource::Ordinary)
		.unwrap();
	every_keyword
		.write_entry(&input(Keyword::Hold, 3), PublicationSource::Ordinary)
		.unwrap();
	every_keyword
		.write_entry(&input(Keyword::Down, 4), PublicationSource::Ordinary)
		.unwrap();
	let text = String::from_utf8(every_keyword.finish().unwrap()).unwrap();
	assert!(Nodelist::parse("other", &text).is_ok());
}

#[test]
fn collected_index_and_assertion_observer_retain_validated_values() {
	let empty = Nodelist::parse("fidonet", ";A no data\n").unwrap();
	assert!(empty.is_empty());
	assert_eq!(empty.len(), 0);
	assert_eq!(empty.iter().count(), 0);

	let text = [
		line("Zone", 1, "", "", ""),
		line("Host", 10, "", "", ""),
		line("", 2, "1-1", "", ""),
	]
	.concat();
	let list = Nodelist::parse("fidonet", &text).unwrap();
	let observed = list.iter().last().unwrap();
	assert_eq!(observed.keyword, Keyword::Normal);
	assert_eq!(observed.node_name, "Node");
	assert_eq!(observed.location, "Location");
	assert_eq!(observed.sysop_name, "Sysop");
	assert_eq!(observed.phone, "1-1");
	assert!(observed.tith.is_none());
	assert!(list.get(&observed.address).is_some());
	assert_eq!(
		format!("{}", Nodelist::parse("fidonet", "bad\n").unwrap_err()),
		"nodelist line 1: WrongFieldCount"
	);
}

#[test]
fn publication_names_and_one_frame_zstandard_are_exact() {
	let first = PublicationName::new("fidonet", 1).unwrap();
	assert_eq!(first.text_filename(), "fidonet-nodelist.001");
	assert_eq!(first.archive_filename(), "fidonet-nodelist.001.zst");
	assert_eq!(first.current_request_filename(), "fidonet-nodelist.zst");
	assert_eq!(
		PublicationName::new("fidonet", 366)
			.unwrap()
			.text_filename(),
		"fidonet-nodelist.366"
	);
	for day in [0, 367, u16::MAX] {
		assert!(matches!(
			PublicationName::new("fidonet", day),
			Err(NodelistErrorKind::InvalidPublication)
		));
	}
	assert!(PublicationName::new("", 1).is_err());
	assert!(PublicationName::new(" pfx", 1).is_err());
	assert!(PublicationName::new("p2p", 1).is_err());
	assert_eq!(
		PublicationName::new("БорМер/path", 42)
			.unwrap()
			.text_filename(),
		"БорМер/path-nodelist.042"
	);
	let alternate = AlternatePublicationName::new("fidonet", "fidonet-N712seg", 42).unwrap();
	assert_eq!(alternate.text_filename(), "fidonet-N712seg.042");
	assert_eq!(alternate.archive_filename(), "fidonet-N712seg.042.zst");
	for base in ["", "fidonet-nodelist"] {
		assert!(AlternatePublicationName::new("fidonet", base, 42).is_err());
	}
	assert!(AlternatePublicationName::new(" pfx", "other", 42).is_err());
	assert!(AlternatePublicationName::new("fidonet", "other", 0).is_err());

	let text = b"Zone\t1\tNode\tLocation\tSysop\t\t\t\t\t\t\n";
	let encoded = compress_zstd_frame(Cursor::new(text), Vec::new()).unwrap();
	let decoded = decompress_zstd_frame(BufReader::new(Cursor::new(&encoded)), Vec::new()).unwrap();
	assert_eq!(decoded, text);
	assert_eq!(
		Nodelist::read("fidonet", Cursor::new(&decoded))
			.unwrap()
			.len(),
		1
	);
	let invalid_text = compress_zstd_frame(Cursor::new(b"unterminated"), Vec::new()).unwrap();
	let invalid_text =
		decompress_zstd_frame(BufReader::new(Cursor::new(invalid_text)), Vec::new()).unwrap();
	assert!(Nodelist::read("fidonet", Cursor::new(invalid_text)).is_err());

	assert_eq!(
		decompress_zstd_frame(BufReader::new(Cursor::new(CLI_FRAME)), Vec::new()).unwrap(),
		b"hello\n"
	);
	for (name, invalid) in [
		("concatenated", [CLI_FRAME, CLI_FRAME].concat()),
		("trailing", [CLI_FRAME, b"x"].concat()),
		("skippable", vec![0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0]),
		("truncated", CLI_FRAME[..CLI_FRAME.len() - 1].to_vec()),
	] {
		assert!(
			decompress_zstd_frame(BufReader::new(Cursor::new(invalid)), Vec::new()).is_err(),
			"{name} input was accepted"
		);
	}

	let dictionary = b"common nodelist dictionary words common nodelist dictionary words";
	let payload = b"common nodelist dictionary words";
	let encoded = zstd::bulk::Compressor::with_dictionary(3, dictionary)
		.unwrap()
		.compress(payload)
		.unwrap();
	assert!(decompress_zstd_frame(BufReader::new(Cursor::new(encoded)), Vec::new()).is_err());
}

struct FailingReader;

impl Read for FailingReader {
	fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
		Err(io::Error::other("read failure"))
	}
}

impl BufRead for FailingReader {
	fn fill_buf(&mut self) -> io::Result<&[u8]> {
		Err(io::Error::other("read failure"))
	}

	fn consume(&mut self, _amount: usize) {}
}

struct FailingWriter;

impl Write for FailingWriter {
	fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
		Err(io::Error::other("write failure"))
	}

	fn flush(&mut self) -> io::Result<()> {
		Err(io::Error::other("flush failure"))
	}
}

struct FailingFlush(Vec<u8>);

impl Write for FailingFlush {
	fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
		self.0.extend_from_slice(buffer);
		Ok(buffer.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		Err(io::Error::other("flush failure"))
	}
}

#[test]
fn streaming_io_failures_are_reported() {
	let error = NodelistReader::distribution("fidonet", FailingReader)
		.unwrap()
		.next()
		.unwrap()
		.unwrap_err();
	assert!(matches!(error.kind, NodelistErrorKind::Io));
	let mut writer = NodelistWriter::distribution("fidonet", FailingWriter).unwrap();
	let error = writer
		.write_entry(&input(Keyword::Zone, 1), PublicationSource::Ordinary)
		.unwrap_err();
	assert!(matches!(error.kind, NodelistErrorKind::Io));
	let mut writer = NodelistWriter::distribution("fidonet", FailingFlush(Vec::new())).unwrap();
	writer
		.write_entry(&input(Keyword::Zone, 1), PublicationSource::Ordinary)
		.unwrap();
	assert!(matches!(
		writer.finish(),
		Err(error) if matches!(error.kind, NodelistErrorKind::Io)
	));
	assert!(compress_zstd_frame(FailingReader, Vec::new()).is_err());
	assert!(compress_zstd_frame(Cursor::new(b"text"), FailingWriter).is_err());
	assert!(decompress_zstd_frame(FailingReader, Vec::new()).is_err());
}
