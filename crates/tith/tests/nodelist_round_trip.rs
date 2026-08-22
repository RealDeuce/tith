//! Converted output must be accepted by the native TTS-5000/TTS-5001 parser.
//!
//! `tith-nodelist-legacy` cannot depend on `tith-nodelist` without pointing the
//! legacy conversion boundary at the native protocol layer, so the round trip
//! is checked here, where both are already linked.

use tith_nodelist::{Keyword, Nodelist};
use tith_nodelist_legacy::{Overrides, Warning, convert};

const FTS_5000: &[u8] = b"\
;A FidoNet nodelist fragment\r\n\
Zone,1,Zone_One,Somewhere,Zone_Coordinator,-Unpublished-,9600,CM,INA:zone.example.org,IBN\r\n\
Region,10,Region_Ten,Anywhere,Region_Coordinator,-Unpublished-,9600,CM\r\n\
Host,20,Net_Twenty,Ada_MI,Net_Coordinator,1-616-555-0100,9600,CM,XX,V32b,INA:net.example.org,IBN,IIH::24555:x8p4jN0PtHsr0nHxLmnw3Uy3v8kZfOZeMcxOWUeMOoo\r\n\
Hub,30,Hub_Thirty,Ada_MI,Hub_Sysop,1-616-555-0101,9600,CM,U,NEC\r\n\
,40,Plain_Node,Ada_MI,A_Sysop,1-616-555-0102,9600,MO,ITX,IEM:sysop@example.org,V42b,TuB\r\n\
Pvt,50,Private_Node,Ada_MI,Another_Sysop,-Unpublished-,9600,\r\n\
\x1a";

fn convert_fragment() -> (String, Vec<Warning>) {
	let mut warnings = Vec::new();
	let output = convert(FTS_5000, &Overrides::default(), &mut |warning| {
		warnings.push(warning);
	})
	.expect("fragment converts");
	(output, warnings)
}

fn flag_text<T: std::fmt::Display>(flags: &[T]) -> Vec<String> {
	flags.iter().map(ToString::to_string).collect()
}

#[test]
fn converted_output_parses_as_a_tts_5000_nodelist() {
	let (output, warnings) = convert_fragment();
	assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");

	let nodelist = Nodelist::parse("fidonet", &output).expect("converted nodelist parses");
	assert_eq!(nodelist.len(), 6);

	let host = nodelist
		.get(&"fidonet#1:20".parse().expect("host address"))
		.expect("Host entry is present");
	assert_eq!(host.keyword, Keyword::Host);
	assert_eq!(host.node_name, "Net Twenty");
	// Underscores became spaces, so the location is no longer "Ada_MI".
	assert_eq!(host.location, "Ada MI");
	assert_eq!(host.sysop_name, "Net Coordinator");
	assert_eq!(host.phone, "1-616-555-0100");
	assert_eq!(flag_text(&host.system_flags), ["CM", "XX"]);
	assert_eq!(flag_text(&host.pstn_isdn_flags), ["V32b"]);
	// TTS-5001 requires INA before IIH and the protocol flags.
	assert_eq!(
		flag_text(&host.internet_flags),
		[
			"INA:net.example.org",
			"IIH::24555:x8p4jN0PtHsr0nHxLmnw3Uy3v8kZfOZeMcxOWUeMOoo",
			"IBN"
		]
	);

	// The IIH flag survived conversion well enough for the parser to build a
	// usable TITH endpoint and key from it.
	let service = host.tith.as_ref().expect("Host publishes a TITH service");
	let endpoint = &service.endpoints[0];
	assert_eq!(endpoint.server.as_deref(), Some("net.example.org"));
	assert_eq!(endpoint.resolved_port(), Some(24555));
	assert!(endpoint.is_usable());
}

#[test]
fn converted_output_keeps_comments_and_drops_the_dce_speed() {
	let (output, _) = convert_fragment();
	assert!(output.starts_with(";A FidoNet nodelist fragment\n"));
	assert!(!output.contains('\r'));
	assert!(output.ends_with('\n'));
	for line in output.lines().filter(|line| !line.starts_with(';')) {
		let fields: Vec<_> = line.split('\t').collect();
		assert_eq!(fields.len(), 11, "line {line:?}");
		assert_ne!(fields[6], "9600", "DCE speed leaked into System Flags");
	}
}

#[test]
fn converted_output_applies_the_tts_5000_field_rules() {
	let (output, _) = convert_fragment();
	let nodelist = Nodelist::parse("fidonet", &output).expect("converted nodelist parses");

	// -Unpublished- became the empty phone number TTS-5000 field 6 requires.
	// A Zone entry's net defaults to its zone, so "fidonet#1" is canonical.
	let zone = nodelist
		.get(&"fidonet#1".parse().expect("zone address"))
		.expect("Zone entry is present");
	assert_eq!(zone.phone, "");

	// The U delimiter is gone but its user flag survived, per TTS-5000 field 11.
	let hub = nodelist
		.get(&"fidonet#1:20/30".parse().expect("hub address"))
		.expect("Hub entry is present");
	assert_eq!(flag_text(&hub.other_flags), ["NEC"]);

	let node = nodelist
		.get(&"fidonet#1:20/40".parse().expect("node address"))
		.expect("member entry is present");
	assert_eq!(flag_text(&node.other_flags), ["MO"]);
	assert_eq!(flag_text(&node.system_flags), ["TuB"]);
	// TTS-5001 requires IEM before the Email Protocol flags.
	assert_eq!(
		flag_text(&node.email_flags),
		["IEM:sysop@example.org", "ITX"]
	);
}

/// TTS-5000 section 5.2 field 1 forbids a Pvt entry to publish a means of
/// direct contact. The converter removes the keyword, so what it writes is
/// exactly what the native parser will accept.
#[test]
fn a_private_entry_which_publishes_contact_information_converts_to_a_normal_node() {
	let source = b"\
Zone,1,Zone_One,Somewhere,Zone_Coordinator,-Unpublished-,9600,CM\r\n\
Host,20,Net_Twenty,Ada_MI,Net_Coordinator,-Unpublished-,9600,CM\r\n\
Pvt,50,Private_Node,Ada_MI,Another_Sysop,-Unpublished-,9600,CM,INA:pvt.example.org,IBN\r\n";

	let mut warnings = Vec::new();
	let output = convert(source, &Overrides::default(), &mut |warning| {
		warnings.push(warning);
	})
	.expect("fragment converts");
	assert_eq!(warnings, vec![Warning::PrivateKeywordStripped { line: 3 }]);

	let nodelist = Nodelist::parse("fidonet", &output).expect("converted nodelist parses");
	let entry = nodelist
		.get(&"fidonet#1:20/50".parse().expect("node address"))
		.expect("the entry survived as a normal node");
	assert_eq!(entry.keyword, Keyword::Normal);
	// Only the keyword went; the addresses the source published remain.
	assert_eq!(
		flag_text(&entry.internet_flags),
		["INA:pvt.example.org", "IBN"]
	);
}

/// The one flag form a Pvt entry may carry, so that a private node still
/// publishes the key its Origin is authenticated with.
#[test]
fn a_private_entry_keeps_an_endpointless_iih_key() {
	let source = b"\
Zone,1,Zone_One,Somewhere,Zone_Coordinator,-Unpublished-,9600,CM\r\n\
Host,20,Net_Twenty,Ada_MI,Net_Coordinator,-Unpublished-,9600,CM\r\n\
Pvt,50,Private_Node,Ada_MI,Another_Sysop,-Unpublished-,9600,IIH:x8p4jN0PtHsr0nHxLmnw3Uy3v8kZfOZeMcxOWUeMOoo\r\n";

	let mut warnings = Vec::new();
	let output = convert(source, &Overrides::default(), &mut |warning| {
		warnings.push(warning);
	})
	.expect("fragment converts");
	assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");

	let nodelist = Nodelist::parse("fidonet", &output).expect("converted nodelist parses");
	let address = "fidonet#1:20/50".parse().expect("node address");
	let entry = nodelist.get(&address).expect("Pvt entry is present");
	assert_eq!(entry.keyword, Keyword::Private);
	// A key without an endpoint: authenticated, but not contactable.
	let service = entry.tith.as_ref().expect("the key survived conversion");
	assert!(!service.endpoints[0].is_usable());
}

/// TTS-5000 section 5.1 gives a nodelist no header, so an FTS-5000.005 first
/// line converts to an ordinary comment and nothing reads its CRC.
#[test]
fn the_legacy_header_line_converts_to_an_ordinary_comment() {
	let source = b"\
;A Friday, August 14, 2026 -- Day number 226 : 12345\r\n\
Zone,1,Zone_One,Somewhere,Zone_Coordinator,-Unpublished-,9600,CM\r\n";

	let mut warnings = Vec::new();
	let output = convert(source, &Overrides::default(), &mut |warning| {
		warnings.push(warning);
	})
	.expect("fragment converts");
	assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");

	// Retained unchanged, so the source nodelist can still be identified.
	assert!(output.starts_with(";A Friday, August 14, 2026 -- Day number 226 : 12345\n"));
	// The stale CRC is not a parse concern: it is comment text like any other.
	let nodelist = Nodelist::parse("fidonet", &output).expect("converted nodelist parses");
	assert_eq!(nodelist.len(), 1);
}
