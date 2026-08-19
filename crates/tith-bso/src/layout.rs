//! FTS-5005.003 outbound layout, flow file naming, and flavours.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// A legacy address as far as the outbound layout is concerned.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NodeAddress {
	pub domain: Option<String>,
	pub zone: u16,
	pub net: u16,
	pub node: u16,
	pub point: u16,
}

impl fmt::Display for NodeAddress {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		if let Some(domain) = &self.domain {
			write!(f, "{domain}#")?;
		}
		write!(f, "{}:{}/{}", self.zone, self.net, self.node)?;
		if self.point != 0 {
			write!(f, ".{}", self.point)?;
		}
		Ok(())
	}
}

/// FTS-5005.003 section 3.2 flavours, in the processing order that section
/// requires: Immediate, Continuous, Direct, Normal, Hold.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Flavour {
	Immediate,
	Continuous,
	Direct,
	Normal,
	Hold,
}

impl Flavour {
	/// The flavour letter for a reference file. Normal uses "f" for references
	/// and "o" for netmail; section 3.2 calls "n" outdated.
	#[must_use]
	pub fn reference_letter(self) -> char {
		match self {
			Self::Immediate => 'i',
			Self::Continuous => 'c',
			Self::Direct => 'd',
			Self::Normal => 'f',
			Self::Hold => 'h',
		}
	}

	#[must_use]
	pub fn packet_letter(self) -> char {
		match self {
			Self::Immediate => 'i',
			Self::Continuous => 'c',
			Self::Direct => 'd',
			Self::Normal => 'o',
			Self::Hold => 'h',
		}
	}
}

/// What a flow file carries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowKind {
	/// An FTS-0001 packet, signature "ut".
	Packet,
	/// A reference file, signature "lo".
	Reference,
	/// An FTS-0006.002 `WaZOO` request list, extension "req".
	///
	/// Unlike the other two this has no flavour letter: section 2 gives one
	/// `.req` per node, so it is reported as Normal.
	Request,
}

/// One recognised flow file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowFile {
	pub path: PathBuf,
	pub flavour: Flavour,
	pub kind: FlowKind,
}

/// Classifies a flow file extension.
///
/// Recognised case-insensitively: FTS-5005 section 2 says the case depends on
/// the filesystem and that software should handle both for maximum
/// compatibility.
#[must_use]
pub fn classify_extension(extension: &str) -> Option<(Flavour, FlowKind)> {
	let lower = extension.to_ascii_lowercase();
	let bytes = lower.as_bytes();
	if bytes.len() != 3 {
		return None;
	}
	// Section 2 gives a node one request list with no flavour of its own. It is
	// checked before the flavour/signature split because "req" would otherwise
	// read as flavour "r" and signature "eq".
	if lower == "req" {
		return Some((Flavour::Normal, FlowKind::Request));
	}
	let kind = match &lower[1..] {
		"ut" => FlowKind::Packet,
		"lo" => FlowKind::Reference,
		_ => return None,
	};
	// "o" is netmail-only and "f" reference-only; the other letters serve both.
	let flavour = match (bytes[0], kind) {
		(b'i', _) => Flavour::Immediate,
		(b'c', _) => Flavour::Continuous,
		(b'd', _) => Flavour::Direct,
		(b'h', _) => Flavour::Hold,
		(b'o', FlowKind::Packet) | (b'f', FlowKind::Reference) => Flavour::Normal,
		_ => return None,
	};
	Some((flavour, kind))
}

/// Maps a domain to its own outbound root.
///
/// FTS-5005 section 2 names separate outbound areas per domain using an
/// abbreviation plus a zone extension. `BinkIT` generalises that to an explicit
/// map (`FIDO.FTNDomains.outboundMap`), which is what this represents; an
/// unmapped domain falls back to the default root.
#[derive(Clone, Debug, Default)]
pub struct Outbound {
	default_root: PathBuf,
	default_zone: u16,
	default_domain: Option<String>,
	domain_roots: BTreeMap<String, PathBuf>,
}

impl Outbound {
	#[must_use]
	pub fn new(default_root: impl Into<PathBuf>, default_zone: u16) -> Self {
		Self {
			default_root: default_root.into(),
			default_zone,
			default_domain: None,
			domain_roots: BTreeMap::new(),
		}
	}

	#[must_use]
	pub fn with_default_domain(mut self, domain: impl Into<String>) -> Self {
		self.default_domain = Some(domain.into());
		self
	}

	#[must_use]
	pub fn with_domain_root(mut self, domain: impl Into<String>, root: impl Into<PathBuf>) -> Self {
		self.domain_roots.insert(domain.into(), root.into());
		self
	}

	fn root_for(&self, address: &NodeAddress) -> &Path {
		address
			.domain
			.as_ref()
			.and_then(|domain| self.domain_roots.get(domain))
			.map_or(self.default_root.as_path(), PathBuf::as_path)
	}

	/// True when this address needs a zone suffix on its outbound directory.
	fn needs_zone_suffix(&self, address: &NodeAddress) -> bool {
		if address.zone != self.default_zone {
			return true;
		}
		// FTS-5005 section 2: outbound areas for a domain other than the primary
		// always carry a zone extension.
		match (&address.domain, &self.default_domain) {
			(Some(domain), Some(default)) => !domain.eq_ignore_ascii_case(default),
			_ => false,
		}
	}

	/// The zone suffix, three hex digits, or four above 4095.
	#[must_use]
	pub fn zone_suffix(zone: u16) -> String {
		if zone > 0xfff {
			format!("{zone:04x}")
		} else {
			format!("{zone:03x}")
		}
	}

	/// Every directory that may hold this address's flow files.
	///
	/// For the default zone both the bare root and the zone-suffixed root are
	/// returned, because section 2 says a generic name and one with a quasi
	/// extension equal to your own zone are both valid and it is recommended to
	/// check both. `BinkIT` documents not doing this as a known limitation.
	#[must_use]
	pub fn directories(&self, address: &NodeAddress) -> Vec<PathBuf> {
		let root = self.root_for(address);
		let suffixed = || {
			let mut name = root.as_os_str().to_os_string();
			name.push(format!(".{}", Self::zone_suffix(address.zone)));
			PathBuf::from(name)
		};
		let mut bases = if self.needs_zone_suffix(address) {
			vec![suffixed()]
		} else {
			vec![root.to_path_buf(), suffixed()]
		};
		if address.point != 0 {
			for base in &mut bases {
				*base = base.join(format!("{:04x}{:04x}.pnt", address.net, address.node));
			}
		}
		bases
	}

	/// The flow file stem: net and node, or the point number for a point.
	#[must_use]
	pub fn stem(address: &NodeAddress) -> String {
		if address.point == 0 {
			format!("{:04x}{:04x}", address.net, address.node)
		} else {
			format!("{:08x}", address.point)
		}
	}

	/// Recovers the address from a flow file path, or `None` when the path does
	/// not sit where this layout would have put it.
	#[must_use]
	pub fn address_of(&self, path: &Path, domain: Option<&str>) -> Option<NodeAddress> {
		let stem = path.file_stem()?.to_str()?;
		let parent = path.parent()?;
		let parent_name = parent.file_name()?.to_str()?.to_ascii_lowercase();

		let (directory, point) = if let Some(prefix) = parent_name.strip_suffix(".pnt") {
			let owner = u32::from_str_radix(prefix, 16).ok()?;
			let point = u16::try_from(u32::from_str_radix(stem, 16).ok()?).ok()?;
			(parent.parent()?, Some((owner, point)))
		} else {
			(parent, None)
		};

		let directory_name = directory.file_name()?.to_str()?.to_ascii_lowercase();
		let zone = match directory_name.rsplit_once('.') {
			Some((_, suffix)) if !suffix.is_empty() && suffix.len() <= 4 => {
				u16::from_str_radix(suffix, 16).ok()?
			}
			_ => self.default_zone,
		};

		let (net, node, point) = if let Some((owner, point)) = point {
			(
				u16::try_from(owner >> 16).ok()?,
				u16::try_from(owner & 0xffff).ok()?,
				point,
			)
		} else {
			let value = u32::from_str_radix(stem, 16).ok()?;
			(
				u16::try_from(value >> 16).ok()?,
				u16::try_from(value & 0xffff).ok()?,
				0,
			)
		};
		Some(NodeAddress {
			domain: domain.map(str::to_owned),
			zone,
			net,
			node,
			point,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn address(zone: u16, net: u16, node: u16, point: u16) -> NodeAddress {
		NodeAddress {
			domain: None,
			zone,
			net,
			node,
			point,
		}
	}

	#[test]
	fn checks_both_directories_for_the_default_zone() {
		let outbound = Outbound::new("/bink/outbound", 1);
		let directories = outbound.directories(&address(1, 104, 36, 0));
		assert_eq!(
			directories,
			[
				PathBuf::from("/bink/outbound"),
				PathBuf::from("/bink/outbound.001")
			]
		);
	}

	#[test]
	fn uses_only_the_suffixed_directory_for_another_zone() {
		let outbound = Outbound::new("/bink/outbound", 1);
		assert_eq!(
			outbound.directories(&address(2, 104, 36, 0)),
			[PathBuf::from("/bink/outbound.002")]
		);
		// FTS-5005 section 2 uses four hex digits above 4095.
		assert_eq!(
			outbound.directories(&address(5000, 1, 1, 0)),
			[PathBuf::from("/bink/outbound.1388")]
		);
	}

	#[test]
	fn places_points_in_a_pnt_subdirectory() {
		let outbound = Outbound::new("/bink/outbound", 1);
		let directories = outbound.directories(&address(1, 104, 36, 45));
		assert_eq!(directories[0], PathBuf::from("/bink/outbound/00680024.pnt"));
		assert_eq!(Outbound::stem(&address(1, 104, 36, 45)), "0000002d");
		assert_eq!(Outbound::stem(&address(1, 104, 36, 0)), "00680024");
	}

	#[test]
	fn a_mapped_domain_uses_its_own_root_and_always_carries_a_zone() {
		let outbound = Outbound::new("/bink/outbound", 1)
			.with_default_domain("fidonet")
			.with_domain_root("amiganet", "/bink/amiganet");
		let mut other = address(39, 100, 1, 0);
		other.domain = Some("amiganet".to_owned());
		assert_eq!(
			outbound.directories(&other),
			[PathBuf::from("/bink/amiganet.027")]
		);

		// Same zone as the default but a different domain still gets a suffix.
		let mut same_zone = address(1, 100, 1, 0);
		same_zone.domain = Some("amiganet".to_owned());
		assert_eq!(
			outbound.directories(&same_zone),
			[PathBuf::from("/bink/amiganet.001")]
		);
	}

	#[test]
	fn classifies_every_flavour_and_type_in_either_case() {
		use FlowKind::{Packet, Reference};
		for (extension, expected) in [
			("ilo", (Flavour::Immediate, Reference)),
			("clo", (Flavour::Continuous, Reference)),
			("dlo", (Flavour::Direct, Reference)),
			("flo", (Flavour::Normal, Reference)),
			("hlo", (Flavour::Hold, Reference)),
			("iut", (Flavour::Immediate, Packet)),
			("cut", (Flavour::Continuous, Packet)),
			("dut", (Flavour::Direct, Packet)),
			("out", (Flavour::Normal, Packet)),
			("hut", (Flavour::Hold, Packet)),
			("FLO", (Flavour::Normal, Reference)),
			("Out", (Flavour::Normal, Packet)),
		] {
			assert_eq!(classify_extension(extension), Some(expected), "{extension}");
		}
	}

	#[test]
	fn rejects_extensions_that_are_not_flow_files() {
		// "olo" and "fut" are the cross products that do not exist: "o" is
		// netmail only and "f" reference only.
		for extension in ["olo", "fut", "nlo", "bsy", "hld", "try", "pkt", "lo"] {
			assert_eq!(classify_extension(extension), None, "{extension}");
		}
	}

	#[test]
	fn a_request_list_has_no_flavour_of_its_own() {
		// "req" must not read as flavour "r" with signature "eq".
		for extension in ["req", "REQ", "Req"] {
			assert_eq!(
				classify_extension(extension),
				Some((Flavour::Normal, FlowKind::Request)),
				"{extension}"
			);
		}
	}

	#[test]
	fn flavours_order_as_the_standard_requires() {
		let mut order = [
			Flavour::Hold,
			Flavour::Normal,
			Flavour::Immediate,
			Flavour::Direct,
			Flavour::Continuous,
		];
		order.sort();
		assert_eq!(
			order,
			[
				Flavour::Immediate,
				Flavour::Continuous,
				Flavour::Direct,
				Flavour::Normal,
				Flavour::Hold
			]
		);
	}

	#[test]
	fn recovers_the_address_from_a_flow_file_path() {
		let outbound = Outbound::new("/bink/outbound", 1);
		assert_eq!(
			outbound.address_of(Path::new("/bink/outbound/00680024.flo"), None),
			Some(address(1, 104, 36, 0))
		);
		assert_eq!(
			outbound.address_of(Path::new("/bink/outbound.002/00680024.out"), None),
			Some(address(2, 104, 36, 0))
		);
		assert_eq!(
			outbound.address_of(Path::new("/bink/outbound/00680024.pnt/0000002d.flo"), None),
			Some(address(1, 104, 36, 45))
		);
		// Upper case components resolve the same way.
		assert_eq!(
			outbound.address_of(Path::new("/bink/OUTBOUND.002/00680024.OUT"), None),
			Some(address(2, 104, 36, 0))
		);
	}
}
