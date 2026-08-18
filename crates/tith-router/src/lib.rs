//! Deterministic TSP-0002 `NetMail` route selection.

#![forbid(unsafe_code)]

use tith_config::{
	BranchKind, ConfigurationSet, FailureKind, FailurePolicy, IdentityRef, IndependentKind, Peer,
	RouteMethod, Routes, Selector,
};
use tith_nodelist::{Keyword, Nodelist};
use tith_wire::bundle::Identity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteFailure {
	Unroutable,
	Loop,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commitment {
	pub next_hop: Identity,
	pub passive: bool,
	pub route_rule: Option<usize>,
	pub method_index: usize,
}

pub fn route_netmail(
	config: &ConfigurationSet,
	routes: &Routes,
	destination: &Identity,
	vias: &[Identity],
	nodelist: &Nodelist,
) -> Result<Commitment, RouteFailure> {
	if nodelist
		.get(&destination.address)
		.is_some_and(|entry| entry.keyword == Keyword::Down)
	{
		return Err(RouteFailure::Unroutable);
	}
	let selected = routes
		.routes
		.iter()
		.enumerate()
		.find(|(_, rule)| selector_matches(&rule.destination, destination, config, nodelist));
	let listed_defaults = [
		RouteMethod::Direct,
		RouteMethod::Boss,
		RouteMethod::Hub,
		RouteMethod::Host,
		RouteMethod::Region,
		RouteMethod::Zone,
		RouteMethod::Hold,
	];
	let unlisted_defaults = [
		RouteMethod::Boss,
		RouteMethod::Hub,
		RouteMethod::Direct,
		RouteMethod::Hold,
	];
	let (rule_index, methods): (Option<usize>, &[RouteMethod]) = selected.map_or_else(
		|| {
			(
				None,
				if destination.address.is_unlisted() {
					unlisted_defaults.as_slice()
				} else {
					listed_defaults.as_slice()
				},
			)
		},
		|(index, rule)| (Some(index), rule.methods.as_slice()),
	);
	for (method_index, method) in methods.iter().enumerate() {
		if let Some((next_hop, passive)) = candidate(method, destination, config, nodelist) {
			if vias.contains(&next_hop) {
				return Err(RouteFailure::Loop);
			}
			return Ok(Commitment {
				next_hop,
				passive,
				route_rule: rule_index,
				method_index,
			});
		}
	}
	Err(RouteFailure::Unroutable)
}

fn peer_identity(peer: &Peer, nodelist: &Nodelist) -> Option<Identity> {
	let public_key = if peer.address.is_unlisted() {
		peer.public_key?
	} else {
		nodelist.get(&peer.address)?.tith.as_ref()?.public_key
	};
	Some(Identity {
		address: peer.address.clone(),
		public_key,
	})
}

fn exact_peer<'a>(
	identity: &Identity,
	config: &'a ConfigurationSet,
	nodelist: &Nodelist,
) -> Option<&'a Peer> {
	config.peers.values().find(|peer| {
		peer.address == identity.address && peer_identity(peer, nodelist).as_ref() == Some(identity)
	})
}

fn usable(identity: &Identity, config: &ConfigurationSet, nodelist: &Nodelist) -> bool {
	if exact_peer(identity, config, nodelist).is_some_and(|peer| !peer.endpoints.is_empty()) {
		return true;
	}
	nodelist
		.get(&identity.address)
		.and_then(|entry| entry.tith.as_ref())
		.is_some_and(|service| {
			service
				.endpoints
				.iter()
				.any(tith_nodelist::Endpoint::is_usable)
		})
}

fn named_peer(name: &str, config: &ConfigurationSet, nodelist: &Nodelist) -> Option<Identity> {
	peer_identity(config.peers.get(name)?, nodelist)
}

fn candidate(
	method: &RouteMethod,
	destination: &Identity,
	config: &ConfigurationSet,
	nodelist: &Nodelist,
) -> Option<(Identity, bool)> {
	match method {
		RouteMethod::Via(name) => Some((named_peer(name, config, nodelist)?, false)),
		RouteMethod::Direct => {
			if destination.address.is_unlisted() {
				let peer = exact_peer(destination, config, nodelist)?;
				(!peer.endpoints.is_empty()).then(|| (destination.clone(), false))
			} else {
				let entry = nodelist.get(&destination.address)?;
				(!matches!(
					entry.keyword,
					Keyword::Private | Keyword::Hold | Keyword::Down
				) && usable(destination, config, nodelist))
				.then(|| (destination.clone(), false))
			}
		}
		RouteMethod::Hold => (!nodelist
			.get(&destination.address)
			.is_some_and(|entry| entry.keyword == Keyword::Down))
		.then(|| (destination.clone(), true)),
		RouteMethod::Boss | RouteMethod::Hub if destination.address.is_unlisted() => {
			let peer = exact_peer(destination, config, nodelist)?;
			let name = match method {
				RouteMethod::Boss => peer.boss.as_ref()?,
				RouteMethod::Hub => peer.hub.as_ref()?,
				_ => unreachable!(),
			};
			let identity = named_peer(name, config, nodelist)?;
			eligible_ancestor(identity, config, nodelist)
		}
		RouteMethod::Boss => {
			if destination.address.point() == 0 {
				None
			} else {
				let address = tith_wire::address::Address::new(
					destination.address.domain().to_owned(),
					destination.address.zone(),
					destination.address.net(),
					destination.address.node(),
					0,
				)
				.ok()?;
				let entry = nodelist.get(&address)?;
				let identity = Identity {
					address,
					public_key: entry.tith.as_ref()?.public_key,
				};
				eligible_ancestor(identity, config, nodelist)
			}
		}
		RouteMethod::Hub | RouteMethod::Host | RouteMethod::Region | RouteMethod::Zone => {
			let entry = nodelist.get(&destination.address)?;
			let address = match method {
				RouteMethod::Hub => entry.branch.hub.as_ref()?,
				RouteMethod::Host => entry.branch.host.as_ref()?,
				RouteMethod::Region => entry.branch.region.as_ref()?,
				RouteMethod::Zone => &entry.branch.zone,
				_ => unreachable!(),
			};
			let entry = nodelist.get(address)?;
			let key = entry.tith.as_ref()?.public_key;
			eligible_ancestor(
				Identity {
					address: address.clone(),
					public_key: key,
				},
				config,
				nodelist,
			)
		}
	}
}

fn eligible_ancestor(
	identity: Identity,
	config: &ConfigurationSet,
	nodelist: &Nodelist,
) -> Option<(Identity, bool)> {
	let configured = exact_peer(&identity, config, nodelist);
	(configured.is_some() || usable(&identity, config, nodelist)).then(|| {
		(
			identity,
			configured.is_some_and(|peer| peer.endpoints.is_empty()),
		)
	})
}

fn selector_matches(
	selector: &Selector,
	identity: &Identity,
	config: &ConfigurationSet,
	nodelist: &Nodelist,
) -> bool {
	match selector {
		Selector::All => true,
		Selector::Address(address) => &identity.address == address,
		Selector::AddressPattern(pattern) => pattern.matches(&identity.address),
		Selector::Peer(name) => named_peer(name, config, nodelist).as_ref() == Some(identity),
		Selector::Branch(kind, root) => {
			nodelist
				.get(&identity.address)
				.is_some_and(|entry| match kind {
					BranchKind::Zone => &entry.branch.zone == root,
					BranchKind::Region => entry.branch.region.as_ref() == Some(root),
					BranchKind::Host => entry.branch.host.as_ref() == Some(root),
					BranchKind::Hub => entry.branch.hub.as_ref() == Some(root),
				})
		}
		Selector::Independent(kind, root) => {
			nodelist
				.get(&identity.address)
				.is_some_and(|entry| match kind {
					IndependentKind::Zone => {
						&entry.branch.zone == root
							&& entry.branch.region.is_none()
							&& entry.branch.host.is_none()
							&& entry.branch.hub.is_none()
					}
					IndependentKind::Region => {
						entry.branch.region.as_ref() == Some(root)
							&& entry.branch.host.is_none()
							&& entry.branch.hub.is_none()
					}
				})
		}
	}
}

#[must_use]
pub fn routes_for<'a>(config: &'a ConfigurationSet, local: &IdentityRef) -> Option<&'a Routes> {
	config.routes.iter().find(|routes| &routes.local == local)
}

#[must_use]
pub fn failure_policies(
	config: &ConfigurationSet,
	routes: &Routes,
	origin: &Identity,
	destination: &Identity,
	route_rule: Option<usize>,
	nodelist: &Nodelist,
) -> [FailurePolicy; 5] {
	let kinds = [
		FailureKind::Unroutable,
		FailureKind::Loop,
		FailureKind::RelayDenied,
		FailureKind::Rejected,
		FailureKind::Authentication,
	];
	let route_override = route_rule
		.and_then(|index| routes.routes.get(index))
		.and_then(|rule| rule.on_failure);
	kinds.map(|kind| {
		route_override.unwrap_or_else(|| {
			routes
				.failures
				.iter()
				.find(|rule| {
					(matches!(rule.kind, FailureKind::Any) || rule.kind == kind)
						&& selector_matches(&rule.origin, origin, config, nodelist)
						&& selector_matches(&rule.destination, destination, config, nodelist)
				})
				.map_or(routes.failure_default, |rule| rule.policy)
		})
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use tith_crypto::PublicKey;
	use tith_wire::address::Address;

	#[test]
	fn via_commits_and_via_loop_is_terminal() {
		let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
		let config = ConfigurationSet::parse(
			&format!("Peer next\nAddress p2p#-1\nPublic-Key {key}\nEnd\n"),
			"Routes fidonet#1\nRoute All Using Via @next Hold\nEnd\n",
			"",
			"",
		)
		.unwrap();
		let routes = &config.routes[0];
		let destination = Identity {
			address: Address::unlisted("p2p".to_owned()).unwrap(),
			public_key: PublicKey::from_bytes([0; 32]),
		};
		let commitment =
			route_netmail(&config, routes, &destination, &[], &Nodelist::default()).unwrap();
		assert_eq!(commitment.next_hop.address, destination.address);
		assert_eq!(
			route_netmail(
				&config,
				routes,
				&destination,
				&[commitment.next_hop],
				&Nodelist::default()
			),
			Err(RouteFailure::Loop)
		);
	}
}
