//! Deterministic TSP-0002 `NetMail` route selection.

#![forbid(unsafe_code)]

use tith_config::{
	BranchKind, ConfigurationSet, FailureKind, FailurePolicy, IdentityRef, IndependentKind, Peer,
	RouteMethod, Routes, Selector,
};
use tith_nodelist::{Keyword, Nodelist};
use tith_wire::bundle::{Identity, KeyResolver};

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
	resolver: &impl KeyResolver,
) -> Result<Commitment, RouteFailure> {
	if nodelist
		.get(&destination.address)
		.is_some_and(|entry| entry.keyword == Keyword::Down)
	{
		return Err(RouteFailure::Unroutable);
	}
	let selected = routes.routes.iter().enumerate().find(|(_, rule)| {
		selector_matches(&rule.destination, destination, config, nodelist, resolver)
	});
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
		if let Some((next_hop, passive)) =
			candidate(method, destination, config, nodelist, resolver)
		{
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

fn peer_identity(peer: &Peer, resolver: &impl KeyResolver) -> Option<Identity> {
	let public_key = if peer.address.is_unlisted() {
		peer.public_key?
	} else {
		resolver.public_key(&peer.address)?
	};
	Some(Identity {
		address: peer.address.clone(),
		public_key,
	})
}

fn exact_peer<'a>(
	identity: &Identity,
	config: &'a ConfigurationSet,
	resolver: &impl KeyResolver,
) -> Option<&'a Peer> {
	config.peers.values().find(|peer| {
		peer.address == identity.address && peer_identity(peer, resolver).as_ref() == Some(identity)
	})
}

fn usable(
	identity: &Identity,
	config: &ConfigurationSet,
	nodelist: &Nodelist,
	resolver: &impl KeyResolver,
) -> bool {
	if exact_peer(identity, config, resolver).is_some_and(|peer| !peer.endpoints.is_empty()) {
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

fn named_peer(
	name: &str,
	config: &ConfigurationSet,
	resolver: &impl KeyResolver,
) -> Option<Identity> {
	peer_identity(config.peers.get(name)?, resolver)
}

fn candidate(
	method: &RouteMethod,
	destination: &Identity,
	config: &ConfigurationSet,
	nodelist: &Nodelist,
	resolver: &impl KeyResolver,
) -> Option<(Identity, bool)> {
	match method {
		RouteMethod::Via(name) => Some((named_peer(name, config, resolver)?, false)),
		RouteMethod::Direct => {
			if destination.address.is_unlisted() {
				let peer = exact_peer(destination, config, resolver)?;
				(!peer.endpoints.is_empty()).then(|| (destination.clone(), false))
			} else {
				let prohibited = nodelist.get(&destination.address).is_some_and(|entry| {
					matches!(
						entry.keyword,
						Keyword::Private | Keyword::Hold | Keyword::Down
					)
				});
				(!prohibited && usable(destination, config, nodelist, resolver))
					.then(|| (destination.clone(), false))
			}
		}
		RouteMethod::Hold => (!nodelist
			.get(&destination.address)
			.is_some_and(|entry| entry.keyword == Keyword::Down))
		.then(|| (destination.clone(), true)),
		RouteMethod::Boss | RouteMethod::Hub if destination.address.is_unlisted() => {
			let peer = exact_peer(destination, config, resolver)?;
			let name = match method {
				RouteMethod::Boss => peer.boss.as_ref()?,
				RouteMethod::Hub => peer.hub.as_ref()?,
				_ => unreachable!(),
			};
			let identity = named_peer(name, config, resolver)?;
			eligible_ancestor(identity, config, nodelist, resolver)
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
				eligible_ancestor(identity, config, nodelist, resolver)
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
				resolver,
			)
		}
	}
}

fn eligible_ancestor(
	identity: Identity,
	config: &ConfigurationSet,
	nodelist: &Nodelist,
	resolver: &impl KeyResolver,
) -> Option<(Identity, bool)> {
	let configured = exact_peer(&identity, config, resolver);
	(configured.is_some() || usable(&identity, config, nodelist, resolver)).then(|| {
		(
			identity,
			configured.is_some_and(|peer| peer.endpoints.is_empty()),
		)
	})
}

/// Whether a configured selector names this identity.
///
/// TSP-0002 uses the same selector grammar for route, relay, failure, and
/// schedule `Next-Hop` lines, so the schedule driver in `tithd` resolves them
/// with the same function the router uses.
#[must_use]
pub fn selector_matches(
	selector: &Selector,
	identity: &Identity,
	config: &ConfigurationSet,
	nodelist: &Nodelist,
	resolver: &impl KeyResolver,
) -> bool {
	match selector {
		Selector::All => true,
		Selector::Address(address) => &identity.address == address,
		Selector::AddressPattern(pattern) => pattern.matches(&identity.address),
		Selector::Peer(name) => named_peer(name, config, resolver).as_ref() == Some(identity),
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
/// Resolves the policy for each permanent remote response kind.
///
/// TSP-0002 section 6 selects in a fixed order: the override on the Route which
/// supplied the method list, then the override on the `Allow-Relay` rule which
/// created the copy, then the first matching Failure line, then Failure-Default,
/// then Dead-Letter with notification None. `relay_override` is the second
/// level and is absent for a locally submitted item.
pub fn failure_policies(
	config: &ConfigurationSet,
	routes: &Routes,
	origin: &Identity,
	destination: &Identity,
	route_rule: Option<usize>,
	relay_override: Option<FailurePolicy>,
	key_sources: (&Nodelist, &impl KeyResolver),
) -> [FailurePolicy; 3] {
	let (nodelist, resolver) = key_sources;
	let kinds = [
		FailureKind::RelayDenied,
		FailureKind::Rejected,
		FailureKind::Authentication,
	];
	let selected = route_rule
		.and_then(|index| routes.routes.get(index))
		.and_then(|rule| rule.on_failure)
		.or(relay_override);
	kinds.map(|kind| {
		selected.unwrap_or_else(|| {
			routes
				.failures
				.iter()
				.find(|rule| {
					(matches!(rule.kind, FailureKind::Any) || rule.kind == kind)
						&& selector_matches(&rule.origin, origin, config, nodelist, resolver)
						&& selector_matches(
							&rule.destination,
							destination,
							config,
							nodelist,
							resolver,
						)
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
		let nodelist = Nodelist::default();
		let commitment =
			route_netmail(&config, routes, &destination, &[], &nodelist, &nodelist).unwrap();
		assert_eq!(commitment.next_hop.address, destination.address);
		assert_eq!(
			route_netmail(
				&config,
				routes,
				&destination,
				&[commitment.next_hop],
				&nodelist,
				&nodelist,
			),
			Err(RouteFailure::Loop)
		);
	}

	#[test]
	fn a_pinned_listed_peer_routes_without_a_nodelist_entry() {
		let config = ConfigurationSet::parse(
			"Peer next\nAddress fidonet#1/2\nEndpoint next.example 24555\nEnd\n",
			"Routes fidonet#1\nRoute All Using Via @next\nEnd\n",
			"",
			"",
		)
		.unwrap();
		let routes = &config.routes[0];
		let destination = Identity {
			address: "fidonet#1/9".parse().unwrap(),
			public_key: PublicKey::from_bytes([9; 32]),
		};
		let next: Address = "fidonet#1/2".parse().unwrap();
		let resolver =
			|address: &Address| (address == &next).then_some(PublicKey::from_bytes([2; 32]));
		let commitment = route_netmail(
			&config,
			routes,
			&destination,
			&[],
			&Nodelist::default(),
			&resolver,
		)
		.unwrap();
		assert_eq!(commitment.next_hop.address, next);
	}
}
