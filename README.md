# TITH

> This Isn't That Hard.

[![Rust](https://github.com/RealDeuce/tith/actions/workflows/rust.yml/badge.svg)](https://github.com/RealDeuce/tith/actions/workflows/rust.yml)
[![Standards site](https://github.com/RealDeuce/tith/actions/workflows/pages.yml/badge.svg)](https://realdeuce.github.io/tith/)

TITH is a modern store-and-forward protocol for FidoNet Technology Networks.
It combines a small set of versioned standards with a Rust reference mailer,
with the goal of making secure FTN transport straightforward to implement and
interoperate with.

The project starts from a deliberately simple premise: define one canonical
representation, authenticate every peer and payload, and keep legacy
conversion at an explicit boundary instead of carrying historical ambiguity
into the native protocol.

## Start here

- Read the [published standards archive](https://realdeuce.github.io/tith/).
- Browse the [normative source documents](standards/).
- Follow implementation work in the [issue tracker](https://github.com/RealDeuce/tith/issues).
- Explore the Rust reference implementation under [`crates/`](crates/).

TITH documents use three publication classes:

- **TTS** — accepted TITH Technical Standards.
- **TSP** — Standards Proposals still subject to change.
- **TRD** — Reference Documents providing rationale and background.

## Design principles

TITH is designed around a few firm constraints:

- canonical TLV framing and integer encodings;
- public-key authentication for nodes, bundles, and end-to-end items;
- authenticated unlisted identities for enrollment and peer-to-peer use;
- a nodelist-backed trust path for listed nodes;
- explicit routing, durable acceptance, polling, and local IPC semantics;
- no arbitrary protocol limits; and
- no passwords, optional security, transport negotiation, or native legacy
  compatibility modes.

Legacy FTN formats still matter, but they belong in adapters. Native TITH
producers and consumers should not need to guess which accidental wire format
another implementation meant.

## Project status

TITH is under active development. The core standards cover canonical values,
addresses, signed bundles, exchange behavior, and the distribution nodelist.
The Rust workspace implements those foundations plus configuration, routing,
durable storage, and local IPC building blocks.

The reference daemon is not yet a production mailer. Native network receipt,
outbound delivery, and the complete application-facing workflow remain under
construction. The C implementation under [`poc/`](poc/) is a frozen historical
proof of concept; new implementation work belongs in Rust.

## Rust workspace

The implementation is divided by responsibility rather than by document:

| Crate | Responsibility |
| --- | --- |
| `tith-crypto` | Libhydrogen keys, signatures, hashes, and encrypted transport primitives; the only crate permitted to use `unsafe` |
| `tith-wire` | Canonical integers, addresses, TLVs, Bundles, and payload items |
| `tith-nodelist` | TTS-5000 nodelist parsing, endpoints, and public-key lookup |
| `tith-exchange` | Blocking TTS-0006 exchange state and response tracking |
| `tith-config` | Canonical reference-mailer configuration parsing |
| `tith-router` | Deterministic route selection and commitment |
| `tith-store` | Pure-Rust `redb` durable state and atomic claims |
| `tith-ipc` | Canonical local IPC request and result documents |
| `tithd` | FreeBSD-first reference service and host bindings |

Rust 1.97.1 is pinned by [`rust-toolchain.toml`](rust-toolchain.toml). To build
and validate the complete workspace:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
```

## Trying the reference service

Validate a TSP-0002 configuration directory containing `peers`, `routes`,
`areas`, and `schedules`:

```sh
cargo run -p tithd -- check-config /path/to/config
```

On Unix, run the current TSP-0012 local consumption service with path
presentation:

```sh
cargo run -p tithd -- serve-unix /var/run/tith.sock \
    /var/db/tith/state.redb /var/db/tith/exports tosser
```

This is an early, local-only interface. It authenticates clients using their
operating-system credentials and grants access only to the configured service
user.

The original C proof of concept is retained for historical reference and can
still be built with:

```sh
gmake -C poc
```

## Repository layout

- [`standards/`](standards/) contains the versioned normative and supporting
  documents.
- [`crates/`](crates/) contains the Rust reference implementation.
- [`site/`](site/) builds the standards archive deployed by GitHub Pages.
- [`poc/`](poc/) contains the original C experiment for historical reference.

## Contributing

Protocol changes should make wire behavior more precise. If two independent
implementations could reasonably interpret a document differently, please
[open an issue](https://github.com/RealDeuce/tith/issues/new) so the standard
can be clarified instead of teaching the reference implementation to guess.

## License

The source code is available under the [ISC License](LICENSE). Each TITH
standard is released to the public domain unless it states otherwise.
