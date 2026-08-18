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
- mandatory public-key authentication for nodes and bundles, with explicit
  end-to-end item authentication states;
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

The reference daemon is not yet a production mailer. It has an initial native
network listener with durable local Message and standalone File acceptance,
duplicate handling, and authenticated replies. Outbound delivery and Poll and
FileRequest handling remain under construction. The C implementation under
[`poc/`](poc/) is a frozen historical proof of concept; new implementation work
belongs in Rust.

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
| `tith-ipc-tcp` | TSP-0009 authenticated key exchange and encrypted IPC records |
| `tith-submit` | TSP-0006 command-line client and reusable clients for every IPC binding |
| `tithd` | Reference service and host bindings |

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

To enable outbound `Submit`, `Submit-Items`, and `Lookup-Submission` on the
Unix endpoint, run the mailer form with its routing configuration, nodelist,
local identity, and matching signing key:

```sh
cargo run -p tithd -- serve-unix-mailer /var/run/tith.sock \
    /var/db/tith/state.redb /var/db/tith/exports mailer \
    /usr/local/etc/tith fidonet /var/db/tith/nodelist.txt \
    fidonet#1:123/45 /secure/path/node.secret
```

Submission ingests path Sources into immutable Job contents before returning
`New`. The current service deliberately omits the optional Move, Delete,
Truncate, and native-handle features from `Capabilities`.

For programs which use atomic filesystem rendezvous instead of sockets, one
configured principal can be served from an endpoint root containing
`requests`, `claimed`, `results`, and `acknowledgements`:

```sh
cargo run -p tithd -- serve-files /var/run/tith-files \
    /var/db/tith/state.redb /var/db/tith/exports tosser
```

Use `serve-files-mailer` with the same five trailing routing arguments shown
for `serve-unix-mailer` to enable the complete mailer operation set. Results
remain in `results/<token>.rsp` until the client durably publishes the empty
`acknowledgements/<token>.ack` file required by TSP-0008.

For authenticated loopback TCP, generate dedicated server and client IPC keys
and retain each printed public key in trusted configuration:

```sh
cargo run -p tithd -- generate-ipc-key /secure/path/server-ipc.secret
cargo run -p tithd -- generate-ipc-key /secure/path/client-ipc.secret
```

Then start the same consumption service over TSP-0009. The address must be an
IPv4 or IPv6 loopback address, and the two public-key arguments are the values
printed by the preceding commands:

```sh
cargo run -p tithd -- serve-tcp 127.0.0.1:24556 \
    /var/db/tith/state.redb /var/db/tith/exports tosser \
    SERVER-PUBLIC-KEY /secure/path/server-ipc.secret CLIENT-PUBLIC-KEY
```

The full mailer form adds the same submission configuration used by the Unix
binding:

```sh
cargo run -p tithd -- serve-tcp-mailer 127.0.0.1:24556 \
    /var/db/tith/state.redb /var/db/tith/exports mailer \
    SERVER-PUBLIC-KEY /secure/path/server-ipc.secret CLIENT-PUBLIC-KEY \
    /usr/local/etc/tith fidonet /var/db/tith/nodelist.txt \
    fidonet#1:123/45 /secure/path/node.secret
```

The authenticated TCP service and client also build on Windows. Platform ACLs
must protect both static secret-key files.

On Windows, the named-pipe service uses the TSP-0010 binary preambles and
authenticates the client through its impersonation token, process creation
time, logon identity, and session before reading an IPC document:

```powershell
cargo run -p tithd -- serve-named-pipe \\.\pipe\tith `
    C:\ProgramData\TITH\state.redb C:\ProgramData\TITH\exports tosser
```

`serve-named-pipe-mailer` adds the same routing and signing arguments as the
other mailer forms. Native handle tables are rejected and their optional
capabilities are not advertised; path presentation and path Sources work over
the pipe. The Windows CI job runs the named-pipe transaction test in addition
to the binding-independent workspace tests.

## Using `tith-submit`

`tith-submit` reads an exact canonical `Submit` or `Submit-Items` document,
sends one transaction, and writes only the complete IPC result to standard
output. It also constructs the standard query, lookup, control, and
capabilities requests. Select the configured carrier before the operation:

```sh
cargo run -p tith-submit -- --unix /var/run/tith.sock capabilities
cargo run -p tith-submit -- --files /var/run/tith-files query-job JOB-ID
cargo run -p tith-submit -- --tcp 127.0.0.1:24556 \
    CLIENT-PUBLIC-KEY /secure/path/client-ipc.secret SERVER-PUBLIC-KEY \
    submit request.ipc
```

On Windows, supply the trusted service account SID from host configuration;
the client verifies the connected server process token before sending its
preamble or request:

```powershell
cargo run -p tith-submit -- --named-pipe \\.\pipe\tith S-1-5-21-... `
    submit-items request.ipc
```

Use `-` as the submission filename to read standard input. The remaining
operations are `query`, `query-job`, `lookup`, `cancel`, `retry`, `reroute`,
and `capabilities`. For submission commands, exit status 0 means the
submission committed, 1 means a complete operation rejection or envelope-level
`Error` was written, and 2 means the transaction, result validation, or local
client failed.

The `tith-submit` library exposes the same binding clients plus one shared
`check_capabilities` conformance check. The daemon tests run that identical
check end-to-end through atomic files, Unix sockets, authenticated TCP, and,
in Windows CI, named pipes.

To exercise native TTS-0006 receipt, generate a dedicated node signing key and
place its printed public key in the applicable nodelist IIH entry or unlisted
Peer configuration:

```sh
cargo run -p tithd -- generate-node-key /secure/path/node.secret
```

The initial mail listener loads the normal four-file configuration set and one
TTS-5000 domain nodelist. `LOCAL-IDENTITY` is a listed canonical address or an
unlisted Peer reference such as `@point`:

```sh
cargo run -p tithd -- serve-mail 0.0.0.0:24555 \
    /var/db/tith/state.redb tosser /usr/local/etc/tith \
    fidonet /var/db/tith/nodelist.txt fidonet#1:123/45 \
    /secure/path/node.secret
```

Local Messages and standalone Files are durably stored before `Accepted` is
sent, and signed-item duplicates receive `Accepted` without creating another
inbound item. Unsupported relay, Poll, and FileRequest work receives a retryable
rejection. EchoMail and area Files are accepted only from configured
`Receive-From` peers.

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
